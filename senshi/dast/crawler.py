"""
Endpoint crawler — discovers URLs, API routes, and parameters.

Crawls pages, parses JavaScript, finds API routes, and classifies endpoints.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlparse

from senshi.ai.brain import Brain
from senshi.ai.prompts.recon import JS_ANALYSIS_PROMPT, ENDPOINT_CLASSIFICATION_PROMPT
from senshi.core.session import Response, Session
from senshi.utils.logger import get_logger

logger = get_logger("senshi.dast.crawler")


class DiscoveredEndpoint:
    """A discovered endpoint with metadata."""

    def __init__(
        self,
        url: str,
        method: str = "GET",
        params: list[str] | None = None,
        source: str = "crawl",
        risk_level: str = "medium",
        content_type: str = "",
    ) -> None:
        self.url = url
        self.method = method
        self.params = params or []
        self.source = source  # crawl, js, api, robots
        self.risk_level = risk_level
        self.content_type = content_type
        self.priority_tests: list[str] = []

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "params": self.params,
            "source": self.source,
            "risk_level": self.risk_level,
            "content_type": self.content_type,
            "priority_tests": self.priority_tests,
        }


class Crawler:
    """Discover endpoints via crawling, JS analysis, and API detection."""

    def __init__(
        self,
        session: Session,
        brain: Brain | None = None,
        max_depth: int = 3,
    ) -> None:
        self.session = session
        self.brain = brain
        self.max_depth = max_depth
        self._visited: set[str] = set()
        self._endpoints: list[DiscoveredEndpoint] = []

    def crawl(self, start_url: str | None = None) -> list[DiscoveredEndpoint]:
        """
        Crawl the target and discover endpoints.

        Returns list of discovered endpoints.
        """
        start = start_url or self.session.base_url
        logger.info(f"Crawling {start} (max depth: {self.max_depth})")

        # Phase 1: Check robots.txt and sitemap
        self._check_robots(start)

        # Phase 2: Crawl pages
        self._crawl_page(start, depth=0)

        # Phase 3: Classify endpoints with LLM
        if self.brain and self._endpoints:
            self._classify_endpoints()

        logger.info(f"Discovered {len(self._endpoints)} endpoints")
        return self._endpoints

    def _crawl_page(self, url: str, depth: int) -> None:
        """Recursively crawl a page for links and resources."""
        if depth > self.max_depth or url in self._visited:
            return

        self._visited.add(url)
        parsed = urlparse(url)

        try:
            response = self.session.get(url)
        except Exception as e:
            logger.debug(f"Failed to fetch {url}: {e}")
            return

        # Add the page itself as an endpoint
        self._add_endpoint(url, "GET", source="crawl")

        body = response.body

        # Extract links from HTML
        links = self._extract_links(body, url)
        for link in links:
            link_parsed = urlparse(link)
            # Only follow same-domain links
            if link_parsed.netloc == parsed.netloc or not link_parsed.netloc:
                self._crawl_page(link, depth + 1)

        # Extract endpoints from JavaScript
        js_urls = self._extract_js_urls(body, url)
        for js_url in js_urls:
            self._fetch_and_parse_js(js_url)

        # Extract form actions
        forms = self._extract_forms(body, url)
        for form in forms:
            self._add_endpoint(
                form["action"],
                form["method"],
                params=form["params"],
                source="form",
            )

        # Look for API patterns in the response
        api_endpoints = self._extract_api_patterns(body, url)
        for ep in api_endpoints:
            self._add_endpoint(ep, "GET", source="api_pattern")

    def _extract_links(self, html: str, base_url: str) -> list[str]:
        """Extract all href links from HTML."""
        links: list[str] = []
        # Match href attributes
        for match in re.finditer(r'href=["\']([^"\']+)["\']', html):
            href = match.group(1)
            if href.startswith(("#", "javascript:", "mailto:", "tel:")):
                continue
            full_url = urljoin(base_url, href)
            links.append(full_url)
        return list(set(links))

    def _extract_js_urls(self, html: str, base_url: str) -> list[str]:
        """Extract JavaScript file URLs from HTML."""
        js_urls: list[str] = []
        for match in re.finditer(r'src=["\']([^"\']*\.js[^"\']*)["\']', html):
            js_url = urljoin(base_url, match.group(1))
            js_urls.append(js_url)
        return js_urls

    def _extract_forms(self, html: str, base_url: str) -> list[dict[str, Any]]:
        """Extract form actions and parameters."""
        forms: list[dict[str, Any]] = []

        # Simple form extraction
        form_pattern = re.compile(
            r'<form[^>]*action=["\']([^"\']*)["\'][^>]*(?:method=["\'](\w+)["\'])?[^>]*>(.*?)</form>',
            re.DOTALL | re.IGNORECASE,
        )

        for match in form_pattern.finditer(html):
            action = urljoin(base_url, match.group(1))
            method = (match.group(2) or "GET").upper()
            form_body = match.group(3)

            # Extract input names
            params = re.findall(
                r'<input[^>]*name=["\']([^"\']+)["\']', form_body, re.IGNORECASE
            )

            forms.append({"action": action, "method": method, "params": params})

        return forms

    def _extract_api_patterns(self, body: str, base_url: str) -> list[str]:
        """Extract API endpoint patterns from response body."""
        endpoints: list[str] = []

        # Match common API patterns in text
        api_patterns = [
            r'["\'](/api/[^"\'?\s]+)["\']',
            r'["\'](/v[0-9]+/[^"\'?\s]+)["\']',
            r'["\'](/graphql[^"\'?\s]*)["\']',
            r'["\'](/rest/[^"\'?\s]+)["\']',
        ]

        for pattern in api_patterns:
            for match in re.finditer(pattern, body):
                full_url = urljoin(base_url, match.group(1))
                endpoints.append(full_url)

        return list(set(endpoints))

    def _fetch_and_parse_js(self, js_url: str) -> None:
        """Fetch and parse a JavaScript file for endpoints."""
        if js_url in self._visited:
            return
        self._visited.add(js_url)

        try:
            response = self.session.get(js_url)
            if response.status_code != 200:
                return
        except Exception:
            return

        # If we have an LLM, use it for deep JS analysis
        if self.brain and len(response.body) < 50000:
            try:
                result = self.brain.think(
                    system_prompt=JS_ANALYSIS_PROMPT,
                    user_prompt=f"Analyze this JavaScript code:\n\n{response.body[:10000]}",
                    json_schema={"type": "object"},
                )
                if isinstance(result, dict):
                    for ep in result.get("endpoints", []):
                        url = urljoin(self.session.base_url, ep.get("url", ""))
                        method = ep.get("method", "GET")
                        self._add_endpoint(url, method, source="js_analysis")
            except Exception as e:
                logger.debug(f"JS LLM analysis failed: {e}")

        # Fallback: regex extraction
        api_endpoints = self._extract_api_patterns(response.body, self.session.base_url)
        for ep in api_endpoints:
            self._add_endpoint(ep, "GET", source="js")

    def _check_robots(self, base_url: str) -> None:
        """Check robots.txt for disallowed paths (interesting targets)."""
        try:
            response = self.session.get(f"{base_url}/robots.txt")
            if response.status_code == 200:
                for line in response.body.splitlines():
                    line = line.strip()
                    if line.lower().startswith(("disallow:", "allow:")):
                        path = line.split(":", 1)[1].strip()
                        if path and path != "/":
                            full_url = urljoin(base_url, path)
                            self._add_endpoint(full_url, "GET", source="robots")
        except Exception:
            pass

    def _classify_endpoints(self) -> None:
        """Use LLM to classify endpoints for targeted scanning."""
        if not self.brain:
            return

        import json

        endpoints_json = json.dumps(
            [ep.to_dict() for ep in self._endpoints[:50]], indent=2
        )

        try:
            result = self.brain.think(
                system_prompt=ENDPOINT_CLASSIFICATION_PROMPT,
                user_prompt=f"Classify these endpoints:\n\n{endpoints_json}",
                json_schema={"type": "object"},
            )

            if isinstance(result, dict):
                for ep_data in result.get("endpoints", []):
                    # Match back to discovered endpoints
                    for ep in self._endpoints:
                        if ep.url == ep_data.get("url"):
                            ep.risk_level = ep_data.get("risk_level", ep.risk_level)
                            ep.priority_tests = ep_data.get("priority_tests", [])
                            break

        except Exception as e:
            logger.debug(f"Endpoint classification failed: {e}")

    def _add_endpoint(
        self,
        url: str,
        method: str,
        params: list[str] | None = None,
        source: str = "crawl",
    ) -> None:
        """Add an endpoint if not already discovered."""
        # Check for duplicates
        for existing in self._endpoints:
            if existing.url == url and existing.method == method:
                # Merge params
                if params:
                    for p in params:
                        if p not in existing.params:
                            existing.params.append(p)
                return

        self._endpoints.append(
            DiscoveredEndpoint(url=url, method=method, params=params, source=source)
        )
