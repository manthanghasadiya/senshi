"""
Endpoint crawler — discovers URLs, API routes, and parameters.

Crawls pages, parses JavaScript, finds API routes, and classifies endpoints.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup
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
        
        # Extract application base path and domain for scope handling
        parsed = urlparse(self.session.base_url)
        self.domain = f"{parsed.scheme}://{parsed.netloc}"
        # app_base is the path prefix, e.g., "/DVWA"
        self.app_base = parsed.path.rstrip('/')

    SENSITIVE_ENDPOINTS_TO_CHECK = [
        "/redirect",
        "/api/config",
        "/config",
        "/admin",
        "/admin/users",
        "/.env",
        "/debug",
        "/actuator",
        "/actuator/health",
        "/actuator/env",
    ]

    SKIP_EXTENSIONS = {
        '.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.ico', 
        '.svg', '.woff', '.woff2', '.ttf', '.pdf', '.zip'
    }

    def _is_scannable(self, url: str) -> bool:
        """Check if URL is worth scanning (not static assets or logout)."""
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        # Skip static assets
        for ext in self.SKIP_EXTENSIONS:
            if path.endswith(ext):
                return False
        
        # Skip logout to avoid killing session
        if 'logout' in path:
            return False
            
        return True

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

        # Phase 3: Check sensitive endpoints wordlist
        self._check_sensitive_endpoints(start)

        # Phase 4: Classify endpoints with LLM
        if self.brain and self._endpoints:
            self._classify_endpoints()

        logger.info(f"Discovered {len(self._endpoints)} endpoints")
        return self._endpoints

    def _crawl_page(self, url: str, depth: int) -> None:
        """Recursively crawl a page for links and resources."""
        if depth > self.max_depth or url in self._visited:
            return

        self._visited.add(url)
        
        try:
            response = self.session.get(url)
            logger.debug(f"Fetched {url} - Status: {response.status_code}, Length: {len(response.body)}")
        except Exception as e:
            logger.debug(f"Failed to fetch {url}: {e}")
            return

        # Add the page itself as an endpoint
        self._add_endpoint(url, "GET", source="crawl")

        body = response.body

        # Extract links from HTML
        links = self._extract_links(body, url)
        for link in links:
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

    def _normalize_url(self, href: str, base_url: str) -> str | None:
        """Normalize URL preserving application base path."""
        if not href or href.startswith(('javascript:', 'mailto:', 'tel:', '#')):
            return None
            
        # 1. Handle root-relative URLs (e.g., /vulnerabilities/)
        if href.startswith('/') and not href.startswith('//'):
            # Detect if we need to prepend the application base path
            if self.app_base and not href.startswith(self.app_base + '/'):
                if href != self.app_base:  # Don't double up if it's exactly the base
                    href = self.app_base + href
            full_url = self.domain + href
        elif href.startswith('http'):
            # 2. Absolute URL
            full_url = href
        else:
            # 3. Relative path (e.g. vulnerabilities/sqli/) - resolves against base page
            # Correctly handle if base_url is a file like about.php
            full_url = urljoin(base_url, href)
        
        try:
            url_parsed = urlparse(full_url)
            
            # Enforce same domain
            if f"{url_parsed.scheme}://{url_parsed.netloc}" != self.domain:
                return None
            
            # Enforce app base path scope (don't wander into other root paths)
            if self.app_base and not url_parsed.path.startswith(self.app_base):
                return None
            
            # Filter out non-scannable stuff (JS, CSS, logout)
            if not self._is_scannable(full_url):
                return None
                
            return full_url
        except Exception:
            return None

    def _extract_links(self, html: str, base_url: str) -> list[str]:
        """Extract all links from HTML using BeautifulSoup."""
        soup = BeautifulSoup(html, 'html.parser')
        links: list[str] = []
        
        anchors = soup.find_all('a', href=True)
        logger.debug(f"Found {len(anchors)} <a> tags on {base_url}")
        
        for tag in anchors:
            href = tag.get('href')
            normalized = self._normalize_url(href, base_url)
            
            if normalized:
                links.append(normalized)
                logger.debug(f"  ✓ {href} -> {normalized}")
            else:
                logger.debug(f"  ✗ {href} (Invalid or Out of Scope)")
                
        return list(set(links))

    def _extract_js_urls(self, html: str, base_url: str) -> list[str]:
        """Extract JavaScript file URLs using BeautifulSoup."""
        soup = BeautifulSoup(html, 'html.parser')
        js_urls: list[str] = []
        
        scripts = soup.find_all('script', src=True)
        for tag in scripts:
            src = tag.get('src')
            if '.js' in src.lower():
                normalized = self._normalize_url(src, base_url)
                if normalized:
                    js_urls.append(normalized)
        return list(set(js_urls))

    def _extract_forms(self, html: str, base_url: str) -> list[dict[str, Any]]:
        """Extract form actions and parameters using BeautifulSoup."""
        soup = BeautifulSoup(html, 'html.parser')
        forms: list[dict[str, Any]] = []

        for form_tag in soup.find_all('form'):
            action = form_tag.get('action', '')
            method = form_tag.get('method', 'GET').upper()
            
            normalized = self._normalize_url(action, base_url)
            if not normalized:
                continue
                
            # Extract input names
            params = []
            for input_tag in form_tag.find_all(['input', 'textarea', 'select']):
                name = input_tag.get('name')
                if name:
                    params.append(name)

            forms.append({"action": normalized, "method": method, "params": list(set(params))})

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
                normalized = self._normalize_url(match.group(1), base_url)
                if normalized:
                    endpoints.append(normalized)

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

    def _check_sensitive_endpoints(self, base_url: str) -> None:
        """Check for common sensitive endpoints (wordlist-based)."""
        logger.info("Checking for sensitive endpoints...")
        for path in self.SENSITIVE_ENDPOINTS_TO_CHECK:
            full_url = f"{base_url.rstrip('/')}{path}"
            
            try:
                response = self.session.get(full_url, timeout=5)
                # If it's not a 404 or 405, it might be interesting
                if response.status_code not in [404, 405]:
                    # Infer params from path
                    params = []
                    if "redirect" in path:
                        params = ["url", "next", "return"]
                    elif "config" in path:
                        params = []
                    
                    self._add_endpoint(
                        full_url,
                        "GET",
                        params=params,
                        source="wordlist",
                    )
            except Exception:
                pass

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
        from urllib.parse import urlparse, parse_qs
        
        # Extract query parameters from URL
        parsed = urlparse(url)
        query_params = list(parse_qs(parsed.query).keys())
        all_params = list(set((params or []) + query_params))
        
        # Check for duplicates
        for existing in self._endpoints:
            if existing.url == url and existing.method == method:
                # Merge params
                if all_params:
                    for p in all_params:
                        if p not in existing.params:
                            existing.params.append(p)
                return

        self._endpoints.append(
            DiscoveredEndpoint(url=url, method=method, params=all_params, source=source)
        )
