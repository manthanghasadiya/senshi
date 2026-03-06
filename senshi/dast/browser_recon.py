"""
Browser-based recon — discover API endpoints via headless browser.

Uses Playwright to launch a headless Chromium browser, navigate to the target,
capture all network requests (XHR, Fetch), and extract API endpoints.

Requires: pip install 'senshi[browser]' && playwright install chromium
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from senshi.dast.crawler import DiscoveredEndpoint
from senshi.utils.logger import get_logger

logger = get_logger("senshi.dast.browser_recon")

# Static asset extensions to skip
STATIC_EXTENSIONS = {
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".map", ".webp", ".avif",
}


class BrowserRecon:
    """Discover API endpoints by observing browser network traffic."""

    def __init__(self, timeout: int = 30, headless: bool = True) -> None:
        self.timeout = timeout * 1000  # Playwright uses milliseconds
        self.headless = headless

    def discover(
        self,
        url: str,
        auth: str = "",
        interactions: bool = True,
    ) -> list[DiscoveredEndpoint]:
        """
        Launch browser, navigate to URL, capture network traffic.

        Args:
            url: Target URL to visit.
            auth: Optional auth header (e.g., "Cookie: session=abc").
            interactions: If True, try clicking buttons and filling forms.

        Returns:
            List of discovered API endpoints.
        """
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            raise ImportError(
                "Playwright is required for browser recon. "
                "Install with: pip install 'senshi[browser]' && playwright install chromium"
            )

        endpoints: dict[str, DiscoveredEndpoint] = {}
        parsed_target = urlparse(url)
        base_domain = parsed_target.hostname or ""

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=self.headless)
            context = browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
            )

            # Set auth cookies/headers if provided
            if auth:
                self._set_auth(context, url, auth)

            page = context.new_page()

            # Capture all network requests
            def on_request(request: Any) -> None:
                try:
                    req_url = request.url
                    req_parsed = urlparse(req_url)

                    # Skip static assets
                    path = req_parsed.path.lower()
                    if any(path.endswith(ext) for ext in STATIC_EXTENSIONS):
                        return

                    # Only capture same-domain or API requests
                    req_host = req_parsed.hostname or ""
                    if req_host != base_domain and not self._is_api_request(req_url):
                        return

                    method = request.method
                    # Normalize URL (remove query params for dedup key)
                    clean_url = f"{req_parsed.scheme}://{req_parsed.netloc}{req_parsed.path}"
                    key = f"{method}:{clean_url}"

                    if key not in endpoints:
                        # Extract query params
                        params = []
                        if req_parsed.query:
                            params = [
                                p.split("=")[0]
                                for p in req_parsed.query.split("&")
                                if "=" in p
                            ]

                        # Try to get POST body params
                        if method.upper() in ("POST", "PUT", "PATCH"):
                            try:
                                post_data = request.post_data or ""
                                if post_data:
                                    if "=" in post_data and "&" in post_data:
                                        params.extend(
                                            p.split("=")[0] for p in post_data.split("&") if "=" in p
                                        )
                                    elif post_data.startswith("{"):
                                        import json
                                        try:
                                            body = json.loads(post_data)
                                            if isinstance(body, dict):
                                                params.extend(body.keys())
                                        except json.JSONDecodeError:
                                            pass
                            except Exception:
                                pass

                        content_type = request.headers.get("content-type", "")

                        endpoints[key] = DiscoveredEndpoint(
                            url=clean_url,
                            method=method,
                            params=list(set(params)),
                            source="browser",
                            content_type=content_type,
                        )

                except Exception as e:
                    logger.debug(f"Failed to capture request: {e}")

            page.on("request", on_request)

            # Navigate to the target
            try:
                page.goto(url, wait_until="networkidle", timeout=self.timeout)
            except Exception as e:
                logger.warning(f"Page load timeout/error: {e}")

            # Interact with the page to trigger more requests
            if interactions:
                self._interact_with_page(page)

            browser.close()

        result = list(endpoints.values())
        logger.info(f"Browser recon: captured {len(result)} endpoints")
        return result

    def _set_auth(self, context: Any, url: str, auth: str) -> None:
        """Set authentication headers/cookies on the browser context."""
        if auth.lower().startswith("cookie:"):
            cookie_str = auth[7:].strip()
            parsed = urlparse(url)
            for cookie_pair in cookie_str.split(";"):
                cookie_pair = cookie_pair.strip()
                if "=" in cookie_pair:
                    name, _, value = cookie_pair.partition("=")
                    context.add_cookies([{
                        "name": name.strip(),
                        "value": value.strip(),
                        "domain": parsed.hostname or "",
                        "path": "/",
                    }])
        elif auth.lower().startswith("bearer "):
            context.set_extra_http_headers({"Authorization": auth})
        else:
            # Try as a raw header
            if ":" in auth:
                key, _, value = auth.partition(":")
                context.set_extra_http_headers({key.strip(): value.strip()})

    def _interact_with_page(self, page: Any) -> None:
        """Click buttons and interact with the page to trigger API calls."""
        import time

        # Wait a bit for dynamic content
        time.sleep(1)

        # Click all visible buttons (limited to 10)
        try:
            buttons = page.query_selector_all("button, [role='button'], a[onclick]")
            for btn in buttons[:10]:
                try:
                    if btn.is_visible():
                        btn.click(timeout=2000)
                        time.sleep(0.5)
                except Exception:
                    continue
        except Exception:
            pass

        # Try submitting forms with empty data
        try:
            forms = page.query_selector_all("form")
            for form in forms[:3]:
                try:
                    submit = form.query_selector("button[type='submit'], input[type='submit']")
                    if submit and submit.is_visible():
                        submit.click(timeout=2000)
                        time.sleep(0.5)
                except Exception:
                    continue
        except Exception:
            pass

        # Scroll to bottom to trigger lazy loading
        try:
            page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            time.sleep(1)
        except Exception:
            pass

    @staticmethod
    def _is_api_request(url: str) -> bool:
        """Check if URL looks like an API endpoint."""
        path = urlparse(url).path.lower()
        api_indicators = ["/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/", "/json"]
        return any(indicator in path for indicator in api_indicators)
