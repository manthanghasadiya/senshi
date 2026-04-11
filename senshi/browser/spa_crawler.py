"""
SPA-aware crawler using Playwright.
Discovers endpoints in JS-heavy applications.
"""

from playwright.sync_api import Page
import re
from typing import Set

class SPACrawler:
    """
    Crawl Single Page Applications by:
    1. Rendering JavaScript
    2. Intercepting XHR/fetch requests
    3. Clicking buttons/links
    4. Extracting routes from JS bundles
    """
    
    def __init__(self, browser_engine, max_depth: int = 3):
        self.engine = browser_engine
        self.max_depth = max_depth
        self._discovered_urls: Set[str] = set()
        self._api_endpoints: Set[str] = set()
    
    def crawl(self, start_url: str) -> dict:
        """
        Crawl SPA and return discovered endpoints.
        
        Returns:
            {
                "pages": [...],      # Rendered pages
                "api_endpoints": [...],  # XHR/fetch URLs
                "forms": [...],      # Form actions
                "js_routes": [...],  # Routes found in JS
            }
        """
        page = self.engine.new_page()
        
        # Intercept API calls
        api_calls = []
        page.on("request", lambda req: api_calls.append({
            "url": req.url,
            "method": req.method,
            "post_data": req.post_data,
        }) if self._is_api_call(req) else None)
        
        try:
            page.goto(start_url, wait_until="networkidle", timeout=self.engine.timeout)
            
            # Extract links from rendered DOM
            links = page.evaluate("""
                () => Array.from(document.querySelectorAll('a[href]'))
                    .map(a => a.href)
                    .filter(href => href && !href.startsWith('javascript:'))
            """)
            
            # Extract form actions
            forms = page.evaluate("""
                () => Array.from(document.querySelectorAll('form'))
                    .map(f => ({
                        action: f.action,
                        method: f.method || 'GET',
                        inputs: Array.from(f.querySelectorAll('input,textarea,select'))
                            .map(i => ({name: i.name, type: i.type}))
                            .filter(i => i.name)
                    }))
            """)
            
            # Extract routes from JavaScript
            js_routes = self._extract_js_routes(page)
            
            # Click interactive elements to discover more
            self._click_interactive_elements(page)
            
            return {
                "pages": list(set(links)),
                "api_endpoints": [c for c in api_calls if self._is_interesting_api(c)],
                "forms": forms,
                "js_routes": js_routes,
            }
            
        finally:
            page.close()
    
    def _is_api_call(self, request) -> bool:
        """Check if request is an API call."""
        url = request.url.lower()
        return (
            "/api/" in url or
            "/v1/" in url or
            "/v2/" in url or
            "/graphql" in url or
            request.resource_type in ["xhr", "fetch"]
        )
    
    def _is_interesting_api(self, call: dict) -> bool:
        """Filter out noise (analytics, etc)."""
        url = call["url"].lower()
        noise_patterns = [
            "google-analytics", "facebook", "twitter",
            "hotjar", "segment", "mixpanel", "sentry",
            ".png", ".jpg", ".css", ".woff"
        ]
        return not any(p in url for p in noise_patterns)
    
    def _extract_js_routes(self, page: Page) -> list[str]:
        """Extract routes defined in JavaScript."""
        routes = []
        
        # Common patterns in JS bundles
        route_patterns = [
            r'["\']/(api|v\d+)/[^"\']+["\']',
            r'path:\s*["\'][^"\']+["\']',
            r'route:\s*["\'][^"\']+["\']',
            r'endpoint:\s*["\'][^"\']+["\']',
        ]
        
        # Get all script contents
        scripts = page.evaluate("""
            () => Array.from(document.querySelectorAll('script'))
                .map(s => s.textContent || '')
                .join('\\n')
        """)
        
        for pattern in route_patterns:
            matches = re.findall(pattern, scripts)
            routes.extend(matches)
        
        return list(set(routes))
    
    def _click_interactive_elements(self, page: Page):
        """Click buttons/links to discover dynamic content."""
        # Click up to 10 buttons to avoid infinite loops
        buttons = page.query_selector_all("button:not([disabled])")[:10]
        
        for button in buttons:
            try:
                button.click(timeout=2000)
                page.wait_for_timeout(500)
            except Exception:
                pass  # Button might navigate away, etc
