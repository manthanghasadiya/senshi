"""
AppInteractor -- interacts with the application to trigger API calls.

Replaces traditional HTML crawling. Instead of parsing <a> tags, we CLICK
things, fill forms, expand menus, scroll pages, and watch what requests
the browser fires. The TrafficInterceptor records everything automatically.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import urlparse

logger = logging.getLogger("senshi.browser.interactor")


@dataclass
class ElementInfo:
    """A clickable/interactive element discovered on the page."""

    selector: str
    tag: str
    text: str
    href: Optional[str]
    element_type: str  # "link" | "button" | "input" | "menu" | "tab" | "other"


class AppInteractor:
    """
    Interacts with the application through the browser to discover endpoints.

    This is NOT an HTML parser. It drives a real browser by clicking links,
    buttons, filling forms, expanding menus, and scrolling. The
    TrafficInterceptor (attached to the same page) captures every API call
    these interactions trigger.

    Usage:
        interactor = AppInteractor(page, interceptor, target_domain)
        await interactor.crawl_spa(max_pages=50)
        await interactor.fill_and_submit_forms()
    """

    _SKIP_PATH_PATTERNS = [
        "logout", "signout", "sign-out", "log-out",
        "delete-account", "deactivate",
        "/manual", "/docs/api", "/swagger-ui",
    ]

    def __init__(
        self,
        page: Any,
        interceptor: Any,
        target_domain: str,
        target_url: str = "",
    ) -> None:
        self.page = page
        self.interceptor = interceptor
        self.target_domain = target_domain
        self.target_path_prefix = urlparse(target_url).path.rstrip("/") if target_url else ""

        self.visited_urls: set[str] = set()
        self.clicked_selectors: set[str] = set()
        self.submitted_forms: set[str] = set()

    # ── SPA Crawling ─────────────────────────────────────────────────

    async def crawl_spa(
        self,
        max_pages: int = 50,
        max_depth: int = 3,
    ) -> dict[str, int]:
        """
        Crawl any web application by combining link-based BFS with SPA interaction.

        Works on:
          - Traditional server-rendered apps (follows <a href> links)
          - SPAs (clicks buttons, tabs, JS-driven elements)
          - Hybrid apps (both)
          - REST API docs/playgrounds (follows links + submits forms)
        """
        start_count = len(self.interceptor.requests)

        # BFS queue: (url, depth)
        queue_start_url = self.page.url
        queue: list[tuple[str, int]] = [(queue_start_url, 0)]
        spa_expanded = False

        while (queue or not spa_expanded) and len(self.visited_urls) < max_pages:
            if not queue and not spa_expanded:
                spa_expanded = True
                if len(self.visited_urls) < 5:
                    logger.debug("Few pages found via BFS - running deeper SPA click exploration")
                    try:
                        await self.page.goto(queue_start_url, wait_until="domcontentloaded", timeout=10_000)
                        await self._wait_for_stable(timeout_ms=3_000)
                    except Exception:
                        pass
                    new_urls = await self._click_spa_elements(max_clicks=100)
                    for new_url in new_urls:
                        new_norm = self._normalize_url(new_url)
                        if new_norm not in self.visited_urls:
                            queue.append((new_url, 1))
                continue
            
            if not queue:
                break
                
            url, depth = queue.pop(0)
            if depth > max_depth:
                continue

            norm = self._normalize_url(url)
            if norm in self.visited_urls:
                continue
            self.visited_urls.add(norm)

            # Navigate to this page
            try:
                await self.page.goto(url, wait_until="domcontentloaded", timeout=10_000)
                await self._wait_for_stable(timeout_ms=3_000)
            except Exception as exc:
                logger.debug("Navigation failed for %s: %s", url, exc)
                continue

            # CHECK: did we land on a different domain after redirect?
            actual_url = self.page.url
            actual_domain = urlparse(actual_url).netloc.lower()
            if self.target_domain not in actual_domain:
                logger.debug("Redirect escaped target domain: %s -> %s (skipping)", url, actual_url)
                # Navigate back to a safe page
                try:
                    await self.page.go_back(wait_until="domcontentloaded", timeout=5_000)
                except Exception:
                    pass
                continue

            logger.debug("Crawling page [depth=%d]: %s", depth, url)

            # Expand hidden navigation (hamburger menus, dropdowns, accordions)
            await self.expand_navigation()

            # Pass 1: Collect all <a href> links from this page
            hrefs = await self._collect_hrefs()
            for href in hrefs:
                href_norm = self._normalize_url(href)
                if href_norm not in self.visited_urls:
                    queue.append((href, depth + 1))

            # Submit forms on this page (discovers POST endpoints + params)
            await self.fill_and_submit_forms()

            # Pass 2: Click non-link interactive elements (SPA routes, buttons, tabs)
            new_urls = await self._click_spa_elements()
            for new_url in new_urls:
                new_norm = self._normalize_url(new_url)
                if new_norm not in self.visited_urls:
                    queue.append((new_url, depth + 1))

        new_requests = len(self.interceptor.requests) - start_count
        stats = {
            "pages_visited": len(self.visited_urls),
            "elements_clicked": len(self.clicked_selectors),
            "new_requests_triggered": new_requests,
        }
        logger.info("SPA crawl complete: %s", stats)
        return stats

    # ── Element Discovery ────────────────────────────────────────────

    async def _collect_hrefs(self) -> list[str]:
        """
        Collect all <a href> URLs from the current page.

        Framework-agnostic: works on server-rendered HTML, Angular routerLink,
        React Link, Vue router-link — all eventually render as <a href>.

        Filters:
          - Same origin only
          - Skips javascript:, mailto:, tel:, data:, blob:
          - Skips file downloads (.pdf, .zip, .exe, etc.)
          - Deduplicates
        """
        raw = await self.page.evaluate("""
            () => {
                const links = [];
                const skip_extensions = new Set([
                    '.pdf', '.zip', '.gz', '.tar', '.exe', '.dmg', '.msi',
                    '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
                    '.mp4', '.mp3', '.avi', '.mov', '.wmv',
                    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp',
                    '.css', '.js', '.map', '.woff', '.woff2', '.ttf', '.eot',
                    '.md', '.txt', '.rst', '.log',
                    '.yml', '.yaml', '.toml', '.ini', '.cfg',
                    '.xml', '.json',
                    '.csv', '.tsv',
                    '.bak', '.old', '.orig', '.swp',
                    '.dist', '.example', '.sample'
                ]);
                const skip_protocols = ['javascript:', 'mailto:', 'tel:', 'data:', 'blob:'];

                document.querySelectorAll('a[href]').forEach(a => {
                    try {
                        const href = a.getAttribute('href');
                        if (!href || href === '#' || href.startsWith('#')) return;
                        if (skip_protocols.some(p => href.toLowerCase().startsWith(p))) return;

                        const url = new URL(href, document.baseURI);
                        if (url.origin !== new URL(document.baseURI).origin) return;

                        // Skip file downloads
                        const ext = url.pathname.split('.').pop()?.toLowerCase();
                        if (ext && skip_extensions.has('.' + ext)) return;

                        let hrefVal = url.href;
                        const hashIdx = hrefVal.indexOf('#');
                        if (hashIdx !== -1) {
                            const fragment = hrefVal.substring(hashIdx + 1);
                            if (fragment.startsWith('/')) {
                                // Hash route - keep it, but strip any plain anchor after the route
                                links.push(hrefVal);
                            } else {
                                // Plain anchor - strip it
                                links.push(hrefVal.substring(0, hashIdx));
                            }
                        } else {
                            links.push(hrefVal);
                        }
                    } catch(e) {}
                });
                return [...new Set(links)];
            }
        """)
        
        filtered_links = []
        for u in raw:
            if self.target_domain not in urlparse(u).netloc.lower():
                continue
            path = urlparse(u).path.lower()
            
            # Skip destructive/useless endpoints
            if any(pattern in path for pattern in self._SKIP_PATH_PATTERNS):
                logger.debug("Skipping destructive/useless URL: %s", u)
                continue
            
            # Scope check: URL must be under target path prefix
            if self.target_path_prefix and not path.startswith(self.target_path_prefix.lower()):
                logger.debug("Scope check failed for %s (prefix=%s, path=%s)", u, self.target_path_prefix.lower(), path)
                continue
                
            logger.debug("Added URL after filter: %s", u)
            filtered_links.append(u)
            
        return filtered_links

    async def _click_spa_elements(self, max_clicks: int = 200) -> list[str]:
        """
        Click interactive elements that don't have meaningful href attributes.
        These are SPA route triggers: buttons, tabs, Angular (click) handlers, etc.

        Returns list of new URLs discovered via clicks.
        """
        elements = await self.discover_interactive_elements()
        new_urls: list[str] = []

        # Filter to only non-link elements (links are handled by BFS)
        spa_elements = [
            el for el in elements
            if not el.href
            or el.href.strip() == '#'
            or el.href.strip() == ''
            or el.href.startswith('javascript:')
        ]

        for el in spa_elements:
            if len(self.clicked_selectors) > max_clicks:  # Safety cap per page
                break
            result = await self.click_and_observe(el)
            if result.get("url_changed") and result.get("new_url"):
                new_url = result["new_url"]
                if self.target_domain in urlparse(new_url).netloc.lower():
                    new_urls.append(new_url)
                # Navigate back for the next click
                try:
                    await self.page.go_back(wait_until="domcontentloaded", timeout=5_000)
                    await self.page.wait_for_timeout(500)
                except Exception:
                    # If go_back fails, just continue — we already captured the URL
                    break

        return new_urls

    def _normalize_url(self, url: str) -> str:
        """
        Normalize URL for dedup.
        
        Preserves hash-based SPA routes (#/login, #/search) because they're
        different views. Strips plain anchors (#section, #top) because they're
        same-page jumps.
        """
        parsed = urlparse(url)
        fragment = parsed.fragment
        
        # Check if fragment is a hash route (starts with /)
        has_hash_route = fragment.startswith("/") if fragment else False
        
        # Strip query string for dedup (we care about the route, not query params)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip("/")
        
        # Normalize common index pages
        for suffix in ("/index.php", "/index.html", "/index.htm", "/index.jsp",
                        "/index.asp", "/index.aspx", "/default.asp", "/default.aspx"):
            if base.lower().endswith(suffix):
                base = base[:len(base) - len(suffix)]
        
        base = base.rstrip("/") or base
        
        # Append hash route if present
        if has_hash_route:
            base = f"{base}#/{fragment.lstrip('/')}"
        
        return base

    async def discover_interactive_elements(self) -> list[ElementInfo]:
        """
        Find all interactive elements on the current page.

        Discovers:
          - <a> links (traditional and SPA router)
          - <button> elements
          - Elements with click handlers (onclick, ng-click, @click, etc.)
          - Navigation menu items
          - Tab controls
          - Any element with role="button" or role="link"
        """
        elements: list[ElementInfo] = []
        seen_selectors: set[str] = set()

        # JS-based extraction: get all elements that are likely interactive
        raw = await self.page.evaluate("""
            () => {
                const results = [];
                const seen = new Set();

                function addElement(el) {
                    // Build a unique selector
                    let selector = '';
                    if (el.id) {
                        selector = '#' + CSS.escape(el.id);
                    } else if (el.getAttribute('data-testid')) {
                        selector = '[data-testid="' + el.getAttribute('data-testid') + '"]';
                    } else {
                        // Build a path-based selector
                        const tag = el.tagName.toLowerCase();
                        const classes = el.className && typeof el.className === 'string'
                            ? '.' + el.className.trim().split(/\\s+/).slice(0, 2).map(c => CSS.escape(c)).join('.')
                            : '';
                        const idx = Array.from(el.parentElement?.children || []).indexOf(el);
                        selector = tag + classes + ':nth-child(' + (idx + 1) + ')';
                    }

                    if (seen.has(selector)) return;
                    seen.add(selector);

                    const rect = el.getBoundingClientRect();
                    // Skip invisible elements
                    if (rect.width === 0 && rect.height === 0) return;

                    const text = (el.textContent || '').trim().substring(0, 80);
                    const href = el.getAttribute('href') || null;
                    const tag = el.tagName.toLowerCase();

                    let elType = 'other';
                    if (tag === 'a') elType = 'link';
                    else if (tag === 'button') elType = 'button';
                    else if (tag === 'input' && el.type === 'submit') elType = 'button';
                    else if (el.getAttribute('role') === 'button') elType = 'button';
                    else if (el.getAttribute('role') === 'tab') elType = 'tab';
                    else if (el.getAttribute('role') === 'menuitem') elType = 'menu';
                    else if (el.getAttribute('role') === 'link') elType = 'link';

                    results.push({ selector, tag, text, href, element_type: elType });
                }

                // Links
                document.querySelectorAll('a[href]').forEach(addElement);

                // Buttons
                document.querySelectorAll('button, input[type="submit"], input[type="button"]').forEach(addElement);

                // Elements with click handlers
                document.querySelectorAll('*').forEach(el => {
                    if (el.hasAttribute('onclick') || 
                        el.hasAttribute('ng-click') || 
                        el.hasAttribute('(click)') || 
                        el.hasAttribute('v-on:click') || 
                        el.hasAttribute('@click')) {
                        addElement(el);
                    }
                });

                // ARIA roles
                document.querySelectorAll('[role="button"], [role="link"], [role="tab"], [role="menuitem"]').forEach(addElement);

                // Elements with cursor pointer style (common in SPAs)
                document.querySelectorAll('[style*="cursor: pointer"], [style*="cursor:pointer"]').forEach(addElement);

                return results;
            }
        """)

        for item in raw:
            sel = item.get("selector", "")
            if sel and sel not in seen_selectors and sel not in self.clicked_selectors:
                seen_selectors.add(sel)
                elements.append(ElementInfo(
                    selector=sel,
                    tag=item.get("tag", ""),
                    text=item.get("text", ""),
                    href=item.get("href"),
                    element_type=item.get("element_type", "other"),
                ))

        return elements

    # ── Click and Observe ────────────────────────────────────────────

    async def click_and_observe(self, element: ElementInfo) -> dict[str, Any]:
        """
        Click an element and observe what happens.

        Returns:
            {
                "url_changed": bool,
                "new_url": str or None,
                "new_requests": int,
                "dom_changed": bool,
                "error": str or None,
            }
        """
        self.clicked_selectors.add(element.selector)

        url_before = self.page.url
        requests_before = len(self.interceptor.requests)

        # Capture DOM hash before click to detect major changes
        dom_hash_before = await self._dom_hash()

        try:
            el_handle = await self.page.query_selector(element.selector)
            if not el_handle:
                return {"url_changed": False, "new_url": None, "new_requests": 0, "dom_changed": False, "error": "element_not_found"}

            # Some links navigate away, so we use click + wait pattern
            try:
                await el_handle.click(timeout=3_000, force=False)
            except Exception:
                # Element might be covered, try JS click
                try:
                    await el_handle.evaluate("el => el.click()")
                except Exception:
                    return {"url_changed": False, "new_url": None, "new_requests": 0, "dom_changed": False, "error": "click_failed"}

            # Wait for potential network activity to settle
            await self._wait_for_stable(timeout_ms=3_000)

            url_after = self.page.url
            new_requests = len(self.interceptor.requests) - requests_before
            dom_hash_after = await self._dom_hash()

            return {
                "url_changed": url_after != url_before,
                "new_url": url_after if url_after != url_before else None,
                "new_requests": new_requests,
                "dom_changed": dom_hash_after != dom_hash_before,
                "error": None,
            }

        except Exception as exc:
            return {"url_changed": False, "new_url": None, "new_requests": 0, "dom_changed": False, "error": str(exc)}

    # ── Form Discovery and Submission ────────────────────────────────

    async def fill_and_submit_forms(self, strategy: str = "smart") -> int:
        """
        Find and submit all forms on the current page.
        After each submission, navigates back if the page changed.
        """
        forms = await self._get_forms()
        current_url = self.page.url  # Remember where we are

        if not forms:
            # Debug: check if the page has any form elements at all
            form_count = await self.page.evaluate("document.querySelectorAll('form').length")
            input_count = await self.page.evaluate("document.querySelectorAll('input').length")
            if form_count > 0 or input_count > 0:
                logger.debug(
                    "Page has %d <form> and %d <input> elements but _get_forms returned 0 — "
                    "fields may lack name/id attributes. URL: %s",
                    form_count, input_count, current_url,
                )
            else:
                logger.debug("No forms or inputs found on %s", current_url)
        else:
            logger.debug("Found %d forms on %s", len(forms), current_url)

        submitted = 0

        for form in forms:
            form_key = f"{form.get('action', '')}:{','.join(f.get('name', '') for f in form.get('fields', []))}"
            if form_key in self.submitted_forms:
                continue
            self.submitted_forms.add(form_key)

            try:
                await self._submit_form(form, strategy)
                submitted += 1
            except Exception as exc:
                logger.debug("Form submission failed: %s", exc)

            # Navigate back if form submission caused navigation (redirect, etc.)
            if self._normalize_url(self.page.url) != self._normalize_url(current_url):
                try:
                    await self.page.goto(current_url, wait_until="domcontentloaded", timeout=10_000)
                    await self._wait_for_stable(timeout_ms=2_000)
                except Exception:
                    pass

        logger.info("Submitted %d forms on %s", submitted, current_url)
        return submitted

    async def _get_forms(self) -> list[dict[str, Any]]:
        """Extract all forms from the page, including non-traditional ones."""
        return await self.page.evaluate("""
            () => {
                const forms = [];

                // Traditional <form> elements
                document.querySelectorAll('form').forEach(f => {
                    const fields = [];
                    f.querySelectorAll('input, select, textarea').forEach(inp => {
                        const name = inp.name || inp.id || '';
                        if (!name) return;
                        fields.push({
                            name: name,
                            type: inp.type || inp.tagName.toLowerCase(),
                            value: inp.value || '',
                            required: inp.required,
                            selector: inp.id ? '#' + CSS.escape(inp.id) : `[name="${CSS.escape(name)}"]`,
                        });
                    });
                    if (fields.length > 0) {
                        forms.push({
                            action: f.action || window.location.href,
                            method: (f.method || 'GET').toUpperCase(),
                            fields: fields,
                            type: 'traditional',
                        });
                    }
                });

                // Non-form input groups (React/Angular/Vue style)
                // Look for input elements NOT inside a <form>
                const orphanInputs = [];
                document.querySelectorAll('input, textarea').forEach(inp => {
                    if (inp.closest('form')) return;  // Already handled above
                    const name = inp.name || inp.id || '';
                    if (!name) return;
                    orphanInputs.push({
                        name: name,
                        type: inp.type || 'text',
                        value: inp.value || '',
                        required: inp.required,
                        selector: inp.id
                            ? '#' + CSS.escape(inp.id)
                            : inp.name
                                ? '[name="' + CSS.escape(inp.name) + '"]'
                                : null,
                    });
                });
                if (orphanInputs.length > 0) {
                    // Find the nearest submit button
                    forms.push({
                        action: window.location.href,
                        method: 'POST',
                        fields: orphanInputs,
                        type: 'js_form',
                    });
                }

                return forms;
            }
        """)

    async def _submit_form(self, form: dict, strategy: str) -> None:
        """Fill and submit a single form."""
        FILL_TIMEOUT = 3_000  # 3 seconds max per field - recon, not exploitation

        for field_info in form.get("fields", []):
            selector = field_info.get("selector", "")
            if not selector:
                continue

            field_type = field_info.get("type", "text").lower()
            name = field_info.get("name", "")

            if field_type in ("hidden", "submit", "button"):
                continue

            el = await self.page.query_selector(selector)
            if not el:
                continue

            # Skip invisible elements immediately instead of waiting
            try:
                if not await el.is_visible():
                    logger.debug("Skipping invisible field: %s", name)
                    continue
            except Exception:
                continue

            if strategy == "empty":
                continue

            value = self._smart_value(field_type, name)

            try:
                if field_type in ("checkbox", "radio"):
                    await el.check(timeout=FILL_TIMEOUT)
                elif field_type == "select":
                    options = await el.evaluate("s => Array.from(s.options).map(o => o.value)")
                    if options:
                        await el.select_option(options[0] if len(options) == 1 else options[1], timeout=FILL_TIMEOUT)
                elif field_type == "file":
                    pass  # Skip file uploads in recon
                else:
                    await el.fill(value, timeout=FILL_TIMEOUT)
            except Exception as exc:
                logger.debug("Could not fill %s: %s", name, str(exc).split('\n')[0])  # Only first line

        # Submit: click the submit button or press Enter
        submit_btn = await self.page.query_selector(
            "button[type='submit'], input[type='submit'], "
            "button:not([type]), [role='button']"
        )
        try:
            if submit_btn:
                await submit_btn.click(timeout=3_000)
            else:
                # Press Enter on the last input field
                last_field = form.get("fields", [{}])[-1]
                last_sel = last_field.get("selector", "")
                if last_sel:
                    el = await self.page.query_selector(last_sel)
                    if el:
                        await el.press("Enter")
        except Exception:
            pass

        await self._wait_for_stable(timeout_ms=3_000)

    # ── Navigation Expansion ─────────────────────────────────────────

    async def expand_navigation(self) -> None:
        """
        Expand navigation menus, dropdowns, hamburger menus, and
        accordions to reveal hidden links and buttons.
        """
        # Hamburger / mobile menu toggles
        hamburger_selectors = [
            "button.navbar-toggler",
            ".hamburger", ".menu-toggle", ".nav-toggle",
            "[aria-label='Menu']", "[aria-label='Toggle navigation']",
            "button.burger", ".mobile-menu-button",
        ]
        for sel in hamburger_selectors:
            try:
                el = await self.page.query_selector(sel)
                if el and await el.is_visible():
                    await el.click(timeout=1_000)
                    await self.page.wait_for_timeout(500)
            except Exception:
                pass

        # Dropdowns
        dropdown_selectors = [
            ".dropdown-toggle", "[data-toggle='dropdown']",
            "[data-bs-toggle='dropdown']", ".dropdown > a",
        ]
        for sel in dropdown_selectors:
            elements = await self.page.query_selector_all(sel)
            for el in elements[:10]:  # Cap at 10 to avoid runaway clicks
                try:
                    if await el.is_visible():
                        await el.click(timeout=1_000)
                        await self.page.wait_for_timeout(300)
                except Exception:
                    pass

        # Accordions / expandable sections
        accordion_selectors = [
            ".accordion-button", "[data-toggle='collapse']",
            "[data-bs-toggle='collapse']", ".expandable",
            "details > summary",
        ]
        for sel in accordion_selectors:
            elements = await self.page.query_selector_all(sel)
            for el in elements[:10]:
                try:
                    if await el.is_visible():
                        await el.click(timeout=1_000)
                        await self.page.wait_for_timeout(300)
                except Exception:
                    pass

    async def scroll_for_lazy_content(self, max_scrolls: int = 10) -> int:
        """
        Scroll down the page incrementally to trigger lazy loading.

        Returns the number of new requests triggered by scrolling.
        """
        requests_before = len(self.interceptor.requests)
        prev_height = 0

        for i in range(max_scrolls):
            current_height = await self.page.evaluate("document.body.scrollHeight")
            if current_height == prev_height:
                break  # No new content loaded
            prev_height = current_height

            await self.page.evaluate("window.scrollBy(0, window.innerHeight)")
            await self.page.wait_for_timeout(1_000)

        # Scroll back to top
        await self.page.evaluate("window.scrollTo(0, 0)")

        new_requests = len(self.interceptor.requests) - requests_before
        if new_requests > 0:
            logger.info("Lazy loading triggered %d new requests", new_requests)
        return new_requests

    async def trigger_javascript_actions(self) -> int:
        """
        Trigger JS-based interactions not tied to clicks:
          - Focus/blur on input fields
          - Keyboard events (Escape, Tab)
          - SearchParams change via history.pushState listening
        """
        requests_before = len(self.interceptor.requests)

        # Focus + blur on every visible input (some apps fetch on focus)
        inputs = await self.page.query_selector_all("input:visible, textarea:visible")
        for inp in inputs[:15]:
            try:
                await inp.focus()
                await self.page.wait_for_timeout(200)
                await inp.evaluate("el => el.blur()")
            except Exception:
                pass

        # Press Escape (closes modals, might reveal underlying API state)
        try:
            await self.page.keyboard.press("Escape")
            await self.page.wait_for_timeout(300)
        except Exception:
            pass

        return len(self.interceptor.requests) - requests_before

    # ── Internal helpers ─────────────────────────────────────────────

    async def _wait_for_stable(self, timeout_ms: int = 3_000) -> None:
        """Wait for network to settle, with a bounded timeout."""
        try:
            await self.page.wait_for_load_state("networkidle", timeout=timeout_ms)
        except Exception:
            pass  # SPAs often never reach networkidle
        await self.page.wait_for_timeout(500)

    async def _dom_hash(self) -> str:
        """Quick structural hash of the DOM to detect major changes."""
        return await self.page.evaluate("""
            () => {
                const tags = document.querySelectorAll('*');
                return tags.length + ':' + document.title + ':' + document.body.children.length;
            }
        """)

    @staticmethod
    def _smart_value(field_type: str, field_name: str) -> str:
        """Generate realistic dummy data based on field type and name."""
        name_lower = field_name.lower()

        # Name-based heuristics
        if "email" in name_lower or field_type == "email":
            return "test@example.com"
        if "password" in name_lower or "passwd" in name_lower or field_type == "password":
            return "TestPassword123!"
        if "phone" in name_lower or "tel" in name_lower or field_type == "tel":
            return "5551234567"
        if "url" in name_lower or "website" in name_lower or field_type == "url":
            return "https://example.com"
        if "zip" in name_lower or "postal" in name_lower:
            return "10001"
        if "city" in name_lower:
            return "New York"
        if "state" in name_lower or "province" in name_lower:
            return "NY"
        if "country" in name_lower:
            return "US"
        if "address" in name_lower:
            return "123 Test Street"
        if "name" in name_lower and "user" in name_lower:
            return "testuser"
        if "first" in name_lower and "name" in name_lower:
            return "Test"
        if "last" in name_lower and "name" in name_lower:
            return "User"
        if "name" in name_lower:
            return "Test User"
        if "search" in name_lower or "query" in name_lower or "q" == name_lower:
            return "test"
        if "age" in name_lower:
            return "25"
        if "date" in name_lower or field_type == "date":
            return "2024-01-15"
        if "quantity" in name_lower or "amount" in name_lower or "count" in name_lower:
            return "1"
        if "comment" in name_lower or "message" in name_lower or "description" in name_lower:
            return "This is a test comment."
        if field_type == "number":
            return "42"

        return "test"
