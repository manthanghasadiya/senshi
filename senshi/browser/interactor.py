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

    def __init__(
        self,
        page: Any,
        interceptor: Any,
        target_domain: str,
    ) -> None:
        self.page = page
        self.interceptor = interceptor
        self.target_domain = target_domain

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
        Crawl a single-page application by interacting with UI elements.

        Instead of parsing HTML for links, we:
        1. Find all clickable elements on the current page
        2. Click each one
        3. Observe what requests are triggered
        4. If the URL changed, treat it as a new "page" and recurse
        5. Navigate back and continue

        Returns dict with crawl stats.
        """
        start_count = len(self.interceptor.requests)
        await self._crawl_recursive(self.page.url, depth=0, max_depth=max_depth, max_pages=max_pages)
        new_requests = len(self.interceptor.requests) - start_count

        stats = {
            "pages_visited": len(self.visited_urls),
            "elements_clicked": len(self.clicked_selectors),
            "new_requests_triggered": new_requests,
        }
        logger.info("SPA crawl complete: %s", stats)
        return stats

    async def _crawl_recursive(
        self,
        url: str,
        depth: int,
        max_depth: int,
        max_pages: int,
    ) -> None:
        """Recursive SPA crawl."""
        if depth > max_depth or len(self.visited_urls) >= max_pages:
            return

        # Normalize URL for dedup
        norm = url.split("#")[0].split("?")[0].rstrip("/")
        if norm in self.visited_urls:
            return
        self.visited_urls.add(norm)

        logger.debug("Crawling page [depth=%d]: %s", depth, url)

        # Expand hidden elements first
        await self.expand_navigation()

        # Find all interactive elements
        elements = await self.discover_interactive_elements()
        logger.debug("Found %d interactive elements on %s", len(elements), url)

        # Click each element
        for el in elements:
            if len(self.visited_urls) >= max_pages:
                break

            result = await self.click_and_observe(el)

            if result.get("url_changed") and result.get("new_url"):
                new_url = result["new_url"]
                new_domain = urlparse(new_url).netloc.lower()
                if self.target_domain in new_domain:
                    await self._crawl_recursive(new_url, depth + 1, max_depth, max_pages)
                    # Navigate back
                    try:
                        await self.page.go_back(wait_until="domcontentloaded", timeout=5_000)
                        await self.page.wait_for_timeout(500)
                    except Exception:
                        try:
                            await self.page.goto(url, wait_until="domcontentloaded", timeout=10_000)
                            await self.page.wait_for_timeout(500)
                        except Exception:
                            pass

    # ── Element Discovery ────────────────────────────────────────────

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

        Strategies:
          smart   -- detect field types and fill with realistic dummy data
          empty   -- submit empty to provoke validation errors

        Returns the number of forms submitted.
        """
        forms = await self._get_forms()
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

        logger.info("Submitted %d forms on %s", submitted, self.page.url)
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
                document.querySelectorAll('input:not(form input), textarea:not(form textarea)').forEach(inp => {
                    const name = inp.name || inp.id || '';
                    if (!name) return;
                    orphanInputs.push({
                        name: name,
                        type: inp.type || 'text',
                        value: inp.value || '',
                        required: inp.required,
                        selector: inp.id ? '#' + CSS.escape(inp.id) : `[name="${CSS.escape(name)}"]`,
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
        for field_info in form.get("fields", []):
            selector = field_info.get("selector", "")
            if not selector:
                continue

            field_type = field_info.get("type", "text").lower()
            name = field_info.get("name", "")

            # Skip hidden, submit, checkbox, radio in smart mode
            if field_type in ("hidden", "submit", "button"):
                continue

            el = await self.page.query_selector(selector)
            if not el:
                continue

            if strategy == "empty":
                continue  # Leave all fields empty

            # Smart fill based on field type and name
            value = self._smart_value(field_type, name)

            try:
                if field_type in ("checkbox", "radio"):
                    await el.check()
                elif field_type == "select":
                    options = await el.evaluate("s => Array.from(s.options).map(o => o.value)")
                    if options:
                        await el.select_option(options[0] if len(options) == 1 else options[1])
                elif field_type == "file":
                    pass  # Skip file uploads in recon phase
                else:
                    await el.fill(value)
            except Exception as exc:
                logger.debug("Could not fill %s: %s", name, exc)

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
