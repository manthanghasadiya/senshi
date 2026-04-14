"""
DOM Analyzer - Extracts forms, inputs, and interactive elements from the page.

Complements traffic interception by analyzing the actual DOM to find:
1. Forms that haven't been submitted yet
2. Hidden inputs and CSRF tokens
3. JavaScript event handlers
4. Dynamic input fields
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any, Optional

logger = logging.getLogger("senshi.browser.dom_analyzer")


@dataclass
class FormField:
    """Represents a form input field."""

    name: str
    field_type: str  # text, password, hidden, email, number, etc.
    value: Optional[str]
    required: bool
    pattern: Optional[str]
    element_id: Optional[str]


@dataclass
class DiscoveredForm:
    """Represents a discovered HTML form."""

    action: str
    method: str  # GET or POST
    enctype: str
    fields: list[FormField]
    has_csrf: bool
    csrf_field: Optional[str]
    submit_button: Optional[str]


@dataclass
class ClickableElement:
    """Represents a clickable element that might trigger actions."""

    tag: str
    text: str
    href: Optional[str]
    onclick: Optional[str]
    element_id: Optional[str]
    classes: list[str]


class DOMAnalyzer:
    """
    Analyzes page DOM to extract attack surface.

    Usage:
        analyzer = DOMAnalyzer(page)
        forms = await analyzer.get_forms()
        inputs = await analyzer.get_all_inputs()
    """

    def __init__(self, page: Any) -> None:
        self.page = page

    async def get_forms(self) -> list[DiscoveredForm]:
        """Extract all forms from the page."""
        forms: list[DiscoveredForm] = []

        form_elements = await self.page.query_selector_all("form")

        for form in form_elements:
            action = await form.get_attribute("action") or ""
            method = (await form.get_attribute("method") or "GET").upper()
            enctype = await form.get_attribute("enctype") or "application/x-www-form-urlencoded"

            # Resolve relative action URLs
            current_url = self.page.url
            if action and not action.startswith(("http://", "https://", "//")):
                base = current_url.rsplit("/", 1)[0]
                action = f"{base}/{action}"
            elif not action:
                action = current_url

            fields = await self._extract_form_fields(form)

            # Detect CSRF tokens
            csrf_field: Optional[str] = None
            has_csrf = False
            for field in fields:
                if field.field_type == "hidden" and any(
                    tok in field.name.lower() for tok in ["csrf", "token", "_token", "authenticity"]
                ):
                    has_csrf = True
                    csrf_field = field.name
                    break

            # Find submit button label
            submit = await form.query_selector("button[type=submit], input[type=submit]")
            submit_text: Optional[str] = None
            if submit:
                submit_text = await submit.get_attribute("value") or await submit.inner_text()

            forms.append(
                DiscoveredForm(
                    action=action,
                    method=method,
                    enctype=enctype,
                    fields=fields,
                    has_csrf=has_csrf,
                    csrf_field=csrf_field,
                    submit_button=submit_text,
                )
            )

        logger.info(f"Found {len(forms)} forms on {self.page.url}")
        return forms

    async def _extract_form_fields(self, form: Any) -> list[FormField]:
        """Extract all input fields from a form element."""
        fields: list[FormField] = []
        inputs = await form.query_selector_all("input, select, textarea")

        for inp in inputs:
            tag = await inp.evaluate("el => el.tagName.toLowerCase()")
            name = await inp.get_attribute("name")
            if not name:
                continue

            if tag == "input":
                field_type = await inp.get_attribute("type") or "text"
            elif tag == "select":
                field_type = "select"
            else:
                field_type = "textarea"

            value = await inp.get_attribute("value")
            required = await inp.get_attribute("required") is not None
            pattern = await inp.get_attribute("pattern")
            element_id = await inp.get_attribute("id")

            fields.append(
                FormField(
                    name=name,
                    field_type=field_type,
                    value=value,
                    required=required,
                    pattern=pattern,
                    element_id=element_id,
                )
            )

        return fields

    async def get_all_inputs(self) -> list[FormField]:
        """Get ALL input elements on the page, including those outside forms."""
        fields: list[FormField] = []
        inputs = await self.page.query_selector_all("input, select, textarea")

        for inp in inputs:
            tag = await inp.evaluate("el => el.tagName.toLowerCase()")
            name = await inp.get_attribute("name") or await inp.get_attribute("id")
            if not name:
                continue

            if tag == "input":
                field_type = await inp.get_attribute("type") or "text"
            elif tag == "select":
                field_type = "select"
            else:
                field_type = "textarea"

            fields.append(
                FormField(
                    name=name,
                    field_type=field_type,
                    value=await inp.get_attribute("value"),
                    required=await inp.get_attribute("required") is not None,
                    pattern=await inp.get_attribute("pattern"),
                    element_id=await inp.get_attribute("id"),
                )
            )

        return fields

    async def get_clickable_elements(self) -> list[ClickableElement]:
        """Find all clickable elements that might trigger actions."""
        clickables: list[ClickableElement] = []
        seen: set[str] = set()

        selectors = ["a[href]", "button", "[onclick]", "[role=button]", ".btn", ".button"]

        for selector in selectors:
            elements = await self.page.query_selector_all(selector)
            for el in elements:
                tag = await el.evaluate("el => el.tagName.toLowerCase()")
                text = (await el.inner_text()).strip()[:100]
                href = await el.get_attribute("href")
                onclick = await el.get_attribute("onclick")
                element_id = await el.get_attribute("id")
                classes = (await el.get_attribute("class") or "").split()

                key = f"{tag}:{text}:{href}"
                if key not in seen:
                    seen.add(key)
                    clickables.append(
                        ClickableElement(
                            tag=tag,
                            text=text,
                            href=href,
                            onclick=onclick,
                            element_id=element_id,
                            classes=classes,
                        )
                    )

        return clickables

    async def get_javascript_endpoints(self) -> list[str]:
        """Extract API endpoints from inline JavaScript."""
        endpoints: list[str] = []
        scripts = await self.page.query_selector_all("script:not([src])")

        url_patterns = [
            r'["\']/(api|v\d+)/[^"\']+["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.[a-z]+\(["\']([^"\']+)["\']',
            r'\$\.(get|post|ajax)\(["\']([^"\']+)["\']',
            r'XMLHttpRequest.*?open\([^,]+,\s*["\']([^"\']+)["\']',
        ]

        for script in scripts:
            content = await script.inner_text()
            for pattern in url_patterns:
                for match in re.findall(pattern, content, re.IGNORECASE):
                    if isinstance(match, tuple):
                        match = match[-1]
                    if match and not match.startswith(("http://", "https://")):
                        endpoints.append(match)

        return list(set(endpoints))

    async def get_page_context(self) -> dict:
        """Get comprehensive page context dict for LLM analysis."""
        forms = await self.get_forms()
        inputs = await self.get_all_inputs()
        js_endpoints = await self.get_javascript_endpoints()
        clickable_count = len(await self.get_clickable_elements())

        return {
            "url": self.page.url,
            "title": await self.page.title(),
            "forms": [
                {
                    "action": f.action,
                    "method": f.method,
                    "fields": [{"name": ff.name, "type": ff.field_type} for ff in f.fields],
                    "has_csrf": f.has_csrf,
                }
                for f in forms
            ],
            "inputs": [{"name": i.name, "type": i.field_type} for i in inputs],
            "js_endpoints": js_endpoints,
            "clickable_count": clickable_count,
        }
