"""
Traffic Interceptor - Captures all browser traffic for analysis and injection.

This is the core of browser-instrumented pentesting. Every request/response
flows through here, giving us:
1. Complete visibility into app communication
2. Ability to inject payloads into any request
3. Response capture for verification
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional
from urllib.parse import parse_qs, urlencode, urlparse

logger = logging.getLogger("senshi.browser.interceptor")


@dataclass
class CapturedRequest:
    """Represents a captured HTTP request."""

    url: str
    method: str
    headers: dict[str, str]
    post_data: Optional[str]
    post_data_json: Optional[dict]
    resource_type: str
    timestamp: float

    # Extracted components
    base_url: str = ""
    path: str = ""
    query_params: dict[str, list[str]] = field(default_factory=dict)
    body_params: dict[str, Any] = field(default_factory=dict)
    path_params: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        parsed = urlparse(self.url)
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"
        self.path = parsed.path
        self.query_params = parse_qs(parsed.query)

        if self.post_data:
            content_type = self.headers.get("content-type", "")
            if "application/json" in content_type:
                try:
                    self.post_data_json = json.loads(self.post_data)
                    self.body_params = self._flatten_json(self.post_data_json)
                except json.JSONDecodeError:
                    pass
            elif "application/x-www-form-urlencoded" in content_type:
                self.body_params = {k: v[0] if len(v) == 1 else v for k, v in parse_qs(self.post_data).items()}

        self.path_params = self._detect_path_params()

    def _flatten_json(self, obj: Any, prefix: str = "") -> dict[str, Any]:
        """Flatten nested JSON into dot-notation keys."""
        items: dict[str, Any] = {}
        if isinstance(obj, dict):
            for k, v in obj.items():
                new_key = f"{prefix}.{k}" if prefix else k
                if isinstance(v, (dict, list)):
                    items.update(self._flatten_json(v, new_key))
                else:
                    items[new_key] = v
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                new_key = f"{prefix}[{i}]"
                if isinstance(v, (dict, list)):
                    items.update(self._flatten_json(v, new_key))
                else:
                    items[new_key] = v
        return items

    def _detect_path_params(self) -> list[str]:
        """Detect likely path parameters (numeric IDs, UUIDs, etc.)."""
        params = []
        parts = self.path.split("/")
        for i, part in enumerate(parts):
            if re.match(r"^\d+$", part):
                params.append(f"path[{i}]:numeric")
            elif re.match(r"^[a-f0-9-]{36}$", part, re.I):
                params.append(f"path[{i}]:uuid")
            elif re.match(r"^[a-f0-9]{24}$", part, re.I):
                params.append(f"path[{i}]:objectid")
        return params

    def get_all_params(self) -> dict[str, Any]:
        """Get all parameters organized by location."""
        return {
            "query": self.query_params,
            "body": self.body_params,
            "path": self.path_params,
            "header": {
                k: v
                for k, v in self.headers.items()
                if k.lower() in ["x-forwarded-for", "x-real-ip", "host", "origin", "referer"]
            },
        }


@dataclass
class CapturedResponse:
    """Represents a captured HTTP response."""

    url: str
    status: int
    headers: dict[str, str]
    body: bytes
    body_text: str = ""
    timestamp: float = 0.0

    def __post_init__(self) -> None:
        try:
            self.body_text = self.body.decode("utf-8", errors="replace")
        except Exception:
            self.body_text = ""

    def contains_pattern(self, patterns: list[str]) -> list[str]:
        """Check if response contains any of the given patterns."""
        return [p for p in patterns if p.lower() in self.body_text.lower()]


@dataclass
class InterceptedExchange:
    """A request-response pair."""

    request: CapturedRequest
    response: Optional[CapturedResponse] = None


class TrafficInterceptor:
    """
    Intercepts all browser traffic for analysis and payload injection.

    Usage (async Playwright context):
        interceptor = TrafficInterceptor(target_base_url="http://target.com")
        await interceptor.attach(page)
        await page.goto("http://target.com")
        endpoints = interceptor.get_discovered_endpoints()
    """

    def __init__(self, target_base_url: str) -> None:
        self.target_base = target_base_url.rstrip("/")
        self.target_host = urlparse(target_base_url).netloc

        self.exchanges: list[InterceptedExchange] = []
        self.requests: dict[str, CapturedRequest] = {}

        self._injection_callback: Optional[Callable] = None

        self.capture_resources = {"document", "xhr", "fetch", "websocket"}
        self.ignore_extensions = {".js", ".css", ".png", ".jpg", ".gif", ".svg", ".woff", ".woff2", ".ico"}

    async def attach(self, page: Any) -> None:
        """Attach interceptor to a Playwright page (async API)."""
        page.on("request", self._on_request)
        page.on("response", self._on_response)
        await page.route("**/*", self._route_handler)
        logger.info(f"Interceptor attached, targeting {self.target_host}")

    def _on_request(self, request: Any) -> None:
        """Capture outgoing request."""
        if self.target_host not in request.url:
            return

        path = urlparse(request.url).path
        if any(path.endswith(ext) for ext in self.ignore_extensions):
            return

        captured = CapturedRequest(
            url=request.url,
            method=request.method,
            headers=dict(request.headers),
            post_data=request.post_data,
            post_data_json=None,
            resource_type=request.resource_type,
            timestamp=time.time(),
        )

        self.requests[request.url] = captured
        self.exchanges.append(InterceptedExchange(request=captured))
        logger.debug(f"Captured: {request.method} {request.url}")

    async def _on_response(self, response: Any) -> None:
        """Capture incoming response."""
        if self.target_host not in response.url:
            return

        try:
            body = await response.body()
        except Exception:
            body = b""

        captured = CapturedResponse(
            url=response.url,
            status=response.status,
            headers=dict(response.headers),
            body=body[:50000],
            timestamp=time.time(),
        )

        for exchange in reversed(self.exchanges):
            if exchange.request.url == response.url and exchange.response is None:
                exchange.response = captured
                break

        logger.debug(f"Response: {response.status} {response.url} ({len(body)} bytes)")

    async def _route_handler(self, route: Any) -> None:
        """Handle route for optional payload injection."""
        request = route.request

        if self._injection_callback and self.target_host in request.url:
            try:
                modification = self._injection_callback(request)
                if modification:
                    await route.continue_(
                        method=modification.get("method", request.method),
                        headers=modification.get("headers", request.headers),
                        post_data=modification.get("post_data", request.post_data),
                    )
                    return
            except Exception as e:
                logger.error(f"Injection callback error: {e}")

        await route.continue_()

    def set_injection_callback(self, callback: Callable) -> None:
        """Set a callback for payload injection. Callback receives a Request and returns dict or None."""
        self._injection_callback = callback

    def clear_injection(self) -> None:
        """Remove injection callback."""
        self._injection_callback = None

    def get_discovered_endpoints(self) -> list[dict]:
        """Get unique endpoints discovered from traffic."""
        seen: set[str] = set()
        endpoints = []

        for exchange in self.exchanges:
            req = exchange.request
            key = f"{req.method}:{req.path}"
            if key in seen:
                continue
            seen.add(key)

            endpoints.append(
                {
                    "url": f"{req.base_url}{req.path}",
                    "method": req.method,
                    "content_type": req.headers.get("content-type", ""),
                    "params": req.get_all_params(),
                    "has_auth": bool(req.headers.get("authorization") or req.headers.get("cookie")),
                }
            )

        return endpoints

    def get_forms_discovered(self) -> list[dict]:
        """Get form submissions (POSTs) from captured traffic."""
        forms = []
        for exchange in self.exchanges:
            req = exchange.request
            if req.method == "POST" and req.body_params:
                forms.append(
                    {
                        "action": req.url,
                        "method": "POST",
                        "fields": list(req.body_params.keys()),
                        "content_type": req.headers.get("content-type", ""),
                    }
                )
        return forms

    def find_response_for_url(self, url: str) -> Optional[CapturedResponse]:
        """Find the most recent response for a URL."""
        for exchange in reversed(self.exchanges):
            if exchange.request.url == url and exchange.response:
                return exchange.response
        return None

    def get_all_exchanges(self) -> list[InterceptedExchange]:
        """Get all captured request-response pairs."""
        return self.exchanges

    def clear(self) -> None:
        """Clear all captured traffic."""
        self.exchanges.clear()
        self.requests.clear()
