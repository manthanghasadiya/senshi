"""
TrafficInterceptor -- captures ALL browser network traffic.

This is the CORE of Senshi's discovery. Instead of parsing HTML for links,
we watch what the browser actually does. Every XHR, fetch, document load,
and WebSocket message is recorded, deduplicated, and made available for
analysis.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Callable, Optional
from urllib.parse import urlparse

from senshi.models.request import CapturedRequest
from senshi.models.response import CapturedResponse

logger = logging.getLogger("senshi.browser.interceptor")

# File extensions that are almost never interesting for security testing
_STATIC_EXTENSIONS = frozenset({
    ".css", ".js", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".woff", ".woff2", ".ttf", ".eot", ".webp", ".avif",
    ".mp4", ".mp3", ".ogg", ".webm",
})


class TrafficInterceptor:
    """
    Captures all HTTP traffic flowing through a Playwright page.

    Attach to a page, then browse normally. Every request and response
    to the target domain is recorded. Static assets are skipped by default.

    Usage:
        interceptor = TrafficInterceptor("target.example.com")
        await interceptor.attach(page)
        # ... navigate, click, interact ...
        endpoints = interceptor.get_api_endpoints()
    """

    def __init__(
        self,
        target_domain: str,
        *,
        capture_static: bool = False,
        max_body_size: int = 100_000,
    ) -> None:
        """
        Args:
            target_domain: Only capture traffic to this domain (and subdomains).
            capture_static: If True, also capture .css/.js/.png etc.
            max_body_size: Max response body bytes to store (truncated after).
        """
        self.target_domain = target_domain.lower()
        self.capture_static = capture_static
        self.max_body_size = max_body_size

        self.requests: list[CapturedRequest] = []
        self.responses: dict[str, CapturedResponse] = {}  # keyed by URL
        self.websocket_messages: list[dict[str, Any]] = []

        self._request_callbacks: list[Callable[[CapturedRequest], None]] = []
        self._response_callbacks: list[Callable[[CapturedResponse], None]] = []

    # ── Attach to page ───────────────────────────────────────────────

    async def attach(self, page: Any) -> None:
        """
        Attach event listeners to a Playwright Page (async API).

        Captures:
          - All outgoing requests
          - All incoming responses
          - WebSocket frames
        """
        page.on("request", self._handle_request)
        page.on("response", self._handle_response)
        page.on("websocket", self._handle_websocket)
        logger.info("Interceptor attached -- capturing traffic for %s", self.target_domain)

    # ── Internal handlers ────────────────────────────────────────────

    def _handle_request(self, pw_request: Any) -> None:
        """Handle an outgoing Playwright request."""
        url = pw_request.url

        if not self._should_capture(url):
            return

        captured = CapturedRequest(
            url=url,
            method=pw_request.method,
            headers=dict(pw_request.headers),
            body=pw_request.post_data,
            timestamp=time.time(),
            resource_type=pw_request.resource_type,
        )
        self.requests.append(captured)

        for cb in self._request_callbacks:
            try:
                cb(captured)
            except Exception as exc:
                logger.debug("Request callback error: %s", exc)

    async def _handle_response(self, pw_response: Any) -> None:
        """Handle an incoming Playwright response."""
        url = pw_response.url

        if not self._should_capture(url):
            return

        # Body extraction
        try:
            raw_body = await pw_response.body()
            body_text = raw_body[:self.max_body_size].decode("utf-8", errors="replace")
        except Exception:
            body_text = ""

        # Timing extraction (separate try/except — don't lose the response over timing)
        timing_ms = 0.0
        try:
            timing = pw_response.request.timing
            if timing:
                timing_ms = max(
                    timing.get("responseEnd", 0) - timing.get("requestStart", 0),
                    0.0,
                )
        except Exception:
            pass

        captured = CapturedResponse(
            url=url,
            status=pw_response.status,
            headers=dict(pw_response.headers),
            body=body_text,
            timing_ms=timing_ms,
        )
        self.responses[url] = captured

        for cb in self._response_callbacks:
            try:
                cb(captured)
            except Exception as exc:
                logger.debug("Response callback error: %s", exc)

    def _handle_websocket(self, ws: Any) -> None:
        """Track WebSocket connections and messages."""
        ws_url = ws.url
        logger.debug("WebSocket opened: %s", ws_url)

        def on_frame(payload: Any) -> None:
            self.websocket_messages.append({
                "url": ws_url,
                "data": str(payload)[:5000],
                "timestamp": time.time(),
            })

        ws.on("framereceived", lambda payload: on_frame(payload))
        ws.on("framesent", lambda payload: on_frame(payload))

    def _should_capture(self, url: str) -> bool:
        """Decide whether to record this URL."""
        parsed = urlparse(url)
        host = parsed.netloc.lower()

        # Must be targeting our domain (or subdomain)
        if self.target_domain not in host:
            return False

        # Skip static assets unless explicitly requested
        if not self.capture_static:
            path_lower = parsed.path.lower()
            if any(path_lower.endswith(ext) for ext in _STATIC_EXTENSIONS):
                return False

        return True

    # ── Callbacks ────────────────────────────────────────────────────

    def on_request(self, callback: Callable[[CapturedRequest], None]) -> None:
        """Register a callback invoked for every captured request (real-time)."""
        self._request_callbacks.append(callback)

    def on_response(self, callback: Callable[[CapturedResponse], None]) -> None:
        """Register a callback invoked for every captured response."""
        self._response_callbacks.append(callback)

    # ── Query methods ────────────────────────────────────────────────

    def get_api_endpoints(self) -> list[CapturedRequest]:
        """
        Return deduplicated API requests (XHR and fetch only).

        Dedup key: (method, path, sorted param names).
        This ensures /api/users?id=1 and /api/users?id=2 collapse into one.
        """
        seen: set[str] = set()
        results: list[CapturedRequest] = []

        for req in self.requests:
            if req.resource_type not in ("xhr", "fetch"):
                continue
            key = self._dedup_key(req)
            if key not in seen:
                seen.add(key)
                results.append(req)

        return results

    def get_all_endpoints(self) -> list[CapturedRequest]:
        """Return ALL unique captured requests (including document loads)."""
        seen: set[str] = set()
        results: list[CapturedRequest] = []

        for req in self.requests:
            key = self._dedup_key(req)
            if key not in seen:
                seen.add(key)
                results.append(req)

        return results

    def get_unique_paths(self) -> set[str]:
        """Return set of unique URL paths discovered."""
        return {req.get_path() for req in self.requests}

    def get_response(self, url: str) -> Optional[CapturedResponse]:
        """Get the captured response for a URL, or None."""
        return self.responses.get(url)

    # ── Auth detection ───────────────────────────────────────────────

    def detect_auth_scheme(self) -> dict[str, str]:
        """
        Analyze captured traffic to infer the authentication mechanism.
        Works for any auth scheme: Bearer, Basic, API key, cookie sessions.
        """
        result: dict[str, str] = {"type": "none"}

        for req in self.requests:
            # Bearer / Basic auth (highest priority)
            auth_hdr = req.headers.get("authorization", "")
            if auth_hdr:
                if auth_hdr.lower().startswith("bearer "):
                    return {"type": "bearer", "token": auth_hdr[7:], "header": "Authorization"}
                if auth_hdr.lower().startswith("basic "):
                    return {"type": "basic", "token": auth_hdr[6:], "header": "Authorization"}

            # API key headers
            for hdr in ("x-api-key", "x-auth-token", "api-key", "apikey"):
                val = req.headers.get(hdr, "")
                if val:
                    return {"type": "api_key", "token": val, "header": hdr}

            # Cookie header in outgoing request
            cookie_hdr = req.headers.get("cookie", "")
            if cookie_hdr and result["type"] == "none":
                match = self._match_session_cookie(cookie_hdr)
                if match:
                    result = match

        # Fallback: check response set-cookie headers for session cookie names
        # This catches cases where the browser sends cookies but Playwright
        # doesn't surface them in request.headers
        if result["type"] == "none":
            for resp in self.responses.values():
                set_cookie = resp.headers.get("set-cookie", "")
                if set_cookie:
                    match = self._match_session_cookie(set_cookie)
                    if match:
                        result = match
                        break

        return result

    def _match_session_cookie(self, cookie_str: str) -> dict[str, str] | None:
        """
        Check a cookie string (from request Cookie header or response Set-Cookie)
        for session-like cookie names.

        Covers: PHP, Java, .NET, Express, Django, Rails, Flask, Laravel, Go, etc.
        """
        session_names = [
            "phpsessid", "jsessionid", "sessionid", "session",
            "sid", "token", "auth", "connect.sid", "asp.net_sessionid",
            "_session", "sess", "laravel_session", "_gorilla_session",
            "flask_session", "rack.session",
        ]
        for pair in cookie_str.split(";"):
            pair = pair.strip()
            if "=" not in pair:
                continue
            name = pair.split("=", 1)[0].strip().lower()
            if any(sn in name for sn in session_names):
                val = pair.split("=", 1)[1].strip()
                return {
                    "type": "cookie",
                    "token": val,
                    "cookie_name": pair.split("=", 1)[0].strip(),
                }
        return None

    # ── Statistics ───────────────────────────────────────────────────

    def get_stats(self) -> dict[str, Any]:
        api = self.get_api_endpoints()
        all_endpoints = self.get_all_endpoints()
        unique_params = set()
        for req in all_endpoints:
            for p in req.get_params():
                unique_params.add((p.name, p.location))

        return {
            "total_requests": len(self.requests),
            "api_requests": len(api),
            "unique_endpoints": len(all_endpoints),
            "unique_params": len(unique_params),
            "unique_paths": len(self.get_unique_paths()),
            "websocket_messages": len(self.websocket_messages),
            "auth_detected": self.detect_auth_scheme()["type"] != "none",
        }

    # ── HAR export ───────────────────────────────────────────────────

    def export_har(self, path: str) -> None:
        """
        Export captured traffic as HAR 1.2 (HTTP Archive).
        Compatible with Burp Suite, OWASP ZAP, Chrome DevTools.
        """
        entries = []
        for req in self.requests:
            resp = self.responses.get(req.url)
            entry: dict[str, Any] = {
                "startedDateTime": time.strftime(
                    "%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(req.timestamp)
                ),
                "request": {
                    "method": req.method,
                    "url": req.url,
                    "headers": [{"name": k, "value": v} for k, v in req.headers.items()],
                    "queryString": [
                        {"name": p.name, "value": p.value}
                        for p in req.get_params() if p.location == "query"
                    ],
                    "postData": {"text": req.body or "", "mimeType": req.headers.get("content-type", "")},
                    "bodySize": len(req.body) if req.body else 0,
                },
            }
            if resp:
                entry["response"] = {
                    "status": resp.status,
                    "headers": [{"name": k, "value": v} for k, v in resp.headers.items()],
                    "content": {"text": resp.body[:self.max_body_size], "size": len(resp.body)},
                }
                entry["time"] = resp.timing_ms
            entries.append(entry)

        har = {
            "log": {
                "version": "1.2",
                "creator": {"name": "Senshi", "version": "1.0.0"},
                "entries": entries,
            }
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(har, f, indent=2)
        logger.info("HAR exported: %s (%d entries)", path, len(entries))

    # ── Reset ────────────────────────────────────────────────────────

    def clear(self) -> None:
        """Clear all captured data."""
        self.requests.clear()
        self.responses.clear()
        self.websocket_messages.clear()

    # ── Internal ─────────────────────────────────────────────────────

    @staticmethod
    def _dedup_key(req: CapturedRequest) -> str:
        """Stable key for deduplication: method + path + sorted param names."""
        param_names = sorted(
            p.name for p in req.get_params()
            if p.location in ("query", "body")
        )
        return f"{req.method}:{req.get_path()}:{','.join(param_names)}"
