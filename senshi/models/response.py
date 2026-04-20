"""
CapturedResponse -- structured representation of an intercepted HTTP response.

Paired with CapturedRequest to form complete request/response exchanges
for analysis and verification.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Optional


# Patterns that suggest a server-side error (useful for finding misconfigs,
# stack traces, debug mode leaks)
_ERROR_PATTERNS = [
    re.compile(r"Traceback \(most recent call last\)", re.I),
    re.compile(r"Fatal error:", re.I),
    re.compile(r"Stack Trace:", re.I),
    re.compile(r"at [\w.]+\([\w]+\.java:\d+\)", re.I),         # Java
    re.compile(r"Exception in thread", re.I),
    re.compile(r"<b>Warning</b>:.*on line \d+", re.I),          # PHP
    re.compile(r"Microsoft \.NET Framework.*Error", re.I),
    re.compile(r"Unhandled Exception", re.I),
    re.compile(r"Internal Server Error", re.I),
    re.compile(r"DEBUG\s*=\s*True", re.I),                      # Django debug
    re.compile(r"SQLSTATE\[\w+\]", re.I),                       # PDO
    re.compile(r"pg_query\(\):", re.I),                          # PostgreSQL
    re.compile(r"ORA-\d{4,5}", re.I),                           # Oracle
    re.compile(r"mysql_fetch", re.I),                            # MySQL
    re.compile(r"MongoError", re.I),                             # MongoDB
]


@dataclass
class CapturedResponse:
    """
    Structured representation of a browser HTTP response.

    Created by TrafficInterceptor when the browser receives a response.
    """

    url: str
    status: int
    headers: dict[str, str]
    body: str                    # text body (truncated for large responses)
    timing_ms: float = 0.0      # response time in milliseconds

    # ── Content helpers ──────────────────────────────────────────────

    def is_json(self) -> bool:
        ct = self.headers.get("content-type", "").lower()
        if "json" in ct:
            return True
        stripped = self.body.strip()
        if stripped and stripped[0] in ("{", "["):
            try:
                json.loads(stripped)
                return True
            except (json.JSONDecodeError, ValueError):
                pass
        return False

    def json(self) -> Any:
        """Parse body as JSON. Returns None on failure."""
        try:
            return json.loads(self.body)
        except (json.JSONDecodeError, ValueError):
            return None

    def is_html(self) -> bool:
        ct = self.headers.get("content-type", "").lower()
        return "html" in ct or self.body.strip().startswith("<")

    def is_redirect(self) -> bool:
        return 300 <= self.status < 400

    def is_error(self) -> bool:
        return self.status >= 400

    def is_success(self) -> bool:
        return 200 <= self.status < 300

    # ── Security-relevant analysis ───────────────────────────────────

    def contains_error_traces(self) -> list[str]:
        """
        Return list of error/debug pattern matches found in the body.
        Useful for detecting information disclosure.
        """
        found: list[str] = []
        for pat in _ERROR_PATTERNS:
            match = pat.search(self.body)
            if match:
                found.append(match.group(0)[:100])
        return found

    def get_security_headers(self) -> dict[str, Optional[str]]:
        """Check presence of security headers. Missing ones = potential issues."""
        checks = [
            "x-frame-options",
            "x-content-type-options",
            "x-xss-protection",
            "strict-transport-security",
            "content-security-policy",
            "referrer-policy",
            "permissions-policy",
        ]
        return {h: self.headers.get(h) for h in checks}

    def get_cookies_from_response(self) -> list[dict[str, str]]:
        """Parse Set-Cookie headers into structured dicts."""
        cookies: list[dict[str, str]] = []
        for hdr_name in ("set-cookie", "Set-Cookie"):
            raw = self.headers.get(hdr_name, "")
            if not raw:
                continue
            for cookie_str in raw.split("\n"):
                parts = cookie_str.strip().split(";")
                if not parts:
                    continue
                name_val = parts[0].strip()
                if "=" not in name_val:
                    continue
                name, val = name_val.split("=", 1)
                cookie: dict[str, str] = {"name": name.strip(), "value": val.strip()}
                for attr in parts[1:]:
                    attr = attr.strip()
                    if "=" in attr:
                        ak, av = attr.split("=", 1)
                        cookie[ak.strip().lower()] = av.strip()
                    else:
                        cookie[attr.lower()] = "true"
                cookies.append(cookie)
        return cookies

    # ── Serialization ────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "status": self.status,
            "headers": dict(self.headers),
            "body_length": len(self.body),
            "body_preview": self.body[:500],
            "is_json": self.is_json(),
            "timing_ms": self.timing_ms,
            "error_traces": self.contains_error_traces(),
        }
