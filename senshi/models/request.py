"""
CapturedRequest -- structured representation of an intercepted HTTP request.

Every outgoing request the browser makes flows through here. We parse it
once into a structured object so all downstream consumers (analyzer,
exploit agents, reporters) work from the same data.
"""

from __future__ import annotations

import json
import re
import shlex
import time
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import parse_qs, urlencode, urlparse


@dataclass
class ParamInfo:
    """A single parameter extracted from a request."""

    name: str
    value: str
    location: str   # "query" | "body" | "path" | "header" | "cookie"
    param_type: str  # "string" | "numeric" | "email" | "uuid" | "json" | "boolean" | "url"


# ---------------------------------------------------------------------------
# Type inference
# ---------------------------------------------------------------------------

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_OBJECTID_RE = re.compile(r"^[0-9a-f]{24}$", re.IGNORECASE)
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_URL_RE = re.compile(r"^https?://", re.IGNORECASE)


def infer_param_type(name: str, value: str) -> str:
    """Infer the semantic type of a parameter from its name and value."""
    if not value:
        return "string"
    if value.isdigit() or (value.startswith("-") and value[1:].isdigit()):
        return "numeric"
    if _UUID_RE.match(value):
        return "uuid"
    if _OBJECTID_RE.match(value):
        return "objectid"
    if _EMAIL_RE.match(value):
        return "email"
    if value.lower() in ("true", "false", "1", "0", "yes", "no"):
        return "boolean"
    if _URL_RE.match(value):
        return "url"
    # Check for JSON value
    if value.startswith(("{", "[")):
        try:
            json.loads(value)
            return "json"
        except (json.JSONDecodeError, ValueError):
            pass
    return "string"


# ---------------------------------------------------------------------------
# CapturedRequest
# ---------------------------------------------------------------------------

# Regex for segments that look like dynamic identifiers in URL paths
_PATH_ID_PATTERNS = [
    re.compile(r"^\d+$"),                                    # numeric id
    re.compile(r"^[0-9a-f]{24}$", re.I),                    # MongoDB ObjectId
    re.compile(                                               # UUID v1-v5
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
        re.I,
    ),
    re.compile(r"^[A-Za-z0-9_-]{20,}$"),                    # JWT-like tokens/slugs
]


@dataclass
class CapturedRequest:
    """
    Structured representation of a browser HTTP request.

    Created by TrafficInterceptor each time a request leaves the browser.
    """

    url: str
    method: str
    headers: dict[str, str]
    body: Optional[str]
    timestamp: float
    resource_type: str  # "document" | "xhr" | "fetch" | "websocket" | "other"

    # Lazily populated
    _params: list[ParamInfo] | None = field(default=None, repr=False)

    # ── Derived helpers ──────────────────────────────────────────────────

    def get_path(self) -> str:
        return urlparse(self.url).path

    def get_base_url(self) -> str:
        p = urlparse(self.url)
        return f"{p.scheme}://{p.netloc}"

    def get_domain(self) -> str:
        return urlparse(self.url).netloc

    # ── Parameter extraction ─────────────────────────────────────────────

    def get_params(self) -> list[ParamInfo]:
        """
        Extract ALL parameters from every location in the request.

        Sources:
          1. Query string (?key=val)
          2. Body -- form-urlencoded, JSON (flattened), multipart
          3. Path segments that look like dynamic IDs
          4. Security-relevant headers (Authorization, X-API-Key, etc.)
          5. Cookies
        """
        if self._params is not None:
            return self._params

        params: list[ParamInfo] = []

        # 1. Query params
        qs = parse_qs(urlparse(self.url).query, keep_blank_values=True)
        for name, values in qs.items():
            val = values[0] if values else ""
            params.append(ParamInfo(name, val, "query", infer_param_type(name, val)))

        # 2. Body params
        params.extend(self._parse_body_params())

        # 3. Path params (dynamic segments)
        params.extend(self._parse_path_params())

        # 4. Interesting headers
        for hdr in (
            "authorization", "x-api-key", "x-auth-token", "x-csrf-token",
            "x-forwarded-for", "x-real-ip", "x-requested-with",
        ):
            val = self.headers.get(hdr, "")
            if val:
                params.append(ParamInfo(hdr, val, "header", infer_param_type(hdr, val)))

        # 5. Cookies
        raw_cookie = self.headers.get("cookie", "")
        if raw_cookie:
            for pair in raw_cookie.split(";"):
                pair = pair.strip()
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    params.append(ParamInfo(k.strip(), v.strip(), "cookie",
                                            infer_param_type(k.strip(), v.strip())))

        self._params = params
        return params

    # -- Body helpers ------------------------------------------------

    def _parse_body_params(self) -> list[ParamInfo]:
        if not self.body:
            return []

        ct = self.get_content_type()

        if ct == "json":
            return self._flatten_json(self.body)
        if ct == "form":
            params: list[ParamInfo] = []
            for k, vs in parse_qs(self.body, keep_blank_values=True).items():
                val = vs[0] if vs else ""
                params.append(ParamInfo(k, val, "body", infer_param_type(k, val)))
            return params
        if ct == "xml":
            return [ParamInfo("__xml_body__", self.body[:200], "body", "string")]
        # Fallback: treat as opaque string
        return []

    def _flatten_json(self, raw: str, prefix: str = "") -> list[ParamInfo]:
        """Recursively flatten JSON body into individual ParamInfo entries."""
        try:
            obj = json.loads(raw) if isinstance(raw, str) else raw
        except (json.JSONDecodeError, ValueError):
            return []

        params: list[ParamInfo] = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                key = f"{prefix}.{k}" if prefix else k
                if isinstance(v, (dict, list)):
                    params.extend(self._flatten_json(json.dumps(v), key))
                else:
                    val_str = str(v) if v is not None else ""
                    params.append(ParamInfo(key, val_str, "body",
                                            infer_param_type(key, val_str)))
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                key = f"{prefix}[{i}]"
                if isinstance(v, (dict, list)):
                    params.extend(self._flatten_json(json.dumps(v), key))
                else:
                    val_str = str(v) if v is not None else ""
                    params.append(ParamInfo(key, val_str, "body",
                                            infer_param_type(key, val_str)))
        return params

    # -- Path helpers ------------------------------------------------

    def _parse_path_params(self) -> list[ParamInfo]:
        params: list[ParamInfo] = []
        segments = [s for s in self.get_path().split("/") if s]
        for idx, seg in enumerate(segments):
            for pat in _PATH_ID_PATTERNS:
                if pat.match(seg):
                    params.append(
                        ParamInfo(
                            f"path_{idx}",
                            seg,
                            "path",
                            infer_param_type(f"path_{idx}", seg),
                        )
                    )
                    break
        return params

    # ── Content type ─────────────────────────────────────────────────

    def get_content_type(self) -> str:
        """Return normalized content type: json | form | multipart | xml | plain"""
        ct = self.headers.get("content-type", "").lower()
        if "json" in ct:
            return "json"
        if "form-urlencoded" in ct:
            return "form"
        if "multipart" in ct:
            return "multipart"
        if "xml" in ct:
            return "xml"
        # Sniff body
        if self.body:
            stripped = self.body.strip()
            if stripped.startswith(("{", "[")):
                try:
                    json.loads(stripped)
                    return "json"
                except Exception:
                    pass
            if "=" in stripped and "&" in stripped:
                return "form"
        return "plain"

    # ── Replay helper ────────────────────────────────────────────────

    def to_curl(self) -> str:
        """Generate a copy-pasteable curl command to replay this request."""
        parts = ["curl", "-X", self.method]

        skip_headers = {"host", "content-length", "connection", "accept-encoding"}
        for k, v in self.headers.items():
            if k.lower() not in skip_headers:
                parts.extend(["-H", f"{k}: {v}"])

        if self.body:
            parts.extend(["-d", self.body])

        parts.append(self.url)
        return " ".join(shlex.quote(p) for p in parts)

    # ── Serialization ────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "path": self.get_path(),
            "content_type": self.get_content_type(),
            "resource_type": self.resource_type,
            "params": [
                {"name": p.name, "value": p.value, "location": p.location, "type": p.param_type}
                for p in self.get_params()
            ],
            "timestamp": self.timestamp,
        }
