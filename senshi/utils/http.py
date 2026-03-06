"""
HTTP utilities — encoding, decoding, header parsing, URL manipulation.

Common helpers used across DAST scanners and the session manager.
"""

from __future__ import annotations

import base64
import re
import urllib.parse
from typing import Any


def parse_auth_header(auth_string: str) -> dict[str, str]:
    """
    Parse an auth string into a dict suitable for session config.

    Supports:
        "Cookie: session=abc123"
        "Bearer token123"
        "X-Api-Key: abc123"

    Returns:
        Dict with auth type and value.
    """
    auth_string = auth_string.strip()

    if auth_string.lower().startswith("bearer "):
        return {"type": "bearer", "value": auth_string[7:].strip()}

    if ":" in auth_string:
        key, _, value = auth_string.partition(":")
        key = key.strip()
        value = value.strip()

        if key.lower() == "cookie":
            return {"type": "cookie", "value": value}
        else:
            return {"type": "header", "key": key, "value": value}

    # Assume it's a bearer token if no format detected
    return {"type": "bearer", "value": auth_string}


def parse_cookies(cookie_string: str) -> dict[str, str]:
    """Parse a Cookie header value into a dict."""
    cookies: dict[str, str] = {}
    for part in cookie_string.split(";"):
        part = part.strip()
        if "=" in part:
            key, _, value = part.partition("=")
            cookies[key.strip()] = value.strip()
    return cookies


def normalize_url(url: str) -> str:
    """Normalize a URL — ensure scheme, strip trailing slash."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def extract_base_url(url: str) -> str:
    """Extract scheme + host from a URL."""
    parsed = urllib.parse.urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def extract_path(url: str) -> str:
    """Extract path from a URL."""
    parsed = urllib.parse.urlparse(url)
    return parsed.path or "/"


def extract_params(url: str) -> dict[str, str]:
    """Extract query parameters from a URL."""
    parsed = urllib.parse.urlparse(url)
    return dict(urllib.parse.parse_qsl(parsed.query))


def url_encode(value: str) -> str:
    """URL-encode a string."""
    return urllib.parse.quote(value, safe="")


def url_decode(value: str) -> str:
    """URL-decode a string."""
    return urllib.parse.unquote(value)


def base64_encode(value: str) -> str:
    """Base64-encode a string."""
    return base64.b64encode(value.encode()).decode()


def base64_decode(value: str) -> str:
    """Base64-decode a string."""
    return base64.b64decode(value.encode()).decode()


def html_encode(value: str) -> str:
    """HTML entity encode special characters."""
    replacements = {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#x27;",
    }
    for char, entity in replacements.items():
        value = value.replace(char, entity)
    return value


def strip_tags(html: str) -> str:
    """Remove HTML tags from a string."""
    return re.sub(r"<[^>]+>", "", html)


def truncate_body(body: str, max_length: int = 2000) -> str:
    """Truncate response body for LLM analysis."""
    if len(body) <= max_length:
        return body
    return body[:max_length] + f"\n... [truncated, {len(body)} total chars]"


def parse_content_type(headers: dict[str, str]) -> str:
    """Extract content type from headers."""
    ct = headers.get("content-type", headers.get("Content-Type", ""))
    if ";" in ct:
        ct = ct.split(";")[0]
    return ct.strip().lower()


def is_json_response(headers: dict[str, str]) -> bool:
    """Check if response is JSON."""
    ct = parse_content_type(headers)
    return "json" in ct


def is_html_response(headers: dict[str, str]) -> bool:
    """Check if response is HTML."""
    ct = parse_content_type(headers)
    return "html" in ct


def safe_json_parse(text: str) -> dict[str, Any] | list[Any] | None:
    """Attempt to parse JSON, return None on failure."""
    import json

    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
]


def get_random_user_agent() -> str:
    """Return a random user agent string."""
    import random

    return random.choice(USER_AGENTS)
