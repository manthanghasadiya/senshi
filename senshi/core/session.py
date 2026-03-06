"""
Session manager — HTTP session with auth, proxy, and rate limiting.

Handles all DAST HTTP requests through a configured session with
auth, cookies, proxy (Burp integration), rate limiting, and UA rotation.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

import httpx

from senshi.utils.http import get_random_user_agent, normalize_url, parse_auth_header, parse_cookies
from senshi.utils.logger import get_logger
from senshi.utils.rate_limiter import RateLimiter

logger = get_logger("senshi.core.session")


@dataclass
class Response:
    """Simplified HTTP response wrapper."""

    status_code: int
    headers: dict[str, str]
    body: str
    url: str
    elapsed_ms: float = 0.0

    @classmethod
    def from_httpx(cls, response: httpx.Response) -> Response:
        """Create from httpx Response."""
        return cls(
            status_code=response.status_code,
            headers=dict(response.headers),
            body=response.text,
            url=str(response.url),
            elapsed_ms=response.elapsed.total_seconds() * 1000 if response.elapsed else 0,
        )


class Session:
    """
    HTTP session manager for DAST scanning.

    Handles: auth, cookies, proxy (Burp), rate limiting, User-Agent rotation.
    """

    def __init__(
        self,
        base_url: str,
        auth: str = "",
        proxy: str = "",
        rate_limit: float = 1.0,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        timeout: float = 10.0,
        verify_ssl: bool = False,
    ) -> None:
        self.base_url = normalize_url(base_url)
        self.proxy = proxy
        self.timeout = timeout
        self.verify_ssl = verify_ssl

        # Rate limiter
        self._rate_limiter = RateLimiter(
            requests_per_second=1.0 / max(rate_limit, 0.1),
            burst=3,
        )

        # Build headers
        self._headers: dict[str, str] = {
            "User-Agent": get_random_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        if headers:
            self._headers.update(headers)

        # Parse auth
        self._cookies: dict[str, str] = cookies or {}
        if auth:
            auth_info = parse_auth_header(auth)
            if auth_info["type"] == "bearer":
                self._headers["Authorization"] = f"Bearer {auth_info['value']}"
            elif auth_info["type"] == "cookie":
                self._cookies.update(parse_cookies(auth_info["value"]))
            elif auth_info["type"] == "header":
                self._headers[auth_info["key"]] = auth_info["value"]

        # Baseline cache
        self._baselines: dict[str, Response] = {}

        # Stats
        self.request_count = 0

    def _build_client_kwargs(self) -> dict[str, Any]:
        """Build kwargs for httpx client."""
        kwargs: dict[str, Any] = {
            "timeout": self.timeout,
            "verify": self.verify_ssl,
            "headers": self._headers,
            "cookies": self._cookies,
            "follow_redirects": True,
        }
        if self.proxy:
            kwargs["proxy"] = self.proxy
        return kwargs

    def _resolve_url(self, path: str) -> str:
        """Resolve a path to a full URL."""
        if path.startswith(("http://", "https://")):
            return path
        path = path if path.startswith("/") else f"/{path}"
        return f"{self.base_url}{path}"

    def get(self, path: str, params: dict[str, str] | None = None) -> Response:
        """Send GET request (sync)."""
        self._rate_limiter.wait()
        url = self._resolve_url(path)

        with httpx.Client(**self._build_client_kwargs()) as client:
            response = client.get(url, params=params)
            self.request_count += 1
            return Response.from_httpx(response)

    def post(
        self,
        path: str,
        data: dict[str, Any] | None = None,
        json_data: dict[str, Any] | None = None,
        content: str | None = None,
    ) -> Response:
        """Send POST request (sync)."""
        self._rate_limiter.wait()
        url = self._resolve_url(path)

        with httpx.Client(**self._build_client_kwargs()) as client:
            response = client.post(url, data=data, json=json_data, content=content)
            self.request_count += 1
            return Response.from_httpx(response)

    def request(
        self,
        method: str,
        path: str,
        params: dict[str, str] | None = None,
        data: dict[str, Any] | None = None,
        json_data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> Response:
        """Send arbitrary HTTP request."""
        self._rate_limiter.wait()
        url = self._resolve_url(path)

        extra_headers = {**self._headers}
        if headers:
            extra_headers.update(headers)

        client_kwargs = self._build_client_kwargs()
        client_kwargs["headers"] = extra_headers

        with httpx.Client(**client_kwargs) as client:
            response = client.request(method, url, params=params, data=data, json=json_data)
            self.request_count += 1
            return Response.from_httpx(response)

    async def async_get(self, path: str, params: dict[str, str] | None = None) -> Response:
        """Send GET request (async)."""
        await self._rate_limiter.async_wait()
        url = self._resolve_url(path)

        async with httpx.AsyncClient(**self._build_client_kwargs()) as client:
            response = await client.get(url, params=params)
            self.request_count += 1
            return Response.from_httpx(response)

    async def async_post(
        self,
        path: str,
        data: dict[str, Any] | None = None,
        json_data: dict[str, Any] | None = None,
    ) -> Response:
        """Send POST request (async)."""
        await self._rate_limiter.async_wait()
        url = self._resolve_url(path)

        async with httpx.AsyncClient(**self._build_client_kwargs()) as client:
            response = await client.post(url, data=data, json=json_data)
            self.request_count += 1
            return Response.from_httpx(response)

    async def async_request(
        self,
        method: str,
        path: str,
        params: dict[str, str] | None = None,
        data: dict[str, Any] | None = None,
        json_data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> Response:
        """Send arbitrary async HTTP request."""
        await self._rate_limiter.async_wait()
        url = self._resolve_url(path)

        extra_headers = {**self._headers}
        if headers:
            extra_headers.update(headers)

        client_kwargs = self._build_client_kwargs()
        client_kwargs["headers"] = extra_headers

        async with httpx.AsyncClient(**client_kwargs) as client:
            response = await client.request(method, url, params=params, data=data, json=json_data)
            self.request_count += 1
            return Response.from_httpx(response)

    def get_baseline(self, path: str) -> Response:
        """
        Get a baseline response for comparison during scanning.
        Results are cached.
        """
        if path in self._baselines:
            return self._baselines[path]

        response = self.get(path)
        self._baselines[path] = response
        return response

    async def async_get_baseline(self, path: str) -> Response:
        """Async version of get_baseline."""
        if path in self._baselines:
            return self._baselines[path]

        response = await self.async_get(path)
        self._baselines[path] = response
        return response

    def rotate_user_agent(self) -> None:
        """Rotate to a new random User-Agent."""
        self._headers["User-Agent"] = get_random_user_agent()
