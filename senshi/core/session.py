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

    @property
    def is_logout_redirect(self) -> bool:
        """Check if this response is a redirect to a login page."""
        if self.status_code in (301, 302, 303, 307, 308):
            location = self.headers.get("Location", "").lower()
            return "login" in location or "signin" in location or "auth" in location
        return False


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

        self._default_headers: dict[str, str] = {
            "User-Agent": get_random_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        if headers:
            self._default_headers.update(headers)

        self._default_cookies: dict[str, str] = {}
        if cookies:
            self._default_cookies.update(cookies)
        
        # Auth info
        self._auth_headers: dict[str, str] = {}
        self._auth_cookies: dict[str, str] = {}
        
        if auth:
            auth_info = parse_auth_header(auth)
            if auth_info["type"] == "bearer":
                self._auth_headers["Authorization"] = f"Bearer {auth_info['value']}"
            elif auth_info["type"] == "cookie":
                self._auth_cookies.update(parse_cookies(auth_info["value"]))
            elif auth_info["type"] == "header":
                self._auth_headers[auth_info["key"]] = auth_info["value"]

        # Baseline cache
        self._baselines: dict[str, Response] = {}

        # Persistent clients for cookie jar management
        self._client: httpx.Client | None = None
        self._async_client: httpx.AsyncClient | None = None

        # Stats
        self.request_count = 0

    @property
    def cookies(self) -> dict[str, str]:
        """Get combined cookies (default + auth)."""
        return {**self._default_cookies, **self._auth_cookies}

    def update_cookies(self, cookies: dict[str, str]) -> None:
        """Update session cookies and sync with active clients."""
        self._auth_cookies.update(cookies)
        if self._client:
            self._client.cookies.update(cookies)
        if self._async_client:
            self._async_client.cookies.update(cookies)

    def update_headers(self, headers: dict[str, str]) -> None:
        """Update session headers and sync with active clients."""
        self._auth_headers.update(headers)
        if self._client:
            self._client.headers.update(headers)
        if self._async_client:
            self._async_client.headers.update(headers)

    def _get_client(self) -> httpx.Client:
        """Get or create persistent sync client."""
        if self._client is None:
            self._client = httpx.Client(**self._build_client_kwargs())
        return self._client

    async def _get_async_client(self) -> httpx.AsyncClient:
        """Get or create persistent async client."""
        if self._async_client is None:
            self._async_client = httpx.AsyncClient(**self._build_client_kwargs())
        return self._async_client

    def is_alive(self) -> bool:
        """
        Check if the session is still valid.
        Returns False if we get a redirect to a login page.
        """
        try:
            # HEAD request to base URL to check session
            response = self.request("GET", "/", allow_redirects=False, timeout=5)
            if response.is_logout_redirect:
                logger.warning(f"Session dead! Redirected to login: {response.headers.get('Location')}")
                return False
            return response.status_code < 400
        except Exception as e:
            logger.debug(f"Session health check failed: {e}")
            return False

    def close(self):
        """Close persistent clients."""
        if self._client:
            self._client.close()
            self._client = None
        if self._async_client:
            # Async close handled outside usually, but we provide this for completeness
            pass

    def _build_client_kwargs(self, skip_auth: bool = False, allow_redirects: bool = True) -> dict[str, Any]:
        """Build kwargs for httpx client."""
        headers = {**self._default_headers}
        cookies = {**self._default_cookies}
        
        if not skip_auth:
            headers.update(self._auth_headers)
            cookies.update(self._auth_cookies)
            
        kwargs: dict[str, Any] = {
            "timeout": self.timeout,
            "verify": self.verify_ssl,
            "headers": headers,
            "cookies": cookies,
            "follow_redirects": allow_redirects,
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

    def get(self, path: str, params: dict[str, str] | None = None, skip_auth: bool = False, allow_redirects: bool = True, **kwargs) -> Response:
        """Send GET request (sync)."""
        return self.request("GET", path, params=params, skip_auth=skip_auth, allow_redirects=allow_redirects, **kwargs)

    def post(
        self,
        path: str,
        data: dict[str, Any] | None = None,
        json_data: dict[str, Any] | None = None,
        content: str | None = None,
        skip_auth: bool = False,
        allow_redirects: bool = True,
        **kwargs
    ) -> Response:
        """Send POST request (sync)."""
        return self.request(
            "POST", path, data=data, json_data=json_data, content=content, 
            skip_auth=skip_auth, allow_redirects=allow_redirects, **kwargs
        )

    def request(
        self,
        method: str,
        path: str,
        params: dict[str, str] | None = None,
        data: dict[str, Any] | None = None,
        json_data: dict[str, Any] | None = None,
        content: str | None = None,
        headers: dict[str, str] | None = None,
        skip_auth: bool = False,
        allow_redirects: bool = True,
        **kwargs
    ) -> Response:
        """Send arbitrary HTTP request."""
        self._rate_limiter.wait()
        url = self._resolve_url(path)

        client_kwargs = self._build_client_kwargs(skip_auth=skip_auth, allow_redirects=allow_redirects)
        if headers:
            client_kwargs["headers"] = {**client_kwargs["headers"], **headers}

        # Debug logging for cookies/headers
        logger.debug(f"Request: {method} {url}")
        
        client = self._get_client()
        
        # Merge one-off headers if provided
        request_headers = client.headers.copy()
        if headers:
            request_headers.update(headers)

        response = client.request(
            method, 
            url, 
            params=params, 
            data=data, 
            json=json_data, 
            content=content,
            headers=request_headers,
            follow_redirects=allow_redirects,
            **kwargs
        )
        self.request_count += 1
        return Response.from_httpx(response)

    async def async_get(self, path: str, params: dict[str, str] | None = None, skip_auth: bool = False, allow_redirects: bool = True) -> Response:
        """Send GET request (async)."""
        await self._rate_limiter.async_wait()
        url = self._resolve_url(path)

        async with httpx.AsyncClient(**self._build_client_kwargs(skip_auth=skip_auth, allow_redirects=allow_redirects)) as client:
            response = await client.get(url, params=params)
            self.request_count += 1
            return Response.from_httpx(response)

    async def async_post(
        self,
        path: str,
        data: dict[str, Any] | None = None,
        json_data: dict[str, Any] | None = None,
        skip_auth: bool = False,
        allow_redirects: bool = True,
    ) -> Response:
        """Send POST request (async)."""
        await self._rate_limiter.async_wait()
        url = self._resolve_url(path)

        async with httpx.AsyncClient(**self._build_client_kwargs(skip_auth=skip_auth, allow_redirects=allow_redirects)) as client:
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
        skip_auth: bool = False,
        allow_redirects: bool = True,
    ) -> Response:
        """Send arbitrary async HTTP request."""
        await self._rate_limiter.async_wait()
        url = self._resolve_url(path)

        client = await self._get_async_client()
        
        # Merge one-off headers
        request_headers = client.headers.copy()
        if headers:
            request_headers.update(headers)

        response = await client.request(
            method, 
            url, 
            params=params, 
            data=data, 
            json=json_data,
            headers=request_headers,
            follow_redirects=allow_redirects
        )
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
        self._default_headers["User-Agent"] = get_random_user_agent()
