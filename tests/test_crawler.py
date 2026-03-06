"""Tests for the crawler module."""

from __future__ import annotations

import pytest

from senshi.utils.http import (
    parse_auth_header,
    normalize_url,
    extract_base_url,
    extract_params,
    url_encode,
    parse_cookies,
    truncate_body,
)


class TestHttpUtils:
    """Test HTTP utility functions."""

    def test_parse_bearer_auth(self):
        result = parse_auth_header("Bearer token123")
        assert result["type"] == "bearer"
        assert result["value"] == "token123"

    def test_parse_cookie_auth(self):
        result = parse_auth_header("Cookie: session=abc123")
        assert result["type"] == "cookie"
        assert result["value"] == "session=abc123"

    def test_parse_header_auth(self):
        result = parse_auth_header("X-Api-Key: abc123")
        assert result["type"] == "header"
        assert result["key"] == "X-Api-Key"
        assert result["value"] == "abc123"

    def test_normalize_url(self):
        assert normalize_url("example.com") == "https://example.com"
        assert normalize_url("http://example.com/") == "http://example.com"

    def test_extract_base_url(self):
        assert extract_base_url("https://example.com/api/test") == "https://example.com"

    def test_extract_params(self):
        params = extract_params("https://example.com/search?q=test&page=1")
        assert params["q"] == "test"
        assert params["page"] == "1"

    def test_url_encode(self):
        assert url_encode("<script>") == "%3Cscript%3E"

    def test_parse_cookies(self):
        cookies = parse_cookies("session=abc; user=bob; theme=dark")
        assert cookies["session"] == "abc"
        assert cookies["user"] == "bob"

    def test_truncate_body(self):
        short = "hello"
        assert truncate_body(short) == short
        long = "x" * 3000
        truncated = truncate_body(long, 100)
        assert len(truncated) < 200
        assert "truncated" in truncated


class TestRateLimiter:
    """Test rate limiter."""

    def test_basic_rate_limit(self):
        from senshi.utils.rate_limiter import RateLimiter

        limiter = RateLimiter(requests_per_second=10.0, burst=5)
        assert limiter.available_tokens > 0

    def test_token_consumption(self):
        from senshi.utils.rate_limiter import RateLimiter

        limiter = RateLimiter(requests_per_second=100.0, burst=5)
        limiter.wait()
        assert limiter.available_tokens < 5


class TestConfig:
    """Test config management."""

    def test_provider_defaults(self):
        from senshi.core.config import PROVIDER_DEFAULTS

        assert "deepseek" in PROVIDER_DEFAULTS
        assert "openai" in PROVIDER_DEFAULTS
        assert PROVIDER_DEFAULTS["deepseek"]["model"] == "deepseek-chat"
