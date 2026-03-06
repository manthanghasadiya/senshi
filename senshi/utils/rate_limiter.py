"""
Rate limiter — prevent target bans and respect API limits.

Provides both sync and async rate limiting with token bucket algorithm.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field


@dataclass
class RateLimiter:
    """
    Token bucket rate limiter.

    Args:
        requests_per_second: Maximum requests per second.
        burst: Maximum burst size (tokens available at once).
    """

    requests_per_second: float = 1.0
    burst: int = 5
    _tokens: float = field(init=False, default=0.0)
    _last_refill: float = field(init=False, default=0.0)

    def __post_init__(self) -> None:
        self._tokens = float(self.burst)
        self._last_refill = time.monotonic()

    def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self.burst, self._tokens + elapsed * self.requests_per_second)
        self._last_refill = now

    def wait(self) -> None:
        """Block until a token is available (sync)."""
        while True:
            self._refill()
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return
            # Sleep until at least one token is available
            sleep_time = (1.0 - self._tokens) / self.requests_per_second
            time.sleep(sleep_time)

    async def async_wait(self) -> None:
        """Wait until a token is available (async)."""
        while True:
            self._refill()
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return
            sleep_time = (1.0 - self._tokens) / self.requests_per_second
            await asyncio.sleep(sleep_time)

    @property
    def available_tokens(self) -> float:
        """Current available tokens."""
        self._refill()
        return self._tokens
