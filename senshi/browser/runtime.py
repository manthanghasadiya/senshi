"""
BrowserRuntime -- manages Playwright browser lifecycle.

SPA-aware navigation, stealth mode, multi-context support.
This is the foundational layer that everything else builds on.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional
from urllib.parse import urlparse

logger = logging.getLogger("senshi.browser.runtime")


class BrowserRuntime:
    """
    Manages a Playwright Chromium instance with stealth bypass
    and SPA-aware navigation strategies.

    Usage:
        async with BrowserRuntime() as runtime:
            page = await runtime.get_page()
            await runtime.navigate("https://target.com")
    """

    def __init__(
        self,
        headless: bool = True,
        timeout: int = 60_000,
        proxy: str = "",
    ) -> None:
        self.headless = headless
        self.timeout = timeout
        self.proxy = proxy

        self._playwright: Any = None
        self._browser: Any = None
        self._context: Any = None
        self._page: Any = None

    # ── Lifecycle ────────────────────────────────────────────────────

    async def launch(self) -> None:
        """
        Start Chromium with stealth settings.

        - Removes navigator.webdriver flag
        - Sets realistic viewport and UA
        - Ignores HTTPS errors (self-signed certs in labs)
        - Disables web security for cross-origin testing
        """
        from playwright.async_api import async_playwright

        self._playwright = await async_playwright().start()

        launch_args = [
            "--disable-blink-features=AutomationControlled",
            "--disable-dev-shm-usage",
            "--no-sandbox",
            "--disable-web-security",
            "--disable-features=IsolateOrigins,site-per-process",
        ]

        launch_kwargs: dict[str, Any] = {
            "headless": self.headless,
            "args": launch_args,
        }
        if self.proxy:
            launch_kwargs["proxy"] = {"server": self.proxy}

        self._browser = await self._playwright.chromium.launch(**launch_kwargs)

        self._context = await self._browser.new_context(
            viewport={"width": 1920, "height": 1080},
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/125.0.0.0 Safari/537.36"
            ),
            java_script_enabled=True,
            ignore_https_errors=True,
        )

        # Stealth scripts: remove automation fingerprints
        await self._context.add_init_script("""
            // Remove webdriver flag
            Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
            // Fake chrome runtime
            window.chrome = { runtime: {}, loadTimes: () => {}, csi: () => {} };
            // Fake plugins
            Object.defineProperty(navigator, 'plugins', {
                get: () => [1, 2, 3, 4, 5],
            });
            // Fake languages
            Object.defineProperty(navigator, 'languages', {
                get: () => ['en-US', 'en'],
            });
        """)

        self._page = await self._context.new_page()
        logger.info("Browser launched (headless=%s)", self.headless)

    async def close(self) -> None:
        """Clean shutdown of browser, context, and playwright."""
        try:
            if self._context:
                await self._context.close()
            if self._browser:
                await self._browser.close()
            if self._playwright:
                await self._playwright.stop()
        except Exception as exc:
            logger.debug("Browser shutdown error (non-fatal): %s", exc)
        finally:
            self._page = None
            self._context = None
            self._browser = None
            self._playwright = None

    async def __aenter__(self) -> BrowserRuntime:
        await self.launch()
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    # ── Navigation ───────────────────────────────────────────────────

    async def navigate(
        self,
        url: str,
        wait_strategy: str = "smart",
    ) -> None:
        """
        Navigate to *url* with SPA-aware waiting.

        Strategies
        ----------
        smart (default)
            Wait for domcontentloaded, then attempt networkidle with
            a short timeout. If networkidle never fires (SPAs keep
            connections open), fall through after 5 seconds. Always
            adds a 1.5 s buffer for late JS execution.

        content
            Wait for domcontentloaded only, plus 2 s buffer.

        full
            Wait for full networkidle (blocks until network is truly
            idle). Use for traditional server-rendered pages.
        """
        page = await self.get_page()

        if wait_strategy == "full":
            await page.goto(url, wait_until="networkidle", timeout=self.timeout)
            return

        # Navigate, wait for initial DOM
        await page.goto(url, wait_until="domcontentloaded", timeout=self.timeout)

        if wait_strategy == "smart":
            # Try networkidle with short timeout -- SPAs often never reach it
            try:
                await page.wait_for_load_state("networkidle", timeout=5_000)
            except Exception:
                pass  # Expected for SPAs with persistent connections
            # Extra buffer for late JS rendering
            await page.wait_for_timeout(1_500)

        elif wait_strategy == "content":
            await page.wait_for_timeout(2_000)

    # ── Page / context access ────────────────────────────────────────

    async def get_page(self) -> Any:
        """Return the current page. Raises if browser not launched."""
        if self._page is None:
            raise RuntimeError("BrowserRuntime not launched. Call launch() first.")
        return self._page

    async def new_page(self) -> Any:
        """Open a new page in the existing context."""
        if self._context is None:
            raise RuntimeError("BrowserRuntime not launched.")
        return await self._context.new_page()

    async def new_context(
        self,
        cookies: Optional[list[dict[str, str]]] = None,
    ) -> Any:
        """
        Create an isolated browser context (e.g. for multi-user IDOR testing).

        Optionally pre-load cookies into the new context.
        """
        if self._browser is None:
            raise RuntimeError("BrowserRuntime not launched.")

        ctx = await self._browser.new_context(
            viewport={"width": 1920, "height": 1080},
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/125.0.0.0 Safari/537.36"
            ),
            ignore_https_errors=True,
        )
        if cookies:
            await ctx.add_cookies(cookies)
        return ctx

    # ── Cookie helpers ───────────────────────────────────────────────

    async def set_cookies(self, cookies: list[dict[str, str]]) -> None:
        """Inject cookies into the current browser context."""
        if self._context:
            await self._context.add_cookies(cookies)

    async def get_cookies(self) -> list[dict]:
        """Return all cookies from the current context."""
        if self._context:
            return await self._context.cookies()
        return []

    async def set_cookies_from_string(self, cookie_str: str, domain: str) -> None:
        """
        Parse a 'key=val; key2=val2' cookie string and inject them.

        Convenience wrapper for CLI --auth 'Cookie: ...' flows.
        """
        cookies: list[dict[str, str]] = []
        for pair in cookie_str.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=", 1)
                cookies.append({
                    "name": k.strip(),
                    "value": v.strip(),
                    "domain": domain,
                    "path": "/",
                })
        if cookies:
            await self.set_cookies(cookies)

    # ── Utility ──────────────────────────────────────────────────────

    async def screenshot(self, path: str) -> str:
        """Take full-page screenshot. Returns the path."""
        page = await self.get_page()
        await page.screenshot(path=path, full_page=True)
        return path

    async def current_url(self) -> str:
        page = await self.get_page()
        return page.url

    async def page_content(self) -> str:
        page = await self.get_page()
        return await page.content()
