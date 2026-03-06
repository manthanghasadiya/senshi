"""
Browser auth handler — handle login flows via Playwright.

Supports form-based login, OAuth redirects, and cookie/token extraction.
"""

from __future__ import annotations

from typing import Any

from senshi.utils.logger import get_logger

logger = get_logger("senshi.browser.auth_handler")


class BrowserAuthHandler:
    """Handle browser-based authentication flows."""

    def __init__(self, headless: bool = True) -> None:
        self.headless = headless
        self._playwright = None
        self._browser = None

    async def start(self) -> None:
        from playwright.async_api import async_playwright
        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(headless=self.headless)

    async def stop(self) -> None:
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()

    async def login_with_form(
        self, url: str, username: str, password: str,
        username_selector: str = "input[name='username'], input[type='email'], #username, #email",
        password_selector: str = "input[name='password'], input[type='password'], #password",
        submit_selector: str = "button[type='submit'], input[type='submit']",
    ) -> dict[str, Any]:
        """
        Login via form submission and extract cookies/tokens.

        Returns:
            {"cookies": [...], "token": str, "success": bool}
        """
        if not self._browser:
            await self.start()

        context = await self._browser.new_context()
        page = await context.new_page()

        try:
            await page.goto(url, timeout=15000)
            await page.wait_for_timeout(1000)

            # Fill username
            username_el = await page.query_selector(username_selector)
            if username_el:
                await username_el.fill(username)

            # Fill password
            password_el = await page.query_selector(password_selector)
            if password_el:
                await password_el.fill(password)

            # Submit
            submit_el = await page.query_selector(submit_selector)
            if submit_el:
                await submit_el.click()
                await page.wait_for_timeout(3000)

            # Extract cookies
            cookies = await context.cookies()

            # Extract tokens from localStorage/sessionStorage
            token = await self._extract_token(page)

            success = len(cookies) > 0 or bool(token)

            return {
                "cookies": cookies,
                "token": token,
                "success": success,
                "final_url": page.url,
            }

        except Exception as e:
            logger.warning(f"Login failed: {e}")
            return {"cookies": [], "token": "", "success": False}
        finally:
            await context.close()

    async def login_with_oauth(self, url: str) -> dict[str, Any]:
        """
        Handle OAuth redirect flow. Opens browser, waits for redirect back.

        Returns extracted cookies and tokens.
        """
        if not self._browser:
            await self.start()

        context = await self._browser.new_context()
        page = await context.new_page()

        try:
            await page.goto(url, timeout=30000)
            # Wait for redirect to complete (up to 30s)
            await page.wait_for_load_state("networkidle", timeout=30000)

            cookies = await context.cookies()
            token = await self._extract_token(page)

            return {
                "cookies": cookies,
                "token": token,
                "success": len(cookies) > 0,
                "final_url": page.url,
            }
        except Exception as e:
            logger.warning(f"OAuth login failed: {e}")
            return {"cookies": [], "token": "", "success": False}
        finally:
            await context.close()

    async def extract_cookies_from_page(self, url: str,
                                         existing_cookies: list[dict] | None = None) -> list[dict]:
        """Visit a URL and extract all cookies."""
        if not self._browser:
            await self.start()

        context = await self._browser.new_context()
        if existing_cookies:
            await context.add_cookies(existing_cookies)

        page = await context.new_page()
        try:
            await page.goto(url, timeout=10000)
            return await context.cookies()
        finally:
            await context.close()

    async def _extract_token(self, page: Any) -> str:
        """Extract auth token from localStorage or sessionStorage."""
        token_keys = ["token", "access_token", "accessToken", "auth_token",
                       "jwt", "id_token", "session_token"]

        for storage in ["localStorage", "sessionStorage"]:
            for key in token_keys:
                try:
                    value = await page.evaluate(f"{storage}.getItem('{key}')")
                    if value:
                        return str(value)
                except Exception:
                    continue
        return ""
