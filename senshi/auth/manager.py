"""
AuthManager — automated and manual authentication management.

Handles automated login via form parsing, cookie extraction,
and session persistence.
"""

from __future__ import annotations

import httpx
from typing import Any
from urllib.parse import urlparse

from senshi.auth.form_parser import LoginFormParser, LoginForm
from senshi.utils.logger import get_logger

logger = get_logger("senshi.auth.manager")


class AuthManager:
    """
    Manage authentication flows.
    
    Supports:
    - Automated login form detection
    - CSRF token extraction
    - Session cookie persistence
    - Re-authentication on session death
    """
    
    def __init__(
        self,
        login_url: str,
        username: str,
        password: str,
    ):
        self.login_url = login_url
        self.username = username
        self.password = password
        self.parser = LoginFormParser()
        self.form: LoginForm | None = None
        self.session_cookie: str | None = None
    
    def login_sync(self, client: httpx.Client) -> str | None:
        """Synchronous wrapper for login."""
        import asyncio
        try:
            # Try to use current loop if exists, else run new
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # This is tricky if already running, but since engine.py is usually 
                # called from sync CLI, we can often just run it.
                # If we are in an async loop already (e.g. from agent), we should use await.
                # But ScanEngine is sync.
                import nest_asyncio
                nest_asyncio.apply()
                return loop.run_until_complete(self.login(client))
            else:
                return loop.run_until_complete(self.login(client))
        except RuntimeError:
            return asyncio.run(self.login(client))

    async def login(self, client: httpx.AsyncClient | httpx.Client) -> str | None:
        """Auto-detect form and login."""
        logger.info(f"Attempting automated login at: {self.login_url}")
        
        try:
            # Step 1: Fetch login page
            if isinstance(client, httpx.AsyncClient):
                resp = await client.get(self.login_url)
            else:
                resp = client.get(self.login_url)
            
            # Step 2: Parse form
            self.form = self.parser.parse(resp.text, self.login_url)
            
            if not self.form:
                logger.error(f"Could not find login form on {self.login_url}")
                return None
            
            logger.info("Detected login form:")
            logger.info(f"  Action: {self.form.action}")
            logger.info(f"  Username field: {self.form.username_field}")
            logger.info(f"  Password field: {self.form.password_field}")
            if self.form.hidden_fields:
                logger.info(f"  Hidden fields: {list(self.form.hidden_fields.keys())}")
            
            # Step 3: Build POST data
            data = {}
            if self.form.username_field:
                data[self.form.username_field] = self.username
            if self.form.password_field:
                data[self.form.password_field] = self.password
            
            # Add hidden fields (CSRF, etc.)
            data.update(self.form.hidden_fields)
            
            # Add submit button if present
            if self.form.submit_field:
                data[self.form.submit_field[0]] = self.form.submit_field[1]
            
            # Step 4: Submit login
            logger.info(f"Performing {self.form.method} login...")
            if self.form.method == "POST":
                if isinstance(client, httpx.AsyncClient):
                    resp = await client.post(self.form.action, data=data)
                else:
                    resp = client.post(self.form.action, data=data)
            else:
                if isinstance(client, httpx.AsyncClient):
                    resp = await client.get(self.form.action, params=data)
                else:
                    resp = client.get(self.form.action, params=data)
            
            # Step 5: Extract session cookie
            self.session_cookie = self._extract_session(resp)
            if self.session_cookie:
                logger.info("Login successful!")
                return self.session_cookie
            else:
                logger.warning("Login completed but no session cookie found.")
                return None
                
        except Exception as e:
            logger.error(f"Login failed: {e}")
            return None
    
    def _extract_session(self, resp: Any) -> str | None:
        """Extract session cookie from response."""
        cookies = []
        
        # httpx response has a .cookies attribute (CookieJar)
        for name, value in resp.cookies.items():
            cookies.append(f"{name}={value}")
        
        # Common session cookie names to prioritize
        session_names = ["phpsessid", "jsessionid", "sessionid", "session", "sid", "token", "auth"]
        
        found_cookies = []
        for cookie in cookies:
            name = cookie.split("=")[0].lower()
            if any(s in name for s in session_names):
                logger.info(f"Found potential session cookie: {cookie.split('=')[0]}")
                found_cookies.append(cookie)
        
        if found_cookies:
            # Join multiple if found (e.g. security=low; PHPSESSID=...)
            return "; ".join(found_cookies)
            
        # Return all cookies if no specific session found but some exist
        if cookies:
            logger.debug(f"Using all found cookies: {'; '.join(cookies)}")
            return "; ".join(cookies)
        
        return None
