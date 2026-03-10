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
        """Synchronous login that properly handles cookies."""
        logger.info(f"Attempting automated login at: {self.login_url}")
        
        try:
            # Step 1: GET login page - Capture cookies automatically via client cookie jar
            resp = client.get(self.login_url)
            
            # Log initial cookies
            if client.cookies:
                logger.info(f"Got cookies from GET: {list(dict(client.cookies).keys())}")
            
            # Step 2: Parse form
            self.form = self.parser.parse(resp.text, self.login_url)
            if not self.form:
                logger.error(f"Could not find login form on {self.login_url}")
                return None
            
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
                resp = client.post(self.form.action, data=data, follow_redirects=True)
            else:
                resp = client.get(self.form.action, params=data, follow_redirects=True)
            
            # Step 5: Check if login worked
            # If we are still on login.php, it probably failed
            if "login.php" in str(resp.url) and resp.status_code == 200:
                logger.warning("Login might have failed - still on login page")
            
            # Step 6: Extract all cookies from the client's cookie jar
            cookies = dict(client.cookies)
            if cookies:
                # Add security=low for DVWA if not present
                if "security" not in cookies:
                    cookies["security"] = "low"
                
                self.session_cookie = "; ".join(f"{k}={v}" for k, v in cookies.items())
                logger.info(f"Login successful! Final cookies: {list(cookies.keys())}")
                return self.session_cookie
            
            return None
                
        except Exception as e:
            logger.error(f"Login failed: {e}")
            return None

    async def login(self, client: httpx.AsyncClient) -> str | None:
        """Async version of automated login."""
        logger.info(f"Attempting automated login at: {self.login_url}")
        
        try:
            # Step 1: GET login page
            resp = await client.get(self.login_url)
            
            if client.cookies:
                logger.info(f"Got cookies from GET: {list(dict(client.cookies).keys())}")
            
            # Step 2: Parse form
            self.form = self.parser.parse(resp.text, self.login_url)
            if not self.form:
                return None
            
            # Step 3: Build POST data
            data = {}
            if self.form.username_field:
                data[self.form.username_field] = self.username
            if self.form.password_field:
                data[self.form.password_field] = self.password
            data.update(self.form.hidden_fields)
            
            if self.form.submit_field:
                data[self.form.submit_field[0]] = self.form.submit_field[1]
            
            # Step 4: Submit login
            if self.form.method == "POST":
                resp = await client.post(self.form.action, data=data, follow_redirects=True)
            else:
                resp = await client.get(self.form.action, params=data, follow_redirects=True)
            
            # Step 5: Extract cookies
            cookies = dict(client.cookies)
            if cookies:
                if "security" not in cookies:
                    cookies["security"] = "low"
                self.session_cookie = "; ".join(f"{k}={v}" for k, v in cookies.items())
                return self.session_cookie
            
            return None
        except Exception as e:
            logger.error(f"Async login failed: {e}")
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
