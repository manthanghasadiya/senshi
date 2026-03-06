"""
AuthManager — multi-account authentication management.

Handles cookie, bearer, and browser-based auth. Supports multi-account
testing for IDOR (Account A accessing Account B's resources).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from senshi.core.session import Session
from senshi.utils.logger import get_logger

logger = get_logger("senshi.auth.manager")


@dataclass
class AuthState:
    """Authentication state for a single account."""

    name: str
    type: str  # "cookie", "bearer", "browser"
    cookies: dict[str, str] = field(default_factory=dict)
    token: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    login_url: str = ""
    credentials: dict[str, str] = field(default_factory=dict)

    @property
    def cookie_string(self) -> str:
        return "; ".join(f"{k}={v}" for k, v in self.cookies.items())


class AuthManager:
    """
    Manage authentication for multiple accounts.

    Supports:
    - Cookie-based auth (parse raw Cookie header)
    - Bearer token auth
    - Browser-based auth (Playwright login flows)
    - Account switching for IDOR testing
    """

    def __init__(self) -> None:
        self.accounts: dict[str, AuthState] = {}
        self.active_account: str = "primary"

    def add_cookie_auth(self, name: str, cookies: str) -> None:
        """Add cookie-based authentication from raw Cookie header value."""
        parsed: dict[str, str] = {}
        for pair in cookies.split(";"):
            pair = pair.strip()
            if "=" in pair:
                key, _, value = pair.partition("=")
                parsed[key.strip()] = value.strip()

        self.accounts[name] = AuthState(
            name=name,
            type="cookie",
            cookies=parsed,
            headers={"Cookie": cookies},
        )
        logger.debug(f"Added cookie auth: {name} ({len(parsed)} cookies)")

    def add_bearer_auth(self, name: str, token: str) -> None:
        """Add Bearer token authentication."""
        self.accounts[name] = AuthState(
            name=name,
            type="bearer",
            token=token,
            headers={"Authorization": f"Bearer {token}"},
        )
        logger.debug(f"Added bearer auth: {name}")

    def add_raw_header_auth(self, name: str, header_str: str) -> None:
        """Add auth from raw header string (e.g., 'Cookie: abc=123')."""
        if ":" in header_str:
            key, _, value = header_str.partition(":")
            key, value = key.strip(), value.strip()

            if key.lower() == "cookie":
                self.add_cookie_auth(name, value)
            elif key.lower() == "authorization":
                if value.lower().startswith("bearer "):
                    self.add_bearer_auth(name, value[7:])
                else:
                    self.accounts[name] = AuthState(
                        name=name, type="bearer",
                        headers={key: value},
                    )
            else:
                self.accounts[name] = AuthState(
                    name=name, type="cookie",
                    headers={key: value},
                )

    def add_browser_auth(self, name: str, login_url: str,
                         username: str, password: str) -> None:
        """Add browser-based auth (login via Playwright)."""
        self.accounts[name] = AuthState(
            name=name,
            type="browser",
            login_url=login_url,
            credentials={"username": username, "password": password},
        )

    def get_headers(self, account: str | None = None) -> dict[str, str]:
        """Get auth headers for a specific account."""
        acc = self.accounts.get(account or self.active_account)
        if not acc:
            return {}
        return dict(acc.headers)

    def get_session(self, account: str | None = None,
                    base_url: str = "", **kwargs: Any) -> Session:
        """Get a configured Session for a specific account."""
        headers = self.get_headers(account)
        acc = self.accounts.get(account or self.active_account)

        auth_str = ""
        if acc:
            if acc.type == "cookie":
                auth_str = f"Cookie: {acc.cookie_string}"
            elif acc.type == "bearer":
                auth_str = f"Bearer {acc.token}"

        return Session(
            base_url=base_url,
            auth=auth_str,
            headers=headers,
            **kwargs,
        )

    def switch_account(self, name: str) -> None:
        """Switch the active account (for IDOR testing)."""
        if name in self.accounts:
            self.active_account = name
            logger.debug(f"Switched to account: {name}")
        else:
            logger.warning(f"Account not found: {name}")

    @property
    def has_multi_account(self) -> bool:
        """Check if we have multiple accounts for IDOR testing."""
        return len(self.accounts) >= 2

    def get_account_names(self) -> list[str]:
        return list(self.accounts.keys())
