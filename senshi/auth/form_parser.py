"""
Smart Login Form Parser.

Detects login fields (username, password, hidden/CSRF) based on hints,
input types, and common patterns.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urljoin

from bs4 import BeautifulSoup


@dataclass
class LoginForm:
    action: str  # Form action URL
    method: str  # GET or POST
    username_field: str | None
    password_field: str | None
    hidden_fields: dict[str, str]  # CSRF tokens, etc.
    submit_field: tuple[str, str] | None


class LoginFormParser:
    """Auto-detect login form fields."""

    USERNAME_HINTS = [
        "user", "username", "uname", "login", "email",
        "account", "uid", "userid", "member", "name", "identity"
    ]

    PASSWORD_HINTS = [
        "pass", "password", "pwd", "passwd", "secret",
        "credential", "key", "token", "auth"
    ]

    def parse(self, html: str, base_url: str) -> LoginForm | None:
        """Parse HTML and extract login form details."""
        soup = BeautifulSoup(html, "html.parser")

        # Find the login form (usually has password field)
        forms = soup.find_all("form")

        for form in forms:
            password_input = form.find("input", {"type": "password"})
            if not password_input:
                # Some forms use type="text" for password if custom JS is used, 
                # but standard forms use type="password"
                continue

            # Found a form with password field — this is likely login
            return self._parse_form(form, base_url)

        # Fallback: find any form with "login" or "signin" in action/id/class
        for form in forms:
            form_str = str(form).lower()
            if "login" in form_str or "signin" in form_str:
                return self._parse_form(form, base_url)

        return None

    def _parse_form(self, form, base_url: str) -> LoginForm:
        """Extract all fields from a form."""

        # Get form action
        action = form.get("action", "")
        if not action or action == "#":
            action = base_url
        elif not action.startswith("http"):
            # Relative URL
            action = urljoin(base_url, action)

        method = form.get("method", "POST").upper()

        username_field = None
        password_field = None
        hidden_fields = {}
        submit_field = None

        for inp in form.find_all("input"):
            input_type = inp.get("type", "text").lower()
            input_name = inp.get("name", inp.get("id", ""))
            input_value = inp.get("value", "")

            if not input_name:
                continue

            # Password field
            if input_type == "password":
                password_field = input_name

            # Hidden fields (CSRF, etc.)
            elif input_type == "hidden":
                hidden_fields[input_name] = input_value

            # Submit button
            elif input_type == "submit":
                if input_name:
                    submit_field = (input_name, input_value or "Submit")
            
            # Button element as submit
            elif input_type == "button":
                pass # Usually not the main submit in standard HTML forms

            # Text/email field — check if it's username
            elif input_type in ("text", "email"):
                if self._is_username_field(input_name):
                    username_field = input_name

        # Final check for password field if not found by type
        if not password_field:
            for inp in form.find_all("input"):
                name = inp.get("name", "").lower()
                if any(hint in name for hint in self.PASSWORD_HINTS):
                    password_field = inp.get("name")
                    break

        # If no username found by hints, take first text field
        if not username_field:
            text_input = form.find("input", {"type": ["text", "email"]})
            if text_input:
                username_field = text_input.get("name")

        return LoginForm(
            action=action,
            method=method,
            username_field=username_field,
            password_field=password_field,
            hidden_fields=hidden_fields,
            submit_field=submit_field,
        )

    def _is_username_field(self, name: str) -> bool:
        """Check if field name looks like username."""
        name_lower = str(name).lower()
        return any(hint in name_lower for hint in self.USERNAME_HINTS)
