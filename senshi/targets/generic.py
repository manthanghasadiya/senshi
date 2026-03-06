"""
Generic target configuration — default config for any web application.
"""

from __future__ import annotations

from typing import Any


class GenericTarget:
    """Generic web app target configuration."""

    def __init__(self, url: str, **kwargs: Any) -> None:
        self.url = url
        self.name = kwargs.get("name", "Generic Web Application")
        self.modules = kwargs.get("modules", [
            "xss", "ssrf", "idor", "injection", "auth",
            "deserialization", "ai_product",
        ])
        self.rate_limit = kwargs.get("rate_limit", 1.0)
        self.max_payloads = kwargs.get("max_payloads", 15)

    def get_config(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "name": self.name,
            "modules": self.modules,
            "rate_limit": self.rate_limit,
            "max_payloads": self.max_payloads,
        }
