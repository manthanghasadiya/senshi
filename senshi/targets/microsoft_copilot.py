"""
Microsoft Copilot target configuration — Copilot-specific API mapping + auth config.
"""

from __future__ import annotations

from typing import Any

from senshi.targets.generic import GenericTarget


class MicrosoftCopilotTarget(GenericTarget):
    """Microsoft Copilot-specific target configuration."""

    def __init__(self, url: str = "https://copilot.microsoft.com", **kwargs: Any) -> None:
        super().__init__(url, **kwargs)
        self.name = "Microsoft Copilot"
        self.modules = kwargs.get("modules", [
            "xss", "ssrf", "idor", "auth", "ai_product",
        ])
        self.rate_limit = kwargs.get("rate_limit", 2.0)

        # Copilot-specific endpoints
        self.api_endpoints = [
            "/api/create",
            "/api/turn",
            "/api/conversations",
            "/api/Sydney/ChatHub",
        ]

    def get_config(self) -> dict[str, Any]:
        config = super().get_config()
        config["api_endpoints"] = self.api_endpoints
        config["app_description"] = (
            "Microsoft Copilot — AI assistant powered by LLMs. "
            "Uses real-time conversation API with WebSocket connections. "
            "Handles multi-turn conversations, image generation, and search."
        )
        return config
