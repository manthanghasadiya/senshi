"""Senshi targets — target-specific configurations."""

from __future__ import annotations

from typing import Any

# Registry of target profiles
_PROFILES: dict[str, dict[str, Any]] = {}


def register_profile(name: str, profile: dict[str, Any]) -> None:
    """Register a target profile."""
    _PROFILES[name.lower()] = profile


def get_profile(name: str) -> dict[str, Any] | None:
    """Get a target profile by name."""
    profile = _PROFILES.get(name.lower())
    if profile:
        return profile

    # Lazy-load built-in profiles
    try:
        if name.lower() in ("copilot", "microsoft_copilot"):
            from senshi.targets.microsoft_copilot import PROFILE
            return PROFILE
        elif name.lower() in ("openai", "chatgpt"):
            from senshi.targets.openai_chatgpt import PROFILE
            return PROFILE
        elif name.lower() in ("salesforce", "agentforce"):
            from senshi.targets.salesforce import PROFILE
            return PROFILE
    except ImportError:
        pass

    return None


def list_profiles() -> list[str]:
    """List all available profile names."""
    built_in = ["copilot", "openai", "salesforce"]
    return sorted(set(built_in + list(_PROFILES.keys())))
