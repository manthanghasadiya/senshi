"""
Senshi global configuration — API keys, proxy, rate limits, defaults.

Config is loaded from (in priority order):
1. CLI arguments
2. Environment variables
3. Config file (~/.senshi/config.json)
4. Built-in defaults
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

CONFIG_DIR = Path.home() / ".senshi"
CONFIG_FILE = CONFIG_DIR / "config.json"


# Provider → (base_url, default_model, env_var_for_key)
PROVIDER_DEFAULTS: dict[str, dict[str, str]] = {
    "deepseek": {
        "base_url": "https://api.deepseek.com/v1",
        "model": "deepseek-chat",
        "env_key": "DEEPSEEK_API_KEY",
    },
    "openai": {
        "base_url": "https://api.openai.com/v1",
        "model": "gpt-4o-mini",
        "env_key": "OPENAI_API_KEY",
    },
    "groq": {
        "base_url": "https://api.groq.com/openai/v1",
        "model": "llama-3.3-70b-versatile",
        "env_key": "GROQ_API_KEY",
    },
    "ollama": {
        "base_url": "http://localhost:11434/v1",
        "model": "llama3.1",
        "env_key": "",
    },
    "anthropic": {
        "base_url": "https://api.anthropic.com/v1",
        "model": "claude-3-5-sonnet-20241022",
        "env_key": "ANTHROPIC_API_KEY",
    },
}


@dataclass
class SenshiConfig:
    """Global configuration for Senshi."""

    # LLM settings
    provider: str = ""
    model: str = ""
    api_key: str = ""
    base_url: str = ""

    # Scanning defaults
    rate_limit: float = 1.0
    max_payloads: int = 15
    timeout: float = 10.0

    # Proxy (Burp integration)
    proxy: str = ""

    # Output
    verbose: bool = False
    output: str = ""

    # Auth
    auth: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    
    # Auto-Auth
    login_url: str = ""
    username: str = ""
    password: str = ""

    def __post_init__(self) -> None:
        """Auto-detect provider from env vars if not set."""
        if not self.provider:
            self.provider = self._detect_provider()

        if self.provider and not self.base_url:
            defaults = PROVIDER_DEFAULTS.get(self.provider, {})
            self.base_url = defaults.get("base_url", "")

        if self.provider and not self.model:
            defaults = PROVIDER_DEFAULTS.get(self.provider, {})
            self.model = defaults.get("model", "")

        if not self.api_key:
            self.api_key = self._detect_api_key()

    def _detect_provider(self) -> str:
        """Auto-detect provider from available API keys."""
        for provider_name, defaults in PROVIDER_DEFAULTS.items():
            env_key = defaults.get("env_key", "")
            if env_key and os.environ.get(env_key):
                return provider_name
        return ""

    def _detect_api_key(self) -> str:
        """Get API key from environment for current provider."""
        if not self.provider:
            return ""
        defaults = PROVIDER_DEFAULTS.get(self.provider, {})
        env_key = defaults.get("env_key", "")
        if env_key:
            return os.environ.get(env_key, "")
        return ""

    def save(self) -> None:
        """Save config to disk."""
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        data = {
            "provider": self.provider,
            "model": self.model,
            "api_key": self.api_key,
            "base_url": self.base_url,
            "rate_limit": self.rate_limit,
            "max_payloads": self.max_payloads,
            "timeout": self.timeout,
            "proxy": self.proxy,
            "login_url": self.login_url,
            "username": self.username,
        }
        CONFIG_FILE.write_text(json.dumps(data, indent=2))

    @classmethod
    def load(cls) -> SenshiConfig:
        """Load config from disk and environment."""
        config = cls()

        # Load from file
        if CONFIG_FILE.exists():
            try:
                data = json.loads(CONFIG_FILE.read_text())
                for key, value in data.items():
                    if hasattr(config, key) and value:
                        setattr(config, key, value)
            except (json.JSONDecodeError, OSError):
                pass

        # Re-run auto-detect after loading
        config.__post_init__()
        return config

    def show(self) -> dict[str, Any]:
        """Return displayable config (API key masked)."""
        masked_key = ""
        if self.api_key:
            masked_key = self.api_key[:8] + "..." + self.api_key[-4:] if len(self.api_key) > 12 else "****"

        return {
            "provider": self.provider or "(auto-detect)",
            "model": self.model or "(default)",
            "api_key": masked_key or "(not set)",
            "base_url": self.base_url or "(auto)",
            "proxy": self.proxy or "(none)",
            "rate_limit": self.rate_limit,
            "max_payloads": self.max_payloads,
            "timeout": self.timeout,
            "login_url": self.login_url or "(none)",
        }
