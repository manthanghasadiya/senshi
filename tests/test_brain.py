"""Tests for Brain LLM interface."""

from __future__ import annotations

import pytest

from senshi.ai.brain import Brain, BrainError
from senshi.core.config import SenshiConfig, PROVIDER_DEFAULTS


class TestBrainInit:
    """Test Brain initialization."""

    def test_provider_defaults_exist(self):
        """All expected providers have defaults."""
        expected = {"deepseek", "openai", "groq", "ollama", "anthropic"}
        assert expected == set(PROVIDER_DEFAULTS.keys())

    def test_no_provider_raises(self):
        """Brain raises error when no provider configured."""
        config = SenshiConfig(provider="", api_key="")
        with pytest.raises(BrainError, match="No LLM provider"):
            Brain(config=config)

    def test_no_api_key_raises(self):
        """Brain raises error when provider needs key but none set."""
        config = SenshiConfig(provider="deepseek", api_key="")
        with pytest.raises(BrainError, match="No API key"):
            Brain(config=config)

    def test_ollama_no_key_ok(self):
        """Ollama doesn't need an API key."""
        config = SenshiConfig(provider="ollama", api_key="")
        brain = Brain(config=config)
        assert brain.provider == "ollama"
        assert brain.model == "llama3.1"


class TestBrainHelpers:
    """Test Brain helper methods."""

    def test_build_headers_with_key(self):
        config = SenshiConfig(provider="ollama")
        brain = Brain(config=config)
        brain.api_key = "test-key"
        headers = brain._build_headers()
        assert headers["Authorization"] == "Bearer test-key"

    def test_build_payload(self):
        config = SenshiConfig(provider="ollama")
        brain = Brain(config=config)
        payload = brain._build_payload("system", "user")
        assert payload["model"] == "llama3.1"
        assert len(payload["messages"]) == 2
        assert payload["messages"][0]["role"] == "system"
        assert payload["messages"][1]["role"] == "user"

    def test_build_payload_with_json_schema(self):
        config = SenshiConfig(provider="ollama")
        brain = Brain(config=config)
        payload = brain._build_payload("system", "user", json_schema={"type": "object"})
        assert payload["response_format"] == {"type": "json_object"}

    def test_parse_json_response(self):
        config = SenshiConfig(provider="ollama")
        brain = Brain(config=config)
        result = brain._parse_json_response('{"key": "value"}')
        assert result == {"key": "value"}

    def test_parse_json_with_markdown(self):
        config = SenshiConfig(provider="ollama")
        brain = Brain(config=config)
        result = brain._parse_json_response('```json\n{"key": "value"}\n```')
        assert result == {"key": "value"}

    def test_parse_json_embedded(self):
        config = SenshiConfig(provider="ollama")
        brain = Brain(config=config)
        result = brain._parse_json_response('Here is the result: {"key": "value"}')
        assert result == {"key": "value"}
