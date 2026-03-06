"""
Brain — Universal LLM interface for Senshi.

Supports: DeepSeek, OpenAI, Groq, Ollama, Anthropic
All calls return structured JSON via schema enforcement.
Handles: retries, rate limiting, fallback providers, token counting.

All providers use OpenAI-compatible API format via raw httpx — no SDK dependencies.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncIterator, Iterator
from typing import Any

import httpx

from senshi.core.config import PROVIDER_DEFAULTS, SenshiConfig
from senshi.utils.logger import get_logger
from senshi.utils.rate_limiter import RateLimiter

logger = get_logger("senshi.ai.brain")


class BrainError(Exception):
    """Error from Brain LLM interface."""


class Brain:
    """
    Universal LLM interface — ALL LLM calls in Senshi go through Brain.

    Supports DeepSeek, OpenAI, Groq, Ollama, and Anthropic.
    All use OpenAI-compatible chat completions format.
    """

    def __init__(
        self,
        provider: str = "",
        model: str | None = None,
        api_key: str | None = None,
        config: SenshiConfig | None = None,
    ) -> None:
        self.config = config or SenshiConfig.load()

        # Override with explicit args
        self.provider = provider or self.config.provider
        if not self.provider:
            raise BrainError(
                "No LLM provider configured. Set via --provider flag, "
                "environment variable, or 'senshi config'."
            )

        defaults = PROVIDER_DEFAULTS.get(self.provider, {})
        self.model = model or self.config.model or defaults.get("model", "")
        self.api_key = api_key or self.config.api_key
        self.base_url = self.config.base_url or defaults.get("base_url", "")

        # Validate API key requirement
        if self.provider != "ollama" and not self.api_key:
            env_key = defaults.get("env_key", "")
            raise BrainError(
                f"No API key for {self.provider}. "
                f"Set {env_key} env var or run 'senshi config --provider {self.provider} --api-key YOUR_KEY'."
            )

        # Rate limiter for API calls
        self._rate_limiter = RateLimiter(requests_per_second=5.0, burst=10)

        # Stats
        self.total_calls = 0
        self.total_tokens = 0

        logger.debug(f"Brain initialized: provider={self.provider}, model={self.model}")

    def _build_headers(self) -> dict[str, str]:
        """Build request headers for the API call."""
        headers = {
            "Content-Type": "application/json",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _build_payload(
        self,
        system_prompt: str,
        user_prompt: str,
        json_schema: dict[str, Any] | None = None,
        temperature: float = 0.1,
    ) -> dict[str, Any]:
        """Build the request payload in OpenAI-compatible format."""
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
        }

        # Request JSON output when schema provided
        if json_schema:
            payload["response_format"] = {"type": "json_object"}

        return payload

    def _parse_response(self, response_data: dict[str, Any]) -> str:
        """Extract the response text from API response."""
        try:
            choices = response_data.get("choices", [])
            if not choices:
                raise BrainError("No choices in API response")

            message = choices[0].get("message", {})
            content = message.get("content", "")

            # Track tokens
            usage = response_data.get("usage", {})
            self.total_tokens += usage.get("total_tokens", 0)

            return content
        except (KeyError, IndexError) as e:
            raise BrainError(f"Failed to parse API response: {e}") from e

    def _parse_json_response(self, text: str) -> dict[str, Any]:
        """Parse JSON from LLM response, handling markdown code blocks."""
        text = text.strip()

        # Strip markdown code blocks if present
        if text.startswith("```"):
            lines = text.split("\n")
            # Remove first and last lines (``` markers)
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            text = "\n".join(lines)

        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            # Try to find JSON object in the response
            start = text.find("{")
            end = text.rfind("}") + 1
            if start != -1 and end > start:
                try:
                    return json.loads(text[start:end])
                except json.JSONDecodeError:
                    pass
            raise BrainError(f"Failed to parse JSON from LLM response: {e}") from e

    def think(
        self,
        system_prompt: str,
        user_prompt: str,
        json_schema: dict[str, Any] | None = None,
        temperature: float = 0.1,
        max_retries: int = 3,
    ) -> dict[str, Any] | str:
        """
        Core method. Send a prompt, get a response.

        If json_schema provided, enforce structured JSON output.
        Handles retries (3x), rate limit backoff, and JSON parsing.

        Args:
            system_prompt: System prompt defining the AI's role.
            user_prompt: User prompt with the specific task.
            json_schema: If provided, request JSON output and parse it.
            temperature: LLM temperature (lower = more deterministic).
            max_retries: Number of retries on failure.

        Returns:
            Parsed JSON dict if json_schema provided, raw string otherwise.
        """
        self._rate_limiter.wait()

        url = f"{self.base_url}/chat/completions"
        headers = self._build_headers()
        payload = self._build_payload(system_prompt, user_prompt, json_schema, temperature)

        last_error: Exception | None = None

        for attempt in range(max_retries):
            try:
                with httpx.Client(timeout=60.0) as client:
                    response = client.post(url, headers=headers, json=payload)

                    if response.status_code == 429:
                        # Rate limited — backoff
                        wait_time = 2 ** (attempt + 1)
                        logger.warning(f"Rate limited, waiting {wait_time}s...")
                        time.sleep(wait_time)
                        continue

                    response.raise_for_status()
                    response_data = response.json()

                self.total_calls += 1
                content = self._parse_response(response_data)

                if json_schema:
                    return self._parse_json_response(content)
                return content

            except httpx.HTTPStatusError as e:
                last_error = e
                logger.warning(
                    f"API error (attempt {attempt + 1}/{max_retries}): "
                    f"{e.response.status_code} — {e.response.text[:200]}"
                )
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)

            except (httpx.RequestError, BrainError) as e:
                last_error = e
                logger.warning(f"Request error (attempt {attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)

        raise BrainError(f"All {max_retries} attempts failed. Last error: {last_error}")

    async def async_think(
        self,
        system_prompt: str,
        user_prompt: str,
        json_schema: dict[str, Any] | None = None,
        temperature: float = 0.1,
        max_retries: int = 3,
    ) -> dict[str, Any] | str:
        """Async version of think()."""
        await self._rate_limiter.async_wait()

        url = f"{self.base_url}/chat/completions"
        headers = self._build_headers()
        payload = self._build_payload(system_prompt, user_prompt, json_schema, temperature)

        last_error: Exception | None = None

        for attempt in range(max_retries):
            try:
                async with httpx.AsyncClient(timeout=60.0) as client:
                    response = await client.post(url, headers=headers, json=payload)

                    if response.status_code == 429:
                        wait_time = 2 ** (attempt + 1)
                        logger.warning(f"Rate limited, waiting {wait_time}s...")
                        await asyncio.sleep(wait_time)
                        continue

                    response.raise_for_status()
                    response_data = response.json()

                self.total_calls += 1
                content = self._parse_response(response_data)

                if json_schema:
                    return self._parse_json_response(content)
                return content

            except httpx.HTTPStatusError as e:
                last_error = e
                logger.warning(f"API error (attempt {attempt + 1}/{max_retries}): {e.response.status_code}")
                if attempt < max_retries - 1:
                    await asyncio.sleep(2 ** attempt)

            except (httpx.RequestError, BrainError) as e:
                last_error = e
                logger.warning(f"Request error (attempt {attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    await asyncio.sleep(2 ** attempt)

        raise BrainError(f"All {max_retries} attempts failed. Last error: {last_error}")

    def think_streaming(
        self, system_prompt: str, user_prompt: str, temperature: float = 0.1
    ) -> Iterator[str]:
        """Stream response tokens for long outputs."""
        self._rate_limiter.wait()

        url = f"{self.base_url}/chat/completions"
        headers = self._build_headers()
        payload = self._build_payload(system_prompt, user_prompt, temperature=temperature)
        payload["stream"] = True

        with httpx.Client(timeout=120.0) as client:
            with client.stream("POST", url, headers=headers, json=payload) as response:
                response.raise_for_status()
                self.total_calls += 1

                for line in response.iter_lines():
                    if line.startswith("data: "):
                        data_str = line[6:]
                        if data_str.strip() == "[DONE]":
                            break
                        try:
                            data = json.loads(data_str)
                            delta = data["choices"][0].get("delta", {})
                            content = delta.get("content", "")
                            if content:
                                yield content
                        except (json.JSONDecodeError, KeyError, IndexError):
                            continue

    async def async_think_streaming(
        self, system_prompt: str, user_prompt: str, temperature: float = 0.1
    ) -> AsyncIterator[str]:
        """Async streaming version."""
        await self._rate_limiter.async_wait()

        url = f"{self.base_url}/chat/completions"
        headers = self._build_headers()
        payload = self._build_payload(system_prompt, user_prompt, temperature=temperature)
        payload["stream"] = True

        async with httpx.AsyncClient(timeout=120.0) as client:
            async with client.stream("POST", url, headers=headers, json=payload) as response:
                response.raise_for_status()
                self.total_calls += 1

                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data_str = line[6:]
                        if data_str.strip() == "[DONE]":
                            break
                        try:
                            data = json.loads(data_str)
                            delta = data["choices"][0].get("delta", {})
                            content = delta.get("content", "")
                            if content:
                                yield content
                        except (json.JSONDecodeError, KeyError, IndexError):
                            continue

    def batch_think(
        self,
        prompts: list[tuple[str, str]],
        json_schema: dict[str, Any] | None = None,
        temperature: float = 0.1,
        max_concurrent: int = 5,
    ) -> list[dict[str, Any] | str]:
        """
        Process multiple prompts concurrently.

        Used for SAST batch file analysis.

        Args:
            prompts: List of (system_prompt, user_prompt) tuples.
            json_schema: Optional JSON schema for structured output.
            temperature: LLM temperature.
            max_concurrent: Max concurrent API calls.

        Returns:
            List of responses in the same order as prompts.
        """
        return asyncio.run(
            self._async_batch_think(prompts, json_schema, temperature, max_concurrent)
        )

    async def _async_batch_think(
        self,
        prompts: list[tuple[str, str]],
        json_schema: dict[str, Any] | None = None,
        temperature: float = 0.1,
        max_concurrent: int = 5,
    ) -> list[dict[str, Any] | str]:
        """Internal async batch processing."""
        semaphore = asyncio.Semaphore(max_concurrent)
        results: list[dict[str, Any] | str | None] = [None] * len(prompts)

        async def process_one(idx: int, system: str, user: str) -> None:
            async with semaphore:
                try:
                    result = await self.async_think(system, user, json_schema, temperature)
                    results[idx] = result
                except BrainError as e:
                    logger.warning(f"Batch item {idx} failed: {e}")
                    results[idx] = {"error": str(e)} if json_schema else f"Error: {e}"

        tasks = [process_one(i, sys, usr) for i, (sys, usr) in enumerate(prompts)]
        await asyncio.gather(*tasks)

        return [r if r is not None else ("Error: no response" if not json_schema else {"error": "no response"}) for r in results]

    def get_stats(self) -> dict[str, Any]:
        """Return usage statistics."""
        return {
            "provider": self.provider,
            "model": self.model,
            "total_calls": self.total_calls,
            "total_tokens": self.total_tokens,
        }
