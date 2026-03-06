"""
WebSocket fuzzer — LLM-generated message payloads for WS endpoints.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from senshi.ai.brain import Brain
from senshi.reporters.models import Finding
from senshi.utils.logger import get_logger

logger = get_logger("senshi.websocket.fuzzer")

WS_FUZZ_PROMPT = """You are a security researcher fuzzing a WebSocket endpoint.

ENDPOINT: {ws_url}
SAMPLE MESSAGES (captured from normal usage):
{sample_messages}

Generate {count} malicious WebSocket messages to test for:
1. SQL injection in message fields
2. Command injection
3. Prototype pollution
4. Authorization bypass (accessing admin functions)
5. Cross-user data access
6. Path traversal in file-related messages
7. SSRF through URL fields in messages

OUTPUT FORMAT (strict JSON array):
[
  {{"message": "{{...}}", "technique": "description", "vuln_type": "sqli|cmdi|xss|auth|idor"}}
]
"""


class WebSocketFuzzer:
    """Generate and send LLM-crafted WebSocket payloads."""

    def __init__(self, brain: Brain, timeout: int = 10) -> None:
        self.brain = brain
        self.timeout = timeout

    async def generate_payloads(
        self, ws_url: str, sample_messages: list[str], count: int = 10
    ) -> list[dict[str, str]]:
        """Generate targeted WS payloads based on observed protocol."""
        prompt = WS_FUZZ_PROMPT.format(
            ws_url=ws_url,
            sample_messages=json.dumps(sample_messages[:5], indent=2),
            count=count,
        )

        result = await self.brain.async_think(
            system_prompt="You are a WebSocket security fuzzer.",
            user_prompt=prompt,
            json_schema={"type": "array"},
        )

        if isinstance(result, list):
            return result
        return []

    async def fuzz(
        self,
        ws_url: str,
        payloads: list[dict[str, str]],
        auth_headers: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Send payloads and collect responses."""
        try:
            import websockets
        except ImportError:
            logger.warning("websockets not installed")
            return []

        results = []
        for payload_info in payloads:
            message = payload_info.get("message", "")
            try:
                async with websockets.connect(
                    ws_url,
                    open_timeout=self.timeout,
                    extra_headers=auth_headers or {},
                ) as ws:
                    await ws.send(message)
                    response = await asyncio.wait_for(ws.recv(), timeout=self.timeout)
                    results.append({
                        "payload": message,
                        "technique": payload_info.get("technique", ""),
                        "vuln_type": payload_info.get("vuln_type", ""),
                        "response": str(response)[:2000],
                        "status": "ok",
                    })
            except Exception as e:
                results.append({
                    "payload": message,
                    "technique": payload_info.get("technique", ""),
                    "status": "error",
                    "error": str(e),
                })

        return results
