"""
Action definitions and executor for the pentest agent.

Each action maps to a concrete operation — scanning, fuzzing,
browser testing, WebSocket probing, etc.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Callable, Awaitable

from senshi.agent.context import PentestContext
from senshi.reporters.models import Finding
from senshi.utils.logger import get_logger, console

logger = get_logger("senshi.agent.actions")


# ── Data models ──────────────────────────────────────────────

@dataclass
class Action:
    """An action the agent wants to perform."""

    type: str  # scan_endpoint, fuzz_parameter, test_auth, browser_test, etc.
    params: dict[str, Any] = field(default_factory=dict)
    reasoning: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Action:
        return cls(
            type=data.get("action", data.get("type", "done")),
            params=data.get("params", {}),
            reasoning=data.get("reasoning", ""),
        )


@dataclass
class ActionResult:
    """Result of executing an action."""

    success: bool = True
    observations: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    is_interesting: bool = False
    raw_data: dict[str, Any] = field(default_factory=dict)
    error: str = ""

    @property
    def summary(self) -> str:
        if self.error:
            return f"Error: {self.error}"
        if self.findings:
            return f"Found {len(self.findings)} potential vulnerabilities"
        if self.is_interesting:
            return "; ".join(self.observations[:3])
        return "No issues found"


# ── Available actions ────────────────────────────────────────

AVAILABLE_ACTIONS = {
    "scan_endpoint": {
        "description": "Test an endpoint for a specific vulnerability type",
        "params": {"endpoint": "URL to test", "vuln_type": "xss|sqli|ssrf|idor|auth|cmdi|ssti"},
    },
    "fuzz_parameter": {
        "description": "Fuzz a specific parameter with targeted payloads",
        "params": {"endpoint": "URL", "param": "parameter name", "payload_type": "injection|boundary|format"},
    },
    "test_auth": {
        "description": "Test authentication and authorization on an endpoint",
        "params": {"endpoint": "URL to test"},
    },
    "test_idor": {
        "description": "Test for IDOR by manipulating object IDs",
        "params": {"endpoint": "URL with ID", "id_param": "parameter or path segment with ID"},
    },
    "test_ssrf": {
        "description": "Test for SSRF with callback detection",
        "params": {"endpoint": "URL", "url_param": "parameter that accepts URLs"},
    },
    "browser_test": {
        "description": "Run Playwright browser test for client-side vulnerabilities",
        "params": {"url": "URL to visit", "test_type": "xss_confirm|csrf|auth_bypass|open_redirect"},
    },
    "websocket_test": {
        "description": "Test a WebSocket endpoint",
        "params": {"ws_url": "WebSocket URL", "test_type": "auth|injection|rate_limit"},
    },
    "explore_endpoint": {
        "description": "Send benign requests to discover more about an endpoint",
        "params": {"url": "URL to explore"},
    },
    "test_graphql": {
        "description": "Test a GraphQL endpoint via introspection and targeted queries",
        "params": {"endpoint": "GraphQL URL"},
    },
    "escalate": {
        "description": "Attempt to escalate a confirmed finding to higher impact",
        "params": {"finding_index": "index of finding to escalate"},
    },
    "done": {
        "description": "Finish testing — all high-value tests have been performed",
        "params": {},
    },
}


def get_actions_prompt() -> str:
    """Format available actions for the LLM prompt."""
    lines = ["AVAILABLE ACTIONS:"]
    for i, (name, info) in enumerate(AVAILABLE_ACTIONS.items(), 1):
        params_str = ", ".join(f"{k}={v}" for k, v in info["params"].items())
        lines.append(f"  {i}. {name}({params_str}) — {info['description']}")
    return "\n".join(lines)


class ActionExecutor:
    """
    Dispatches actions to the appropriate handler.

    Each handler is registered as an async callable. The agent loop
    registers handlers during setup based on available capabilities
    (e.g., browser handlers only if Playwright is available).
    """

    def __init__(self) -> None:
        self._handlers: dict[str, Callable[..., Awaitable[ActionResult]]] = {}

    def register(self, action_type: str,
                 handler: Callable[..., Awaitable[ActionResult]]) -> None:
        """Register a handler for an action type."""
        self._handlers[action_type] = handler

    async def execute(self, action: Action, context: PentestContext) -> ActionResult:
        """Execute an action and return the result."""
        if action.type == "done":
            return ActionResult(success=True, observations=["Agent decided to stop"])

        handler = self._handlers.get(action.type)
        if not handler:
            return ActionResult(
                success=False,
                error=f"Unknown action type: {action.type}",
            )

        console.print(
            f"    [dim]→ {action.type}({', '.join(f'{k}={v}' for k, v in action.params.items())})[/dim]"
        )

        try:
            result = await handler(action.params, context)
            context.iteration += 1
            return result
        except Exception as e:
            logger.warning(f"Action {action.type} failed: {e}")
            return ActionResult(success=False, error=str(e))
