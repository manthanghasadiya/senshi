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


VULN_TYPE_ALIASES = {
    "sqli": "injection",
    "sql_injection": "injection", 
    "sql": "injection",
    "cmdi": "injection",
    "command_injection": "injection",
    "rce": "injection",
    "xss": "xss",
    "ssrf": "ssrf",
    "idor": "idor",
    "auth": "auth",
    "auth_bypass": "auth",
    "deserialization": "deserialization",
    "open_redirect": "xss",
    "ssti": "injection",
}


# ── Data models ──────────────────────────────────────────────

@dataclass
class Action:
    """An action the agent wants to perform."""

    type: str  # scan_endpoint, fuzz_parameter, test_auth, browser_test, etc.
    params: dict[str, Any] = field(default_factory=dict)
    reasoning: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Action:
        params = data.get("params", {})
        if "vuln_type" in params:
            params["vuln_type"] = VULN_TYPE_ALIASES.get(params["vuln_type"].lower(), params["vuln_type"])
            
        return cls(
            type=data.get("action", data.get("type", "done")),
            params=params,
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
    # Existing injection testing
    "scan_endpoint": "Test endpoint for XSS, SQLi, SSRF, CMDi vulnerabilities",
    "fuzz_parameter": "Fuzz a specific parameter with targeted payloads",
    "explore_endpoint": "Discover endpoint behavior and parameters",
    
    # NEW: Access control testing
    "test_idor": "Test for IDOR by changing numeric/UUID IDs in URL path",
    "test_auth": "Test if endpoint requires authentication (try without auth)",
    "test_info_disclosure": "Check response for leaked secrets, API keys, internal data",
    "test_open_redirect": "Test redirect/url parameters for open redirect",
    
    # Control
    "done": "Finish testing when all high-value tests are complete",
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
