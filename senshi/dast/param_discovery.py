"""
Parameter discovery — discover hidden parameters via fuzzing and analysis.
"""

from __future__ import annotations

from typing import Any

from senshi.ai.brain import Brain
from senshi.core.session import Session
from senshi.utils.logger import get_logger

logger = get_logger("senshi.dast.param_discovery")

# Common parameter names to test
COMMON_PARAMS: list[str] = [
    "id", "user", "username", "email", "name", "q", "query", "search",
    "page", "limit", "offset", "sort", "order", "filter", "type",
    "action", "cmd", "command", "exec", "url", "uri", "path", "file",
    "dir", "redirect", "next", "return", "callback", "token", "key",
    "api_key", "secret", "password", "pass", "auth", "session",
    "debug", "test", "admin", "role", "permission", "internal",
    "format", "output", "template", "view", "render", "include",
    "data", "json", "xml", "body", "content", "message", "text",
    "input", "value", "param", "args", "config", "settings",
]


class ParamDiscovery:
    """Discover hidden parameters on endpoints."""

    def __init__(self, session: Session, brain: Brain | None = None) -> None:
        self.session = session
        self.brain = brain

    def discover(
        self,
        endpoint: str,
        method: str = "GET",
        known_params: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Discover parameters for an endpoint.

        Returns list of parameter dicts with name, type, and discovery method.
        """
        discovered: list[dict[str, Any]] = []
        known = set(known_params or [])

        # Phase 1: Common param fuzzing
        baseline = self.session.get_baseline(endpoint)

        for param in COMMON_PARAMS:
            if param in known:
                continue

            try:
                if method.upper() == "GET":
                    response = self.session.get(endpoint, params={param: "test123"})
                else:
                    response = self.session.post(endpoint, data={param: "test123"})

                # Check if the parameter affected the response
                if self._is_param_accepted(baseline, response, param):
                    discovered.append({
                        "name": param,
                        "type": "string",
                        "method": "fuzzing",
                        "evidence": f"Response changed with param={param}",
                    })

            except Exception:
                continue

        # Phase 2: LLM-based discovery
        if self.brain:
            llm_params = self._llm_discover(endpoint, method, known)
            discovered.extend(llm_params)

        logger.info(f"Discovered {len(discovered)} parameters for {endpoint}")
        return discovered

    def _is_param_accepted(self, baseline: Any, response: Any, param: str) -> bool:
        """Check if a parameter was accepted by comparing responses."""
        # Different status code
        if response.status_code != baseline.status_code:
            return True

        # Significant body length difference
        if abs(len(response.body) - len(baseline.body)) > 50:
            return True

        # Parameter name reflected in response
        if param in response.body and param not in baseline.body:
            return True

        return False

    def _llm_discover(
        self,
        endpoint: str,
        method: str,
        known: set[str],
    ) -> list[dict[str, Any]]:
        """Use LLM to suggest likely parameters."""
        if not self.brain:
            return []

        user_prompt = (
            f"Suggest hidden parameters for this endpoint:\n"
            f"  Method: {method}\n"
            f"  URL: {endpoint}\n"
            f"  Known params: {', '.join(known) if known else 'none'}\n\n"
            f"Consider common patterns for this type of endpoint."
        )

        system_prompt = (
            "You are a web security expert discovering hidden parameters. "
            "Suggest parameters that are commonly found on similar endpoints "
            "but not documented. Output JSON with a 'parameters' array of "
            "objects with 'name', 'type', and 'reasoning' fields."
        )

        try:
            result = self.brain.think(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                json_schema={"type": "object"},
            )

            params = []
            if isinstance(result, dict):
                for p in result.get("parameters", []):
                    if p.get("name") not in known:
                        params.append({
                            "name": p.get("name", ""),
                            "type": p.get("type", "string"),
                            "method": "llm_suggestion",
                            "evidence": p.get("reasoning", ""),
                        })
            return params

        except Exception as e:
            logger.debug(f"LLM param discovery failed: {e}")
            return []
