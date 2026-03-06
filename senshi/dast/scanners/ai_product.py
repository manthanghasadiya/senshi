"""
AI Product Scanner — inference manipulation, data leak, cross-user, prompt injection.

v0.2.0: Smart routing + heuristic checks using batch results.
"""

from __future__ import annotations

import re
from typing import Any

from senshi.dast.crawler import DiscoveredEndpoint
from senshi.dast.scanners.base import BaseDastScanner
from senshi.reporters.models import Confidence, Finding, Severity, ScanMode
from senshi.utils.logger import get_logger

logger = get_logger("senshi.dast.scanners.ai_product")

SYSTEM_PROMPT_INDICATORS: list[str] = [
    "you are a", "your instructions", "system prompt",
    "you must", "you should always", "your role is",
    "I was instructed", "my instructions are",
    "I am an AI", "I am a language model",
    "I cannot reveal", "I'm not able to share",
]

AI_PATH_KEYWORDS = {"chat", "ai", "bot", "assistant", "copilot", "api", "llm", "completion", "generate", "ask", "prompt"}


class AiProductScanner(BaseDastScanner):
    """Scanner for AI/LLM-powered application vulnerabilities."""

    def get_scanner_name(self) -> str:
        return "AI Product Scanner"

    def get_vulnerability_class(self) -> str:
        return "ai_product"

    def filter_relevant_endpoints(
        self, endpoints: list[DiscoveredEndpoint]
    ) -> list[DiscoveredEndpoint]:
        """AI scanner is relevant for chat/AI/bot/LLM-related endpoints."""
        relevant = []
        for ep in endpoints:
            path_lower = ep.url.lower()
            if any(kw in path_lower for kw in AI_PATH_KEYWORDS):
                relevant.append(ep)
            elif ep.params and any(
                p.lower() in {"message", "prompt", "query", "input", "text", "question"}
                for p in ep.params
            ):
                relevant.append(ep)
        return relevant  # Don't fallback — no AI surface = skip

    def run_heuristics(
        self,
        endpoint: DiscoveredEndpoint,
        baseline: Any,
        payload_results: list[dict[str, Any]],
    ) -> list[Finding]:
        """Check for system prompt leakage and cross-user data leak."""
        findings = []
        baseline_body = baseline.body if hasattr(baseline, "body") else ""

        for pr in payload_results:
            payload = pr.get("payload", "")
            body = pr.get("response_body", "")

            # System prompt leakage
            for indicator in SYSTEM_PROMPT_INDICATORS:
                if indicator.lower() in body.lower() and indicator.lower() not in baseline_body.lower():
                    findings.append(Finding(
                        title=f"System Prompt Leakage via {endpoint.url}",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.POSSIBLE,
                        category="prompt_injection",
                        description=f"Potential system prompt leak indicator: '{indicator}'.",
                        mode=ScanMode.DAST,
                        endpoint=endpoint.url,
                        method=endpoint.method,
                        payload=payload,
                        response_snippet=body[:1000],
                        status_code=pr.get("response_status", 0),
                        evidence=f"Indicator: {indicator}",
                    ))
                    break

            # Cross-user data leakage
            if self._check_cross_user_leak(body, baseline_body):
                findings.append(Finding(
                    title=f"Potential cross-user data leak via {endpoint.url}",
                    severity=Severity.HIGH,
                    confidence=Confidence.POSSIBLE,
                    category="data_leak",
                    description="Response contains data suggesting cross-user leakage.",
                    mode=ScanMode.DAST,
                    endpoint=endpoint.url,
                    method=endpoint.method,
                    payload=payload,
                    response_snippet=body[:1000],
                    status_code=pr.get("response_status", 0),
                ))

        return findings

    def _check_cross_user_leak(self, response: str, baseline: str) -> bool:
        """Check for patterns suggesting cross-user data leakage."""
        patterns = [
            r"User:\s+\w+.*?Assistant:",
            r"Previous conversation:",
            r"\[Context from user \w+\]",
        ]
        for pattern in patterns:
            if re.search(pattern, response) and not re.search(pattern, baseline):
                return True
        return False
