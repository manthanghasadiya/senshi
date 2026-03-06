"""
LLM response analyzer — analyze HTTP responses for vulnerabilities.

Takes baseline and tested responses, asks the LLM to identify vulns.
"""

from __future__ import annotations

import json
from typing import Any

from senshi.ai.brain import Brain
from senshi.ai.prompts.response_analysis import RESPONSE_ANALYSIS_SYSTEM_PROMPT
from senshi.reporters.models import Confidence, Finding, ScanMode, Severity
from senshi.utils.http import truncate_body
from senshi.utils.logger import get_logger

logger = get_logger("senshi.ai.response_analyzer")


class ResponseAnalyzer:
    """Analyze HTTP responses using LLM to detect vulnerabilities."""

    def __init__(self, brain: Brain) -> None:
        self.brain = brain

    def analyze(
        self,
        endpoint: str,
        method: str,
        payload: str,
        technique: str,
        baseline_status: int,
        baseline_headers: dict[str, str],
        baseline_body: str,
        test_status: int,
        test_headers: dict[str, str],
        test_body: str,
    ) -> Finding | None:
        """
        Analyze a test response against a baseline.

        Returns a Finding if vulnerability detected, None otherwise.
        """
        system_prompt = RESPONSE_ANALYSIS_SYSTEM_PROMPT.format(
            method=method,
            url=endpoint,
            payload=payload,
            technique=technique,
            baseline_status=baseline_status,
            baseline_headers=json.dumps(dict(list(baseline_headers.items())[:20])),
            baseline_body=truncate_body(baseline_body),
            test_status=test_status,
            test_headers=json.dumps(dict(list(test_headers.items())[:20])),
            test_body=truncate_body(test_body),
        )

        user_prompt = (
            "Analyze the tested response compared to the baseline. "
            "Is there a vulnerability? Be thorough but avoid false positives."
        )

        try:
            result = self.brain.think(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                json_schema={"type": "object"},
            )

            if isinstance(result, dict) and result.get("is_vulnerable"):
                return self._result_to_finding(result, endpoint, method, payload)

            return None

        except Exception as e:
            logger.warning(f"Response analysis failed: {e}")
            return None

    def _result_to_finding(
        self,
        result: dict[str, Any],
        endpoint: str,
        method: str,
        payload: str,
    ) -> Finding:
        """Convert LLM analysis result to Finding object."""
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
        }
        confidence_map = {
            "confirmed": Confidence.CONFIRMED,
            "likely": Confidence.LIKELY,
            "possible": Confidence.POSSIBLE,
        }

        vuln_type = result.get("vulnerability_type", "unknown")

        return Finding(
            title=f"{vuln_type.upper()} in {endpoint}",
            severity=severity_map.get(result.get("severity", "medium"), Severity.MEDIUM),
            confidence=confidence_map.get(result.get("confidence", "possible"), Confidence.POSSIBLE),
            category=vuln_type,
            description=result.get("reasoning", ""),
            mode=ScanMode.DAST,
            endpoint=endpoint,
            method=method,
            payload=payload,
            evidence=result.get("evidence", ""),
            cvss_estimate=result.get("cvss_estimate", 0.0),
            llm_reasoning=result.get("reasoning", ""),
            chain_potential=result.get("follow_up_test", ""),
        )

    async def async_analyze(
        self,
        endpoint: str,
        method: str,
        payload: str,
        technique: str,
        baseline_status: int,
        baseline_headers: dict[str, str],
        baseline_body: str,
        test_status: int,
        test_headers: dict[str, str],
        test_body: str,
    ) -> Finding | None:
        """Async version of analyze()."""
        system_prompt = RESPONSE_ANALYSIS_SYSTEM_PROMPT.format(
            method=method,
            url=endpoint,
            payload=payload,
            technique=technique,
            baseline_status=baseline_status,
            baseline_headers=json.dumps(dict(list(baseline_headers.items())[:20])),
            baseline_body=truncate_body(baseline_body),
            test_status=test_status,
            test_headers=json.dumps(dict(list(test_headers.items())[:20])),
            test_body=truncate_body(test_body),
        )

        user_prompt = (
            "Analyze the tested response compared to the baseline. "
            "Is there a vulnerability? Be thorough but avoid false positives."
        )

        try:
            result = await self.brain.async_think(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                json_schema={"type": "object"},
            )

            if isinstance(result, dict) and result.get("is_vulnerable"):
                return self._result_to_finding(result, endpoint, method, payload)

            return None

        except Exception as e:
            logger.warning(f"Async response analysis failed: {e}")
            return None
