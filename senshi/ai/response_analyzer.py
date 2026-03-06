"""
LLM response analyzer — analyze HTTP responses for vulnerabilities.

v0.2.0: Added analyze_batch() for batched analysis (1 LLM call per endpoint).
"""

from __future__ import annotations

import json
from typing import Any

from senshi.ai.brain import Brain
from senshi.ai.prompts.response_analysis import (
    BATCH_ANALYSIS_SYSTEM_PROMPT,
    RESPONSE_ANALYSIS_SYSTEM_PROMPT,
)
from senshi.reporters.models import Confidence, Finding, ScanMode, Severity
from senshi.utils.http import truncate_body
from senshi.utils.logger import get_logger

logger = get_logger("senshi.ai.response_analyzer")


class ResponseAnalyzer:
    """Analyze HTTP responses using LLM to detect vulnerabilities."""

    def __init__(self, brain: Brain) -> None:
        self.brain = brain

    def analyze_batch(
        self,
        endpoint: str,
        method: str,
        vuln_type: str,
        baseline_status: int,
        baseline_content_type: str,
        baseline_body: str,
        payload_results: list[dict[str, Any]],
    ) -> list[Finding]:
        """
        Analyze ALL payload results in ONE LLM call.

        This is the v0.2.0 performance optimization — instead of
        calling the LLM once per payload, we batch all results.

        Args:
            endpoint: Target URL.
            method: HTTP method.
            vuln_type: Vulnerability class being tested.
            baseline_status: Baseline response status.
            baseline_content_type: Baseline content type.
            baseline_body: Baseline response body.
            payload_results: List of {payload, status, body, headers} dicts.

        Returns:
            List of findings from the batch.
        """
        if not payload_results:
            return []

        # Format payload results for the prompt
        formatted_parts = []
        for i, pr in enumerate(payload_results):
            body_preview = pr.get("response_body", "")[:500]
            formatted_parts.append(
                f"[Payload {i}] {pr.get('payload', '')}\n"
                f"  Status: {pr.get('response_status', '?')} | "
                f"Content-Type: {pr.get('content_type', '?')}\n"
                f"  Body preview: {body_preview}"
            )

        payload_results_formatted = "\n\n".join(formatted_parts)

        system_prompt = BATCH_ANALYSIS_SYSTEM_PROMPT.format(
            method=method,
            url=endpoint,
            count=len(payload_results),
            vuln_type=vuln_type,
            baseline_status=baseline_status,
            baseline_content_type=baseline_content_type,
            baseline_body_preview=truncate_body(baseline_body, 500),
            payload_results_formatted=payload_results_formatted,
        )

        try:
            result = self.brain.think(
                system_prompt=system_prompt,
                user_prompt="Analyze all payload results. Return findings as JSON.",
                json_schema={"type": "object"},
            )

            if isinstance(result, dict):
                findings_data = result.get("findings", [])
                findings = []
                for fd in findings_data:
                    if fd.get("is_vulnerable"):
                        idx = fd.get("payload_index", 0)
                        payload_val = ""
                        if 0 <= idx < len(payload_results):
                            payload_val = payload_results[idx].get("payload", "")

                        finding = self._batch_result_to_finding(
                            fd, endpoint, method, payload_val
                        )
                        findings.append(finding)
                return findings

            return []

        except Exception as e:
            logger.warning(f"Batch analysis failed: {e}")
            return []

    def _batch_result_to_finding(
        self,
        result: dict[str, Any],
        endpoint: str,
        method: str,
        payload: str,
    ) -> Finding:
        """Convert a batch analysis result to a Finding."""
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
            title=result.get("title", f"{vuln_type.upper()} in {endpoint}"),
            severity=severity_map.get(
                result.get("severity", "medium"), Severity.MEDIUM
            ),
            confidence=confidence_map.get(
                result.get("confidence", "possible"), Confidence.POSSIBLE
            ),
            category=vuln_type,
            description=result.get("reasoning", ""),
            mode=ScanMode.DAST,
            endpoint=endpoint,
            method=method,
            payload=payload,
            evidence=result.get("evidence", ""),
            llm_reasoning=result.get("reasoning", ""),
        )

    # --- Legacy single-payload analysis (kept for backwards compat) ---

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
        Analyze a single test response against a baseline.

        DEPRECATED in v0.2.0 — use analyze_batch() instead.
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
