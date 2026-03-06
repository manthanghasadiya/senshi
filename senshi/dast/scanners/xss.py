"""
XSS Scanner — reflected, stored, DOM, and markdown injection.

v0.2.0: Smart routing + heuristic reflection check (no double-send).
"""

from __future__ import annotations

import re
from typing import Any

from senshi.dast.crawler import DiscoveredEndpoint
from senshi.dast.scanners.base import BaseDastScanner
from senshi.reporters.models import Confidence, Finding, Severity, ScanMode
from senshi.utils.logger import get_logger

logger = get_logger("senshi.dast.scanners.xss")


class XssScanner(BaseDastScanner):
    """XSS scanner — reflected, stored, DOM, and markdown injection."""

    def get_scanner_name(self) -> str:
        return "XSS Scanner"

    def get_vulnerability_class(self) -> str:
        return "xss"

    def filter_relevant_endpoints(
        self, endpoints: list[DiscoveredEndpoint]
    ) -> list[DiscoveredEndpoint]:
        """XSS is relevant for endpoints with params that return HTML."""
        relevant = []
        for ep in endpoints:
            if not ep.params:
                continue
            # HTML endpoints or unknown content type
            ct = getattr(ep, "content_type", "")
            if not ct or "html" in ct.lower() or "text" in ct.lower():
                relevant.append(ep)
        return relevant or endpoints[:2]  # Fallback: test first 2

    def run_heuristics(
        self,
        endpoint: DiscoveredEndpoint,
        baseline: Any,
        payload_results: list[dict[str, Any]],
    ) -> list[Finding]:
        """Check for direct unencoded reflection in responses."""
        findings = []

        for pr in payload_results:
            payload = pr.get("payload", "")
            body = pr.get("response_body", "")

            if payload and payload in body:
                if self._is_unencoded_reflection(payload, body):
                    findings.append(
                        Finding(
                            title=f"Reflected XSS in {endpoint.url}",
                            severity=Severity.HIGH,
                            confidence=Confidence.LIKELY,
                            category="xss",
                            description=(
                                f"Payload reflected unencoded in response body. "
                                f"Parameter: {pr.get('injection_point', '?')}"
                            ),
                            mode=ScanMode.DAST,
                            endpoint=endpoint.url,
                            method=endpoint.method,
                            payload=payload,
                            response_snippet=self._extract_context(payload, body),
                            status_code=pr.get("response_status", 0),
                            evidence=f"Unencoded reflection of: {payload[:100]}",
                        )
                    )

        return findings

    def _is_unencoded_reflection(self, payload: str, body: str) -> bool:
        """Check if payload is reflected without HTML encoding."""
        dangerous_chars = ["<", ">", '"', "'"]
        for char in dangerous_chars:
            if char in payload and char in body:
                idx = body.find(payload)
                if idx != -1:
                    return True
        return False

    def _extract_context(self, payload: str, body: str, window: int = 200) -> str:
        """Extract surrounding context of a reflected payload."""
        idx = body.find(payload)
        if idx == -1:
            return ""
        start = max(0, idx - window // 2)
        end = min(len(body), idx + len(payload) + window // 2)
        return body[start:end]
