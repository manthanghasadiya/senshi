"""
XSS Scanner — reflected, stored, DOM, and markdown injection.
"""

from __future__ import annotations

import re
from typing import Any

from senshi.core.session import Session
from senshi.ai.brain import Brain
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

    def send_and_analyze(self, payloads: list[dict[str, Any]]) -> list[Finding]:
        """Override to add XSS-specific detection heuristics."""
        findings = super().send_and_analyze(payloads)

        # Additional heuristic: check for direct reflection
        endpoint = self.context.get("endpoint", "")
        method = self.context.get("method", "GET")
        params = self.context.get("parameters", [])

        for payload_data in payloads:
            value = payload_data.get("value", "")
            injection_point = payload_data.get("injection_point", "")

            if not value:
                continue

            try:
                target_param = injection_point or (params[0] if params else "q")

                if method.upper() == "GET":
                    response = self.session.get(endpoint, params={target_param: value})
                else:
                    response = self.session.post(endpoint, data={target_param: value})

                # Check for direct payload reflection (strong indicator)
                if value in response.body:
                    # Check if the payload is reflected without encoding
                    if self._is_unencoded_reflection(value, response.body):
                        # Check if not already found
                        already_found = any(
                            f.payload == value and f.endpoint == endpoint
                            for f in findings
                        )
                        if not already_found:
                            findings.append(Finding(
                                title=f"Reflected XSS in {endpoint}",
                                severity=Severity.HIGH,
                                confidence=Confidence.LIKELY,
                                category="xss",
                                description=(
                                    f"Payload reflected unencoded in response body. "
                                    f"Parameter: {target_param}"
                                ),
                                mode=ScanMode.DAST,
                                endpoint=endpoint,
                                method=method,
                                payload=value,
                                response_snippet=self._extract_context(value, response.body),
                                status_code=response.status_code,
                                evidence=f"Unencoded reflection of: {value[:100]}",
                            ))

            except Exception as e:
                logger.debug(f"XSS heuristic check failed: {e}")
                continue

        return findings

    def _is_unencoded_reflection(self, payload: str, body: str) -> bool:
        """Check if payload is reflected without HTML encoding."""
        # Key characters that should be encoded
        dangerous_chars = ["<", ">", '"', "'"]
        for char in dangerous_chars:
            if char in payload and char in body:
                # Find the payload in the body and check surrounding context
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
