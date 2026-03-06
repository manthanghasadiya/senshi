"""
IDOR Scanner — ID enumeration, access control bypass.
"""

from __future__ import annotations

import re
from typing import Any

from senshi.dast.scanners.base import BaseDastScanner
from senshi.reporters.models import Confidence, Finding, Severity, ScanMode
from senshi.utils.logger import get_logger

logger = get_logger("senshi.dast.scanners.idor")


class IdorScanner(BaseDastScanner):
    """IDOR scanner — insecure direct object reference testing."""

    def get_scanner_name(self) -> str:
        return "IDOR Scanner"

    def get_vulnerability_class(self) -> str:
        return "idor"

    def send_and_analyze(self, payloads: list[dict[str, Any]]) -> list[Finding]:
        """Override with IDOR-specific analysis."""
        findings: list[Finding] = []
        endpoint = self.context.get("endpoint", "")
        method = self.context.get("method", "GET")
        params = self.context.get("parameters", [])

        baseline = self.session.get_baseline(endpoint)

        for payload_data in payloads:
            original_value = payload_data.get("original", payload_data.get("value", ""))
            test_value = payload_data.get("test", payload_data.get("value", ""))
            technique = payload_data.get("technique", "sequential")
            injection_point = payload_data.get("injection_point", "")

            if not test_value:
                continue

            try:
                target_param = injection_point or (params[0] if params else "id")

                # Send with modified ID
                if method.upper() == "GET":
                    response = self.session.get(endpoint, params={target_param: test_value})
                else:
                    response = self.session.post(endpoint, data={target_param: test_value})

                # IDOR indicators:
                # 1. Got 200 with different data (different user's data)
                # 2. Response body changed significantly
                # 3. Got different user identifiers in response
                if response.status_code == 200:
                    body_diff = abs(len(response.body) - len(baseline.body))

                    if body_diff > 100 or self._contains_different_data(
                        baseline.body, response.body
                    ):
                        # Use LLM to verify this is a real IDOR
                        finding = self.response_analyzer.analyze(
                            endpoint=endpoint,
                            method=method,
                            payload=f"{target_param}={test_value} (original: {original_value})",
                            technique=f"IDOR {technique}",
                            baseline_status=baseline.status_code,
                            baseline_headers=baseline.headers,
                            baseline_body=baseline.body,
                            test_status=response.status_code,
                            test_headers=response.headers,
                            test_body=response.body,
                        )

                        if finding:
                            finding.category = "idor"
                            findings.append(finding)

            except Exception as e:
                logger.debug(f"IDOR check failed: {e}")
                continue

        # Also test path-based IDOR
        path_findings = self._test_path_idor(endpoint, method)
        findings.extend(path_findings)

        return findings

    def _contains_different_data(self, baseline: str, response: str) -> bool:
        """Check if response contains different user data than baseline."""
        # Look for common PII-like patterns
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        baseline_emails = set(re.findall(email_pattern, baseline))
        response_emails = set(re.findall(email_pattern, response))

        if response_emails - baseline_emails:
            return True

        # Look for different IDs
        id_pattern = r'"id"\s*:\s*(\d+)'
        baseline_ids = set(re.findall(id_pattern, baseline))
        response_ids = set(re.findall(id_pattern, response))

        if response_ids - baseline_ids:
            return True

        return False

    def _test_path_idor(self, endpoint: str, method: str) -> list[Finding]:
        """Test for IDOR in URL path segments."""
        findings: list[Finding] = []

        # Look for numeric IDs in path
        id_pattern = re.compile(r'/(\d+)(?:/|$)')
        matches = id_pattern.findall(endpoint)

        for original_id in matches:
            # Try adjacent IDs
            test_ids = [
                str(int(original_id) + 1),
                str(int(original_id) - 1),
                "1",
            ]

            for test_id in test_ids:
                modified_url = endpoint.replace(f"/{original_id}", f"/{test_id}", 1)

                try:
                    response = self.session.get(modified_url)
                    baseline = self.session.get_baseline(endpoint)

                    if response.status_code == 200 and response.body != baseline.body:
                        findings.append(Finding(
                            title=f"Potential IDOR in path — {endpoint}",
                            severity=Severity.HIGH,
                            confidence=Confidence.POSSIBLE,
                            category="idor",
                            description=(
                                f"Changing path ID from {original_id} to {test_id} "
                                f"returns different data with 200 status."
                            ),
                            mode=ScanMode.DAST,
                            endpoint=endpoint,
                            method=method,
                            payload=f"Path: {original_id} → {test_id}",
                            status_code=response.status_code,
                            evidence=f"Modified URL: {modified_url}",
                        ))
                        break  # One finding per ID position

                except Exception:
                    continue

        return findings
