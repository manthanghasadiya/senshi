"""
SSRF Scanner — internal URLs, cloud metadata, DNS rebind.
"""

from __future__ import annotations

from typing import Any

from senshi.dast.scanners.base import BaseDastScanner
from senshi.reporters.models import Confidence, Finding, Severity, ScanMode
from senshi.utils.logger import get_logger

logger = get_logger("senshi.dast.scanners.ssrf")

# Known cloud metadata indicators
METADATA_INDICATORS = [
    "ami-id",
    "instance-id",
    "instance-type",
    "iam",
    "security-credentials",
    "meta-data",
    "user-data",
    "computeMetadata",
    "access-token",
    "service-accounts",
]


class SsrfScanner(BaseDastScanner):
    """SSRF scanner — internal URLs, cloud metadata, DNS rebinding."""

    def get_scanner_name(self) -> str:
        return "SSRF Scanner"

    def get_vulnerability_class(self) -> str:
        return "ssrf"

    def send_and_analyze(self, payloads: list[dict[str, Any]]) -> list[Finding]:
        """Override to add SSRF-specific detection heuristics."""
        findings = super().send_and_analyze(payloads)

        endpoint = self.context.get("endpoint", "")
        method = self.context.get("method", "GET")
        params = self.context.get("parameters", [])
        baseline = self.session.get_baseline(endpoint)

        for payload_data in payloads:
            value = payload_data.get("value", "")
            injection_point = payload_data.get("injection_point", "")

            if not value:
                continue

            try:
                target_param = injection_point or (params[0] if params else "url")

                if method.upper() == "GET":
                    response = self.session.get(endpoint, params={target_param: value})
                else:
                    response = self.session.post(endpoint, data={target_param: value})

                # Check for cloud metadata indicators
                for indicator in METADATA_INDICATORS:
                    if indicator in response.body and indicator not in baseline.body:
                        already_found = any(
                            f.payload == value and f.category == "ssrf"
                            for f in findings
                        )
                        if not already_found:
                            findings.append(Finding(
                                title=f"SSRF — Cloud metadata access via {endpoint}",
                                severity=Severity.CRITICAL,
                                confidence=Confidence.CONFIRMED,
                                category="ssrf",
                                description=(
                                    f"Cloud metadata indicator '{indicator}' found in response. "
                                    f"The server is making requests to internal/cloud URLs."
                                ),
                                mode=ScanMode.DAST,
                                endpoint=endpoint,
                                method=method,
                                payload=value,
                                response_snippet=response.body[:500],
                                status_code=response.status_code,
                                evidence=f"Cloud metadata indicator: {indicator}",
                                cvss_estimate=9.1,
                            ))
                            break

                # Check for internal service indicators
                internal_indicators = [
                    "root:", "/etc/passwd", "localhost",
                    "Connection refused", "No route to host",
                ]
                for indicator in internal_indicators:
                    if indicator in response.body and indicator not in baseline.body:
                        already_found = any(
                            f.payload == value and f.category == "ssrf"
                            for f in findings
                        )
                        if not already_found:
                            findings.append(Finding(
                                title=f"SSRF — Internal service access via {endpoint}",
                                severity=Severity.HIGH,
                                confidence=Confidence.LIKELY,
                                category="ssrf",
                                description=(
                                    f"Internal service indicator '{indicator}' found. "
                                    f"Server may be making internal requests."
                                ),
                                mode=ScanMode.DAST,
                                endpoint=endpoint,
                                method=method,
                                payload=value,
                                response_snippet=response.body[:500],
                                status_code=response.status_code,
                                evidence=f"Internal indicator: {indicator}",
                                cvss_estimate=7.5,
                            ))
                            break

            except Exception as e:
                logger.debug(f"SSRF heuristic check failed: {e}")
                continue

        return findings
