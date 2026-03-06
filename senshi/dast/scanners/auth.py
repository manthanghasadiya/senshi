"""
Auth Scanner — authentication bypass, session issues, JWT flaws, OAuth.
"""

from __future__ import annotations

from typing import Any

from senshi.dast.scanners.base import BaseDastScanner
from senshi.reporters.models import Confidence, Finding, Severity, ScanMode
from senshi.utils.logger import get_logger

logger = get_logger("senshi.dast.scanners.auth")


class AuthScanner(BaseDastScanner):
    """Auth bypass, session issues, JWT flaws, OAuth issues scanner."""

    def get_scanner_name(self) -> str:
        return "Auth Scanner"

    def get_vulnerability_class(self) -> str:
        return "auth"

    def send_and_analyze(self, payloads: list[dict[str, Any]]) -> list[Finding]:
        """Override with auth-specific checks."""
        findings = super().send_and_analyze(payloads)

        endpoint = self.context.get("endpoint", "")
        method = self.context.get("method", "GET")
        baseline = self.session.get_baseline(endpoint)

        # Test 1: Access without auth headers
        unauthenticated = self._test_no_auth(endpoint, method)
        if unauthenticated:
            findings.extend(unauthenticated)

        # Test 2: HTTP method switching
        method_findings = self._test_method_switch(endpoint, baseline)
        findings.extend(method_findings)

        # Test 3: Header-based bypasses
        header_findings = self._test_header_bypass(endpoint, baseline)
        findings.extend(header_findings)

        return findings

    def _test_no_auth(self, endpoint: str, method: str) -> list[Finding]:
        """Test if endpoint is accessible without authentication."""
        findings: list[Finding] = []

        try:
            # Send request without session cookies/auth
            response = self.session.request(
                method, endpoint, headers={"Cookie": "", "Authorization": ""}
            )

            # If we get 200 and the response has data, might be missing auth
            if response.status_code == 200 and len(response.body) > 100:
                findings.append(Finding(
                    title=f"Missing authentication on {endpoint}",
                    severity=Severity.HIGH,
                    confidence=Confidence.POSSIBLE,
                    category="auth",
                    description="Endpoint returns data without authentication headers.",
                    mode=ScanMode.DAST,
                    endpoint=endpoint,
                    method=method,
                    payload="No auth headers",
                    status_code=response.status_code,
                    evidence=f"Response length: {len(response.body)} bytes without auth",
                ))

        except Exception:
            pass

        return findings

    def _test_method_switch(self, endpoint: str, baseline: Any) -> list[Finding]:
        """Test if switching HTTP method bypasses auth."""
        findings: list[Finding] = []
        original_method = self.context.get("method", "GET")

        alternative_methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
        alternative_methods = [m for m in alternative_methods if m != original_method]

        for alt_method in alternative_methods[:3]:  # Test up to 3 alternatives
            try:
                response = self.session.request(alt_method, endpoint)

                if response.status_code == 200 and baseline.status_code in (401, 403):
                    findings.append(Finding(
                        title=f"Auth bypass via HTTP method switching on {endpoint}",
                        severity=Severity.HIGH,
                        confidence=Confidence.LIKELY,
                        category="auth",
                        description=(
                            f"Using {alt_method} instead of {original_method} "
                            f"returns 200 instead of {baseline.status_code}."
                        ),
                        mode=ScanMode.DAST,
                        endpoint=endpoint,
                        method=alt_method,
                        payload=f"Method: {original_method} → {alt_method}",
                        status_code=response.status_code,
                        evidence=f"{alt_method} returned 200 vs {original_method} returned {baseline.status_code}",
                    ))

            except Exception:
                continue

        return findings

    def _test_header_bypass(self, endpoint: str, baseline: Any) -> list[Finding]:
        """Test header-based auth bypass techniques."""
        findings: list[Finding] = []

        bypass_headers = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Original-URL": endpoint},
            {"X-Rewrite-URL": endpoint},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"X-Forwarded-Host": "localhost"},
        ]

        for headers in bypass_headers:
            try:
                response = self.session.request(
                    "GET", endpoint, headers=headers
                )

                if (
                    response.status_code == 200
                    and baseline.status_code in (401, 403)
                ):
                    header_name = list(headers.keys())[0]
                    findings.append(Finding(
                        title=f"Auth bypass via {header_name} on {endpoint}",
                        severity=Severity.HIGH,
                        confidence=Confidence.LIKELY,
                        category="auth",
                        description=(
                            f"Adding {header_name}: {headers[header_name]} "
                            f"bypasses authentication (200 vs {baseline.status_code})."
                        ),
                        mode=ScanMode.DAST,
                        endpoint=endpoint,
                        method="GET",
                        payload=f"{header_name}: {headers[header_name]}",
                        status_code=response.status_code,
                        evidence=f"Header bypass with {header_name}",
                    ))

            except Exception:
                continue

        return findings
