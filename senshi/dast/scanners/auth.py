"""
Auth Scanner — authentication bypass, session issues, JWT flaws, OAuth.

v0.2.0: Smart routing + auth-specific heuristic tests.
"""

from __future__ import annotations

import re
from typing import Any

from senshi.dast.crawler import DiscoveredEndpoint
from senshi.dast.scanners.base import BaseDastScanner
from senshi.reporters.models import Confidence, Finding, Severity, ScanMode
from senshi.utils.logger import get_logger

logger = get_logger("senshi.dast.scanners.auth")

AUTH_PATH_KEYWORDS = {"admin", "login", "auth", "register", "api", "dashboard", "panel", "user", "account", "settings"}


class AuthScanner(BaseDastScanner):
    """Auth bypass, session issues, JWT flaws, OAuth issues scanner."""

    def get_scanner_name(self) -> str:
        return "Auth Scanner"

    def get_vulnerability_class(self) -> str:
        return "auth"

    def filter_relevant_endpoints(
        self, endpoints: list[DiscoveredEndpoint]
    ) -> list[DiscoveredEndpoint]:
        """Auth testing is relevant for admin, login, API, and protected paths."""
        relevant = []
        for ep in endpoints:
            path_lower = ep.url.lower()
            if any(kw in path_lower for kw in AUTH_PATH_KEYWORDS):
                relevant.append(ep)
        return relevant or endpoints[:3]

    def run_heuristics(
        self,
        endpoint: DiscoveredEndpoint,
        baseline: Any,
        payload_results: list[dict[str, Any]],
    ) -> list[Finding]:
        """Run auth-specific heuristic checks."""
        findings = []

        # Test 1: Access without auth headers
        unauth = self._test_no_auth(endpoint)
        findings.extend(unauth)

        # Test 2: HTTP method switching
        method_findings = self._test_method_switch(endpoint, baseline)
        findings.extend(method_findings)

        # Test 3: Header-based bypasses
        header_findings = self._test_header_bypass(endpoint, baseline)
        findings.extend(header_findings)

        return findings

    def _test_no_auth(self, endpoint: DiscoveredEndpoint) -> list[Finding]:
        """Test if endpoint is accessible without authentication."""
        findings: list[Finding] = []
        try:
            response = self.session.request(
                endpoint.method, endpoint.url,
                headers={"Cookie": "", "Authorization": ""}
            )
            if response.status_code == 200 and len(response.body) > 100:
                findings.append(Finding(
                    title=f"Missing authentication on {endpoint.url}",
                    severity=Severity.HIGH,
                    confidence=Confidence.POSSIBLE,
                    category="auth",
                    description="Endpoint returns data without authentication headers.",
                    mode=ScanMode.DAST,
                    endpoint=endpoint.url,
                    method=endpoint.method,
                    payload="No auth headers",
                    status_code=response.status_code,
                    evidence=f"Response length: {len(response.body)} bytes without auth",
                ))
        except Exception:
            pass
        return findings

    def _test_method_switch(self, endpoint: DiscoveredEndpoint, baseline: Any) -> list[Finding]:
        """Test if switching HTTP method bypasses auth."""
        findings: list[Finding] = []
        alt_methods = [m for m in ["GET", "POST", "PUT", "PATCH", "DELETE"] if m != endpoint.method]

        for alt in alt_methods[:3]:
            try:
                response = self.session.request(alt, endpoint.url)
                if response.status_code == 200 and baseline.status_code in (401, 403):
                    findings.append(Finding(
                        title=f"Auth bypass via method switching on {endpoint.url}",
                        severity=Severity.HIGH,
                        confidence=Confidence.LIKELY,
                        category="auth",
                        description=f"Using {alt} returns 200 instead of {baseline.status_code}.",
                        mode=ScanMode.DAST,
                        endpoint=endpoint.url,
                        method=alt,
                        payload=f"Method: {endpoint.method} → {alt}",
                        status_code=response.status_code,
                        evidence=f"{alt} returned 200 vs {endpoint.method} returned {baseline.status_code}",
                    ))
            except Exception:
                continue
        return findings

    def _test_header_bypass(self, endpoint: DiscoveredEndpoint, baseline: Any) -> list[Finding]:
        """Test header-based auth bypass techniques."""
        findings: list[Finding] = []
        bypass_headers = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Original-URL": endpoint.url},
            {"X-Rewrite-URL": endpoint.url},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"X-Forwarded-Host": "localhost"},
        ]

        for headers in bypass_headers:
            try:
                response = self.session.request("GET", endpoint.url, headers=headers)
                if response.status_code == 200 and baseline.status_code in (401, 403):
                    header_name = list(headers.keys())[0]
                    findings.append(Finding(
                        title=f"Auth bypass via {header_name} on {endpoint.url}",
                        severity=Severity.HIGH,
                        confidence=Confidence.LIKELY,
                        category="auth",
                        description=f"Adding {header_name} bypasses authentication.",
                        mode=ScanMode.DAST,
                        endpoint=endpoint.url,
                        method="GET",
                        payload=f"{header_name}: {headers[header_name]}",
                        status_code=response.status_code,
                        evidence=f"Header bypass with {header_name}",
                    ))
            except Exception:
                continue
        return findings
