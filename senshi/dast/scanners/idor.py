"""
IDOR Scanner — ID enumeration, access control bypass.

v0.2.0: Smart routing + path-based IDOR testing.
"""

from __future__ import annotations

import re
from typing import Any

from senshi.dast.crawler import DiscoveredEndpoint
from senshi.dast.scanners.base import BaseDastScanner
from senshi.reporters.models import Confidence, Finding, Severity, ScanMode
from senshi.utils.logger import get_logger

logger = get_logger("senshi.dast.scanners.idor")

ID_PARAM_NAMES = {"id", "user_id", "uid", "account", "account_id", "profile", "pid", "doc_id"}


class IdorScanner(BaseDastScanner):
    """IDOR scanner — insecure direct object reference testing."""

    def get_scanner_name(self) -> str:
        return "IDOR Scanner"

    def get_vulnerability_class(self) -> str:
        return "idor"

    def filter_relevant_endpoints(
        self, endpoints: list[DiscoveredEndpoint]
    ) -> list[DiscoveredEndpoint]:
        """IDOR is relevant for endpoints with numeric IDs in path or ID params."""
        relevant = []
        for ep in endpoints:
            # Path-based IDs
            if re.search(r'/\d+', ep.url):
                relevant.append(ep)
                continue
            # Param-based IDs
            if ep.params and any(p.lower() in ID_PARAM_NAMES for p in ep.params):
                relevant.append(ep)
        return relevant

    def run_heuristics(
        self,
        endpoint: DiscoveredEndpoint,
        baseline: Any,
        payload_results: list[dict[str, Any]],
    ) -> list[Finding]:
        """Check for different data returned with different IDs + path IDOR."""
        findings = []
        baseline_body = baseline.body if hasattr(baseline, "body") else ""

        for pr in payload_results:
            body = pr.get("response_body", "")
            status = pr.get("response_status", 0)

            if status == 200:
                body_diff = abs(len(body) - len(baseline_body))
                if body_diff > 100 or self._contains_different_data(baseline_body, body):
                    findings.append(Finding(
                        title=f"Potential IDOR in {endpoint.url}",
                        severity=Severity.HIGH,
                        confidence=Confidence.POSSIBLE,
                        category="idor",
                        description="Different data returned with modified ID.",
                        mode=ScanMode.DAST,
                        endpoint=endpoint.url,
                        method=endpoint.method,
                        payload=pr.get("payload", ""),
                        status_code=status,
                        evidence=f"Body length diff: {body_diff} bytes",
                    ))

        # Path-based IDOR
        path_findings = self._test_path_idor(endpoint)
        findings.extend(path_findings)

        return findings

    def _contains_different_data(self, baseline: str, response: str) -> bool:
        """Check if response contains different user data."""
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        baseline_emails = set(re.findall(email_pattern, baseline))
        response_emails = set(re.findall(email_pattern, response))
        if response_emails - baseline_emails:
            return True

        id_pattern = r'"id"\s*:\s*(\d+)'
        baseline_ids = set(re.findall(id_pattern, baseline))
        response_ids = set(re.findall(id_pattern, response))
        if response_ids - baseline_ids:
            return True

        return False

    def _test_path_idor(self, endpoint: DiscoveredEndpoint) -> list[Finding]:
        """Test for IDOR in URL path segments."""
        findings: list[Finding] = []
        id_pattern = re.compile(r'/(\d+)(?:/|$)')
        matches = id_pattern.findall(endpoint.url)

        for original_id in matches:
            test_ids = [str(int(original_id) + 1), str(int(original_id) - 1), "1"]
            for test_id in test_ids:
                modified_url = endpoint.url.replace(f"/{original_id}", f"/{test_id}", 1)
                try:
                    response = self.session.get(modified_url)
                    baseline = self.session.get_baseline(endpoint.url)
                    if response.status_code == 200 and response.body != baseline.body:
                        findings.append(Finding(
                            title=f"Potential IDOR in path — {endpoint.url}",
                            severity=Severity.HIGH,
                            confidence=Confidence.POSSIBLE,
                            category="idor",
                            description=f"Changing ID from {original_id} to {test_id} returns different data.",
                            mode=ScanMode.DAST,
                            endpoint=endpoint.url,
                            method=endpoint.method,
                            payload=f"Path: {original_id} → {test_id}",
                            status_code=response.status_code,
                            evidence=f"Modified URL: {modified_url}",
                        ))
                        break
                except Exception:
                    continue

        return findings
