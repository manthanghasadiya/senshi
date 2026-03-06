"""
Injection Scanner — SQLi, command injection, template injection, NoSQL injection.

v0.2.0: Smart routing + heuristic checks using batch results.
"""

from __future__ import annotations

import re
import time
from typing import Any

from senshi.dast.crawler import DiscoveredEndpoint
from senshi.dast.scanners.base import BaseDastScanner
from senshi.reporters.models import Confidence, Finding, Severity, ScanMode
from senshi.utils.logger import get_logger

logger = get_logger("senshi.dast.scanners.injection")

# Error-based detection patterns
SQL_ERROR_PATTERNS: list[str] = [
    "SQL syntax", "mysql_", "ORA-", "PG::SyntaxError",
    "sqlite3.OperationalError", "Microsoft OLE DB",
    "ODBC SQL Server Driver", "PostgreSQL", "SQLite",
    "Unclosed quotation mark", "quoted string not properly terminated",
    "You have an error in your SQL syntax",
    "Warning: mysql_", "Warning: pg_",
]

COMMAND_INJECTION_PATTERNS: list[str] = [
    "uid=", "root:", "/etc/passwd", "bin/bash",
    "Windows IP Configuration", "ipconfig",
    "PING", "bytes from", "icmp_seq",
    "total        used        free",
]

SSTI_PATTERNS: list[str] = [
    "49", "7777777", "<class", "__class__", "__mro__",
    "config", "SECRET_KEY",
]

# Param names suggesting injection surface
INJECTION_PARAM_NAMES = {
    "q", "query", "search", "filter", "sort", "order", "id", "user_id",
    "page", "limit", "offset", "name", "username", "email", "host",
    "cmd", "command", "exec", "run", "ip", "ping", "dir", "path",
    "file", "template", "input", "data", "value", "key", "param",
}


class InjectionScanner(BaseDastScanner):
    """SQLi, command injection, template injection, NoSQL injection scanner."""

    def get_scanner_name(self) -> str:
        return "Injection Scanner"

    def get_vulnerability_class(self) -> str:
        return "injection"

    def filter_relevant_endpoints(
        self, endpoints: list[DiscoveredEndpoint]
    ) -> list[DiscoveredEndpoint]:
        """Injection needs endpoints with params (search, filter, id, cmd)."""
        relevant = []
        for ep in endpoints:
            if not ep.params:
                continue
            if any(p.lower() in INJECTION_PARAM_NAMES for p in ep.params):
                relevant.append(ep)
            elif ep.params:
                # Any endpoint with params is potentially injectable
                relevant.append(ep)
        return relevant or endpoints[:3]

    def run_heuristics(
        self,
        endpoint: DiscoveredEndpoint,
        baseline: Any,
        payload_results: list[dict[str, Any]],
    ) -> list[Finding]:
        """Check for SQL errors, command output, and SSTI indicators."""
        findings = []
        baseline_body = baseline.body if hasattr(baseline, "body") else ""

        for pr in payload_results:
            payload = pr.get("payload", "")
            body = pr.get("response_body", "")

            # SQL error-based detection
            for pattern in SQL_ERROR_PATTERNS:
                if pattern.lower() in body.lower() and pattern.lower() not in baseline_body.lower():
                    findings.append(Finding(
                        title=f"SQL Injection (error-based) in {endpoint.url}",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.CONFIRMED,
                        category="sqli",
                        description=f"SQL error message detected: {pattern}",
                        mode=ScanMode.DAST,
                        endpoint=endpoint.url,
                        method=endpoint.method,
                        payload=payload,
                        response_snippet=body[:500],
                        status_code=pr.get("response_status", 0),
                        evidence=f"SQL error pattern: {pattern}",
                        cvss_estimate=9.8,
                    ))
                    break

            # Command injection detection
            for pattern in COMMAND_INJECTION_PATTERNS:
                if pattern in body and pattern not in baseline_body:
                    findings.append(Finding(
                        title=f"Command Injection in {endpoint.url}",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.LIKELY,
                        category="cmdi",
                        description=f"Command output indicator: {pattern}",
                        mode=ScanMode.DAST,
                        endpoint=endpoint.url,
                        method=endpoint.method,
                        payload=payload,
                        response_snippet=body[:500],
                        status_code=pr.get("response_status", 0),
                        evidence=f"Command output: {pattern}",
                        cvss_estimate=9.8,
                    ))
                    break

            # SSTI detection
            for pattern in SSTI_PATTERNS:
                if pattern in body and pattern not in baseline_body:
                    if len(pattern) <= 5 and body.count(pattern) < 3:
                        continue
                    findings.append(Finding(
                        title=f"Template Injection (SSTI) in {endpoint.url}",
                        severity=Severity.HIGH,
                        confidence=Confidence.POSSIBLE,
                        category="ssti",
                        description=f"Template injection indicator: {pattern}",
                        mode=ScanMode.DAST,
                        endpoint=endpoint.url,
                        method=endpoint.method,
                        payload=payload,
                        response_snippet=body[:500],
                        status_code=pr.get("response_status", 0),
                        evidence=f"SSTI indicator: {pattern}",
                        cvss_estimate=8.0,
                    ))
                    break

        # Time-based blind SQLi (separate from batch)
        time_findings = self._test_time_based(endpoint)
        findings.extend(time_findings)

        return findings

    def _test_time_based(self, endpoint: DiscoveredEndpoint) -> list[Finding]:
        """Test for time-based blind SQL injection."""
        findings: list[Finding] = []
        target_param = endpoint.params[0] if endpoint.params else "q"

        time_payloads = [
            ("' AND SLEEP(3)--", "mysql_sleep"),
            ("'; WAITFOR DELAY '0:0:3'--", "mssql_waitfor"),
            ("' AND pg_sleep(3)--", "pg_sleep"),
        ]

        for payload, technique in time_payloads:
            try:
                start = time.time()
                if endpoint.method.upper() == "GET":
                    self.session.get(endpoint.url, params={target_param: payload})
                else:
                    self.session.post(endpoint.url, data={target_param: payload})
                elapsed = time.time() - start

                if elapsed >= 2.5:
                    findings.append(Finding(
                        title=f"Blind SQL Injection (time-based) in {endpoint.url}",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.LIKELY,
                        category="sqli",
                        description=(
                            f"Response delayed by {elapsed:.1f}s with time-based payload. "
                            f"Technique: {technique}"
                        ),
                        mode=ScanMode.DAST,
                        endpoint=endpoint.url,
                        method=endpoint.method,
                        payload=payload,
                        evidence=f"Response time: {elapsed:.1f}s (expected ≥3s)",
                        cvss_estimate=9.8,
                    ))
                    break

            except Exception:
                continue

        return findings
