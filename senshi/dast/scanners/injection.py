"""
Injection Scanner — SQLi, command injection, template injection, NoSQL injection.
"""

from __future__ import annotations

import time
from typing import Any

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
    "total        used        free",  # free command output
]

SSTI_PATTERNS: list[str] = [
    "49",  # 7*7
    "7777777",  # 7*'7' in Jinja2
    "<class", "__class__", "__mro__",
    "config", "SECRET_KEY",
]


class InjectionScanner(BaseDastScanner):
    """SQLi, command injection, template injection, NoSQL injection scanner."""

    def get_scanner_name(self) -> str:
        return "Injection Scanner"

    def get_vulnerability_class(self) -> str:
        return "injection"

    def send_and_analyze(self, payloads: list[dict[str, Any]]) -> list[Finding]:
        """Override with injection-specific heuristics."""
        findings = super().send_and_analyze(payloads)

        endpoint = self.context.get("endpoint", "")
        method = self.context.get("method", "GET")
        params = self.context.get("parameters", [])
        baseline = self.session.get_baseline(endpoint)

        for payload_data in payloads:
            value = payload_data.get("value", "")
            injection_point = payload_data.get("injection_point", "")
            technique = payload_data.get("technique", "")

            if not value:
                continue

            try:
                target_param = injection_point or (params[0] if params else "q")

                if method.upper() == "GET":
                    response = self.session.get(endpoint, params={target_param: value})
                else:
                    response = self.session.post(endpoint, data={target_param: value})

                # SQL error-based detection
                for pattern in SQL_ERROR_PATTERNS:
                    if pattern.lower() in response.body.lower() and pattern.lower() not in baseline.body.lower():
                        already_found = any(
                            f.category == "sqli" and f.endpoint == endpoint
                            for f in findings
                        )
                        if not already_found:
                            findings.append(Finding(
                                title=f"SQL Injection (error-based) in {endpoint}",
                                severity=Severity.CRITICAL,
                                confidence=Confidence.CONFIRMED,
                                category="sqli",
                                description=f"SQL error message detected: {pattern}",
                                mode=ScanMode.DAST,
                                endpoint=endpoint,
                                method=method,
                                payload=value,
                                response_snippet=response.body[:500],
                                status_code=response.status_code,
                                evidence=f"SQL error pattern: {pattern}",
                                cvss_estimate=9.8,
                            ))
                            break

                # Command injection detection
                for pattern in COMMAND_INJECTION_PATTERNS:
                    if pattern in response.body and pattern not in baseline.body:
                        already_found = any(
                            f.category == "cmdi" and f.endpoint == endpoint
                            for f in findings
                        )
                        if not already_found:
                            findings.append(Finding(
                                title=f"Command Injection in {endpoint}",
                                severity=Severity.CRITICAL,
                                confidence=Confidence.LIKELY,
                                category="cmdi",
                                description=f"Command output indicator: {pattern}",
                                mode=ScanMode.DAST,
                                endpoint=endpoint,
                                method=method,
                                payload=value,
                                response_snippet=response.body[:500],
                                status_code=response.status_code,
                                evidence=f"Command output: {pattern}",
                                cvss_estimate=9.8,
                            ))
                            break

                # SSTI detection (template injection)
                for pattern in SSTI_PATTERNS:
                    if pattern in response.body and pattern not in baseline.body:
                        # Be more careful with short patterns
                        if len(pattern) <= 5 and response.body.count(pattern) < 3:
                            continue
                        already_found = any(
                            f.category == "ssti" and f.endpoint == endpoint
                            for f in findings
                        )
                        if not already_found:
                            findings.append(Finding(
                                title=f"Template Injection (SSTI) in {endpoint}",
                                severity=Severity.HIGH,
                                confidence=Confidence.POSSIBLE,
                                category="ssti",
                                description=f"Template injection indicator: {pattern}",
                                mode=ScanMode.DAST,
                                endpoint=endpoint,
                                method=method,
                                payload=value,
                                response_snippet=response.body[:500],
                                status_code=response.status_code,
                                evidence=f"SSTI indicator: {pattern}",
                                cvss_estimate=8.0,
                            ))
                            break

            except Exception as e:
                logger.debug(f"Injection heuristic check failed: {e}")
                continue

        # Time-based blind SQLi check
        time_findings = self._test_time_based(endpoint, method, params)
        findings.extend(time_findings)

        return findings

    def _test_time_based(
        self,
        endpoint: str,
        method: str,
        params: list[str],
    ) -> list[Finding]:
        """Test for time-based blind SQL injection."""
        findings: list[Finding] = []
        target_param = params[0] if params else "q"

        time_payloads = [
            ("' AND SLEEP(3)--", "mysql_sleep"),
            ("'; WAITFOR DELAY '0:0:3'--", "mssql_waitfor"),
            ("' AND pg_sleep(3)--", "pg_sleep"),
        ]

        for payload, technique in time_payloads:
            try:
                start = time.time()
                if method.upper() == "GET":
                    self.session.get(endpoint, params={target_param: payload})
                else:
                    self.session.post(endpoint, data={target_param: payload})
                elapsed = time.time() - start

                if elapsed >= 2.5:
                    findings.append(Finding(
                        title=f"Blind SQL Injection (time-based) in {endpoint}",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.LIKELY,
                        category="sqli",
                        description=(
                            f"Response delayed by {elapsed:.1f}s with time-based payload. "
                            f"Technique: {technique}"
                        ),
                        mode=ScanMode.DAST,
                        endpoint=endpoint,
                        method=method,
                        payload=payload,
                        evidence=f"Response time: {elapsed:.1f}s (expected ≥3s)",
                        cvss_estimate=9.8,
                    ))
                    break  # One time-based finding is enough

            except Exception:
                continue

        return findings
