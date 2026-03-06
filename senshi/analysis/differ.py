"""
ResponseDiffer — compare HTTP responses to detect security anomalies.

Compares baseline vs payload responses to find:
- Status code changes
- Body length differences
- New content appearing
- Headers changing
- Timing differences
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class DiffResult:
    """Result of comparing two HTTP responses."""

    status_changed: bool = False
    status_from: int = 0
    status_to: int = 0
    body_len_delta: int = 0
    body_len_ratio: float = 1.0
    new_content: list[str] = field(default_factory=list)
    removed_content: list[str] = field(default_factory=list)
    headers_changed: list[str] = field(default_factory=list)
    timing_delta_ms: float = 0.0
    is_significant: bool = False
    significance_reasons: list[str] = field(default_factory=list)


class ResponseDiffer:
    """Compare HTTP responses to detect security-relevant changes."""

    # Error patterns that indicate a vulnerability
    SQL_ERRORS = re.compile(
        r"(sql|mysql|postgresql|oracle|sqlite|syntax error|"
        r"unclosed quotation|ORA-\d|SQLSTATE|"
        r"You have an error in your SQL|"
        r"Warning: mysql_|pg_query|ODBC SQL Server Driver)",
        re.IGNORECASE,
    )

    TEMPLATE_ERRORS = re.compile(
        r"(TemplateSyntaxError|Jinja2|jinja2|Mako|"
        r"freemarker|velocity|twig|ERB|Smarty|"
        r"\{\{.*\}\}|<%= .*%>)",
        re.IGNORECASE,
    )

    SERVER_ERRORS = re.compile(
        r"(Traceback|stack trace|at [\w.]+\(|"
        r"Exception in thread|ASP\.NET|"
        r"Internal Server Error|Debug|debug_mode)",
        re.IGNORECASE,
    )

    def diff(
        self,
        baseline_status: int,
        baseline_body: str,
        baseline_headers: dict[str, str],
        baseline_time_ms: float,
        payload_status: int,
        payload_body: str,
        payload_headers: dict[str, str],
        payload_time_ms: float,
    ) -> DiffResult:
        """Compare baseline vs payload response."""
        result = DiffResult()

        # Status code
        if baseline_status != payload_status:
            result.status_changed = True
            result.status_from = baseline_status
            result.status_to = payload_status
            if payload_status >= 500:
                result.is_significant = True
                result.significance_reasons.append(
                    f"Server error: {baseline_status} → {payload_status}"
                )

        # Body length
        base_len = len(baseline_body)
        pay_len = len(payload_body)
        result.body_len_delta = pay_len - base_len
        result.body_len_ratio = pay_len / base_len if base_len > 0 else float("inf")

        if abs(result.body_len_delta) > 500:
            result.is_significant = True
            result.significance_reasons.append(
                f"Body size change: {base_len} → {pay_len} ({result.body_len_delta:+d})"
            )

        # Content diff (new content in payload response)
        if base_len < 50000 and pay_len < 50000:
            baseline_lines = baseline_body.splitlines()
            payload_lines = payload_body.splitlines()
            differ = difflib.unified_diff(baseline_lines, payload_lines, lineterm="")
            for line in differ:
                if line.startswith("+") and not line.startswith("+++"):
                    result.new_content.append(line[1:].strip())
                elif line.startswith("-") and not line.startswith("---"):
                    result.removed_content.append(line[1:].strip())

        # Check for error patterns in new content
        new_text = "\n".join(result.new_content)
        if self.SQL_ERRORS.search(new_text):
            result.is_significant = True
            result.significance_reasons.append("SQL error detected in response")
        if self.TEMPLATE_ERRORS.search(new_text):
            result.is_significant = True
            result.significance_reasons.append("Template injection indicators detected")
        if self.SERVER_ERRORS.search(new_text):
            result.is_significant = True
            result.significance_reasons.append("Server debug/error info leaked")

        # Header changes
        for key in set(list(baseline_headers.keys()) + list(payload_headers.keys())):
            base_val = baseline_headers.get(key, "")
            pay_val = payload_headers.get(key, "")
            if base_val != pay_val:
                result.headers_changed.append(f"{key}: {base_val!r} → {pay_val!r}")

        # Timing (blind injection indicator)
        result.timing_delta_ms = payload_time_ms - baseline_time_ms
        if result.timing_delta_ms > 5000:
            result.is_significant = True
            result.significance_reasons.append(
                f"Timing anomaly: +{result.timing_delta_ms:.0f}ms (possible blind injection)"
            )

        return result

    def quick_diff(
        self, baseline_body: str, payload_body: str
    ) -> tuple[bool, str]:
        """
        Quick boolean diff — is the payload response significantly different?

        Returns (is_different, reason).
        """
        if abs(len(baseline_body) - len(payload_body)) > 200:
            return True, f"Body length: {len(baseline_body)} vs {len(payload_body)}"

        if self.SQL_ERRORS.search(payload_body) and not self.SQL_ERRORS.search(baseline_body):
            return True, "SQL error appeared"

        if self.SERVER_ERRORS.search(payload_body) and not self.SERVER_ERRORS.search(baseline_body):
            return True, "Server error appeared"

        return False, ""
