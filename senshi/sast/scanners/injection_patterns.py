"""
Injection pattern scanner (SAST) — SQLi, command injection, SSRF in source code.
"""

from __future__ import annotations

from senshi.sast.scanners.base import BaseSastScanner
from senshi.sast.file_parser import ParsedFile


class InjectionPatternScanner(BaseSastScanner):
    """Find injection vulnerabilities in source code."""

    def get_scanner_name(self) -> str:
        return "SAST Injection Scanner"

    def get_analysis_prompt(self) -> str:
        return (
            "Focus specifically on INJECTION vulnerabilities: "
            "SQL injection, command injection, SSRF, path traversal, "
            "template injection, LDAP injection, and NoSQL injection. "
            "Look for user input reaching dangerous sinks without sanitization."
        )

    def filter_relevant_files(self) -> list[ParsedFile]:
        """Filter to files likely containing injection sinks."""
        keywords = [
            "query", "execute", "exec", "system", "subprocess", "popen",
            "eval", "render", "template", "sql", "cursor", "command",
            "shell", "request", "url", "fetch", "http", "open",
            "path", "file", "read", "write", "include", "require",
        ]
        return [
            f for f in self.files
            if any(kw in f.content.lower() for kw in keywords)
        ]
