"""
Auth pattern scanner (SAST) — broken auth, missing auth checks, hardcoded creds.
"""

from __future__ import annotations

from senshi.sast.scanners.base import BaseSastScanner
from senshi.sast.file_parser import ParsedFile


class AuthPatternScanner(BaseSastScanner):
    """Find authentication and authorization issues in source code."""

    def get_scanner_name(self) -> str:
        return "SAST Auth Scanner"

    def get_analysis_prompt(self) -> str:
        return (
            "Focus specifically on AUTHENTICATION and AUTHORIZATION vulnerabilities: "
            "missing auth checks on routes, hardcoded credentials, insecure session handling, "
            "broken access control, privilege escalation, JWT issues, "
            "and insecure password storage."
        )

    def filter_relevant_files(self) -> list[ParsedFile]:
        keywords = [
            "auth", "login", "password", "session", "token", "jwt",
            "oauth", "permission", "role", "admin", "user", "credential",
            "cookie", "bearer", "api_key", "secret", "hash", "bcrypt",
        ]
        return [
            f for f in self.files
            if any(kw in f.content.lower() for kw in keywords)
        ]
