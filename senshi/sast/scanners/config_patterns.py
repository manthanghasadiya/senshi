"""
Config pattern scanner (SAST) — misconfigurations, debug mode, CORS issues.
"""

from __future__ import annotations

from senshi.sast.scanners.base import BaseSastScanner
from senshi.sast.file_parser import ParsedFile


class ConfigPatternScanner(BaseSastScanner):
    """Find security misconfigurations in source code."""

    def get_scanner_name(self) -> str:
        return "SAST Config Scanner"

    def get_analysis_prompt(self) -> str:
        return (
            "Focus specifically on CONFIGURATION vulnerabilities: "
            "debug mode enabled in production, insecure CORS configuration, "
            "missing security headers, verbose error messages, "
            "exposed admin interfaces, insecure default settings, "
            "permissive file permissions, and missing rate limiting."
        )

    def filter_relevant_files(self) -> list[ParsedFile]:
        keywords = [
            "config", "settings", "debug", "cors", "helmet", "csp",
            "header", "middleware", "env", "production", "development",
            "allow_origin", "access-control", "x-frame", "x-content-type",
            "rate_limit", "throttle",
        ]
        return [
            f for f in self.files
            if any(kw in f.content.lower() for kw in keywords)
        ]
