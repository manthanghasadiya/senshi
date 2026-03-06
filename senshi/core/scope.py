"""
ScopeManager — enforce in-scope/out-of-scope rules.

Prevents testing unauthorized assets. Critical for bug bounty programs
where testing out-of-scope assets can result in legal issues.
"""

from __future__ import annotations

import fnmatch
import re
from urllib.parse import urlparse

from senshi.utils.logger import get_logger

logger = get_logger("senshi.core.scope")


class ScopeManager:
    """
    Enforce in-scope/out-of-scope rules.

    Rules:
    - "*.copilot.microsoft.com" — include all subdomains
    - "!*.login.microsoft.com" — exclude login domain
    - "https://api.target.com/*" — include all paths on api.target.com
    """

    def __init__(self, rules: list[str] | None = None) -> None:
        self.include_rules: list[str] = []
        self.exclude_rules: list[str] = []

        if rules:
            for rule in rules:
                self.add_rule(rule)

    def add_rule(self, rule: str) -> None:
        """Add a scope rule. Prefix with ! for exclusion."""
        rule = rule.strip()
        if not rule:
            return

        if rule.startswith("!"):
            self.exclude_rules.append(rule[1:])
        else:
            self.include_rules.append(rule)

    def is_in_scope(self, url: str) -> bool:
        """
        Check if a URL is in scope.

        If no include rules are set, everything is in scope.
        Exclude rules always take precedence over include rules.
        """
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        full_url = url

        # Check exclusions first (always takes precedence)
        for rule in self.exclude_rules:
            if self._matches(hostname, full_url, rule):
                logger.debug(f"Out of scope (excluded): {url}")
                return False

        # If no include rules, everything is in scope
        if not self.include_rules:
            return True

        # Check inclusion rules
        for rule in self.include_rules:
            if self._matches(hostname, full_url, rule):
                return True

        logger.debug(f"Out of scope (not included): {url}")
        return False

    def filter_urls(self, urls: list[str]) -> list[str]:
        """Filter a list of URLs to only in-scope ones."""
        return [url for url in urls if self.is_in_scope(url)]

    @staticmethod
    def _matches(hostname: str, full_url: str, pattern: str) -> bool:
        """Check if a hostname/URL matches a scope pattern."""
        # Full URL pattern
        if "://" in pattern or "/" in pattern:
            return fnmatch.fnmatch(full_url, pattern)

        # Hostname pattern
        return fnmatch.fnmatch(hostname, pattern)

    @classmethod
    def from_target_profile(cls, profile: dict) -> ScopeManager:
        """Create ScopeManager from a target profile."""
        rules = profile.get("scope", [])
        return cls(rules=rules)

    def __repr__(self) -> str:
        return (
            f"ScopeManager(include={self.include_rules}, "
            f"exclude={self.exclude_rules})"
        )
