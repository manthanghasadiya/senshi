"""
PentestContext — accumulates ALL knowledge across the agent loop.

Stores tech stack, endpoints, params, tests performed, findings,
auth info, and observations. Provides compressed summaries for LLM prompts
that stay within token budgets.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from senshi.reporters.models import Finding


@dataclass
class Observation:
    """A single observation from an action."""

    action_type: str
    target: str
    result_summary: str
    is_interesting: bool = False
    timestamp: float = field(default_factory=time.time)
    raw_data: dict[str, Any] = field(default_factory=dict)


@dataclass
class TestRecord:
    """Record of a test that was performed."""

    action_type: str
    endpoint: str
    vuln_type: str = ""
    params_tested: list[str] = field(default_factory=list)
    result: str = ""  # "negative", "interesting", "confirmed"
    timestamp: float = field(default_factory=time.time)


class PentestContext:
    """
    Accumulates ALL knowledge across the pentest agent loop.

    This is the agent's memory — everything it knows about the target,
    what it's tested, what it's found, and what it should test next.
    """

    def __init__(self, target: str, max_context_tokens: int = 8000) -> None:
        self.target = target
        self.max_context_tokens = max_context_tokens
        self.start_time = datetime.now().isoformat()

        # Knowledge
        self.tech_stack: dict[str, Any] = {}
        self.endpoints: list[dict[str, Any]] = []
        self.auth_info: dict[str, Any] = {}
        self.scope_rules: list[str] = []

        # History
        self.observations: list[Observation] = []
        self.tests_performed: list[TestRecord] = []
        self.findings: list[Finding] = []
        self.failed_tests: list[dict[str, str]] = []

        # Stats
        self.iteration: int = 0
        self.llm_calls: int = 0
        self.http_requests: int = 0

    # ── Mutation ─────────────────────────────────────────────

    def add_endpoints(self, endpoints: list[dict[str, Any]]) -> None:
        """Add discovered endpoints (deduplicates by url+method)."""
        seen = {(ep["url"], ep.get("method", "GET")) for ep in self.endpoints}
        for ep in endpoints:
            key = (ep["url"], ep.get("method", "GET"))
            if key not in seen:
                self.endpoints.append(ep)
                seen.add(key)

    def add_observation(self, action_type: str, target: str,
                        result_summary: str, is_interesting: bool = False,
                        raw_data: dict[str, Any] | None = None) -> None:
        """Record an observation from an action."""
        self.observations.append(Observation(
            action_type=action_type,
            target=target,
            result_summary=result_summary,
            is_interesting=is_interesting,
            raw_data=raw_data or {},
        ))

    def add_finding(self, finding: Finding) -> None:
        """Add a confirmed finding (deduplicated)."""
        for f in self.findings:
            if f.endpoint == finding.endpoint and f.category == finding.category and f.payload == finding.payload:
                return
        self.findings.append(finding)

    def mark_tested(self, endpoint: str, vuln_type: str,
                    result: str = "negative",
                    params: list[str] | None = None) -> None:
        """Record that a test was performed."""
        self.tests_performed.append(TestRecord(
            action_type="scan",
            endpoint=endpoint,
            vuln_type=vuln_type,
            params_tested=params or [],
            result=result,
        ))

    def was_tested(self, endpoint: str, vuln_type: str) -> bool:
        """Check if a specific test was already performed."""
        return any(
            t.endpoint == endpoint and t.vuln_type == vuln_type
            for t in self.tests_performed
        )

    # ── Summaries for LLM ────────────────────────────────────

    def get_summary(self) -> str:
        """Get full context summary for LLM prompt (token-aware)."""
        parts = [
            f"TARGET: {self.target}",
            f"ITERATION: {self.iteration}",
            "",
            self._tech_summary(),
            self._endpoints_summary(),
            self._tests_summary(),
            self._findings_summary(),
            self._observations_summary(),
        ]
        full = "\n".join(parts)

        # Rough token estimate (4 chars ≈ 1 token)
        if len(full) > self.max_context_tokens * 4:
            return self._compressed_summary()
        return full

    @property
    def tech_summary(self) -> str:
        return self._tech_summary()

    @property
    def endpoints_summary(self) -> str:
        return self._endpoints_summary()

    @property
    def findings_summary(self) -> str:
        return self._findings_summary()

    @property
    def params_summary(self) -> str:
        all_params: set[str] = set()
        for ep in self.endpoints:
            all_params.update(ep.get("params", []))
        return ", ".join(sorted(all_params)[:30]) if all_params else "none discovered"

    def _tech_summary(self) -> str:
        if not self.tech_stack:
            return "TECH STACK: Unknown"
        parts = []
        for k, v in self.tech_stack.items():
            if v:
                parts.append(f"{k}: {v}")
        return "TECH STACK: " + ", ".join(parts) if parts else "TECH STACK: Unknown"

    def _endpoints_summary(self) -> str:
        if not self.endpoints:
            return "ENDPOINTS: None discovered"
        lines = [f"ENDPOINTS ({len(self.endpoints)} total):"]
        # Show untested first, limit to 20
        untested = [ep for ep in self.endpoints if not self._is_fully_tested(ep)]
        tested = [ep for ep in self.endpoints if self._is_fully_tested(ep)]

        for ep in untested[:15]:
            params = ", ".join(ep.get("params", []))
            mark = " [UNTESTED]"
            lines.append(f"  {ep.get('method', 'GET'):4s} {ep['url']}"
                         f"{' (' + params + ')' if params else ''}{mark}")

        if tested:
            lines.append(f"  ... and {len(tested)} fully tested endpoints")
        return "\n".join(lines)

    def _tests_summary(self) -> str:
        if not self.tests_performed:
            return "TESTS PERFORMED: None"
        # Group by result
        negative = [t for t in self.tests_performed if t.result == "negative"]
        interesting = [t for t in self.tests_performed if t.result == "interesting"]
        confirmed = [t for t in self.tests_performed if t.result == "confirmed"]

        lines = [f"TESTS PERFORMED ({len(self.tests_performed)} total):"]
        if confirmed:
            lines.append(f"  ✓ {len(confirmed)} confirmed vulnerabilities")
        if interesting:
            for t in interesting[-5:]:
                lines.append(f"  ⚠ {t.vuln_type} on {t.endpoint} — interesting")
        if negative:
            lines.append(f"  ✗ {len(negative)} negative results")
        return "\n".join(lines)

    def _findings_summary(self) -> str:
        if not self.findings:
            return "CONFIRMED FINDINGS: None yet"
        
        lines = ["✅ CONFIRMED FINDINGS (do not retest these endpoints for these vuln types):"]
        for f in self.findings:
            lines.append(f"  ✓ {f.category.upper()} on {f.endpoint} — CONFIRMED")
        return "\n".join(lines)

    def _observations_summary(self) -> str:
        lines = []
        
        # Make failed tests VERY prominent
        if self.failed_tests:
            lines.append("⛔ BLOCKED COMBINATIONS — DO NOT TEST THESE AGAIN:")
            
            # Group by endpoint+vuln_type to show clearly
            tested_combos = set()
            for ft in self.failed_tests:
                combo = f"{ft.get('endpoint', '?')} + {ft.get('vuln_type', '?')}"
                tested_combos.add(combo)
            
            for combo in list(tested_combos)[-10:]:  # Last 10
                lines.append(f"  ⛔ {combo}: ALREADY TESTED, NO ISSUES")
            
            lines.append("")
            lines.append("  → Choose an endpoint+vuln_type combination NOT in the list above")
            lines.append("")
        
        if self.observations:
            lines.append("RECENT OBSERVATIONS:")
            for obs in self.observations[-5:]:
                mark = "⚠" if obs.is_interesting else "ℹ"
                lines.append(f"  {mark} {obs.result_summary}")
        
        return "\n".join(lines) if lines else ""

    def _compressed_summary(self) -> str:
        """Compressed summary when context is too large."""
        return "\n".join([
            f"TARGET: {self.target}",
            f"ITERATION: {self.iteration}",
            self._tech_summary(),
            f"ENDPOINTS: {len(self.endpoints)} discovered, "
            f"{len([e for e in self.endpoints if not self._is_fully_tested(e)])} untested",
            f"TESTS: {len(self.tests_performed)} performed",
            self._findings_summary(),
            f"OBSERVATIONS: {len(self.observations)} total",
            "",
            "RECENT (last 5):",
            *[f"  {obs.action_type}: {obs.result_summary}"
              for obs in self.observations[-5:]],
        ])

    def _is_fully_tested(self, ep: dict[str, Any]) -> bool:
        """Check if an endpoint has been tested for all major vuln types."""
        major_types = {"xss", "sqli", "ssrf", "idor", "auth"}
        tested_types = {
            t.vuln_type for t in self.tests_performed
            if t.endpoint == ep["url"]
        }
        return len(tested_types & major_types) >= 3

    # ── Serialization ────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        """Serialize full context for progressive save."""
        return {
            "target": self.target,
            "start_time": self.start_time,
            "iteration": self.iteration,
            "tech_stack": self.tech_stack,
            "endpoints": self.endpoints,
            "findings_count": len(self.findings),
            "tests_count": len(self.tests_performed),
            "observations_count": len(self.observations),
            "llm_calls": self.llm_calls,
            "http_requests": self.http_requests,
        }
