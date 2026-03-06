"""
Senshi data models — Finding, Severity, Confidence, ScanMode.

All scan results flow through these models. Used by every scanner,
reporter, and the chain builder.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Vulnerability severity levels aligned with CVSS ranges."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }[self]

    def __lt__(self, other: Severity) -> bool:
        return self.rank < other.rank


class Confidence(str, Enum):
    """Finding confidence levels."""

    CONFIRMED = "confirmed"
    LIKELY = "likely"
    POSSIBLE = "possible"


class ScanMode(str, Enum):
    """Scan mode — DAST (live) or SAST (source)."""

    DAST = "dast"
    SAST = "sast"


class Finding(BaseModel):
    """
    A single security finding from DAST or SAST scanning.

    Every scanner produces Finding objects. These flow through the
    false-positive filter, chain builder, and reporters.
    """

    title: str
    severity: Severity
    confidence: Confidence
    category: str = ""  # xss, ssrf, idor, sqli, auth, etc.
    description: str = ""
    mode: ScanMode = ScanMode.DAST

    # DAST-specific
    endpoint: str = ""
    method: str = ""
    payload: str = ""
    response_snippet: str = ""
    status_code: int = 0

    # SAST-specific
    file_path: str = ""
    line_number: int = 0
    code_snippet: str = ""

    # Common
    evidence: str = ""
    cvss_estimate: float = 0.0
    remediation: str = ""
    llm_reasoning: str = ""
    chain_potential: str = ""

    # v0.3.0 — PoC and exploit confirmation
    poc_curl: str = ""
    poc_python: str = ""
    poc_steps: list[str] = Field(default_factory=list)
    screenshot_path: str = ""
    confirmed: bool = False

    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for JSON output."""
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        """Deserialize from dictionary."""
        return cls.model_validate(data)

    def summary_line(self) -> str:
        """One-line summary for CLI output."""
        location = self.endpoint or self.file_path or "unknown"
        return f"[{self.severity.value.upper()}] {self.title} — {location}"


class ScanState:
    """Persistent scan state that survives interrupts.

    Writes findings to disk as they're discovered so nothing is lost
    on Ctrl+C or crash.
    """

    def __init__(self, output_path: str) -> None:
        import json as _json  # noqa: avoid circular
        from pathlib import Path as _Path

        self._json = _json
        self._Path = _Path
        self.output_path = output_path
        self.findings: list[Finding] = []
        self.scanned_endpoints: list[str] = []
        self.start_time = datetime.now().isoformat()
        self.status = "running"
        self.llm_calls = 0

    def add_finding(self, finding: Finding) -> None:
        """Add finding and immediately save to disk."""
        self.findings.append(finding)
        self._save()

    def add_findings(self, findings: list[Finding]) -> None:
        """Add multiple findings and save."""
        self.findings.extend(findings)
        self._save()

    def mark_endpoint_done(self, endpoint: str) -> None:
        self.scanned_endpoints.append(endpoint)
        self._save()

    def _save(self) -> None:
        """Write current state to JSON file."""
        data = {
            "status": self.status,
            "start_time": self.start_time,
            "findings_count": len(self.findings),
            "scanned_endpoints": self.scanned_endpoints,
            "llm_calls": self.llm_calls,
            "findings": [f.to_dict() for f in self.findings],
        }
        self._Path(self.output_path).write_text(
            self._json.dumps(data, indent=2, default=str)
        )

    def complete(self) -> None:
        self.status = "complete"
        self._save()

    def interrupt(self) -> None:
        self.status = "interrupted"
        self._save()


class ScanResult(BaseModel):
    """Container for a complete scan's results."""

    target: str = ""
    mode: ScanMode = ScanMode.DAST
    started_at: str = Field(default_factory=lambda: datetime.now().isoformat())
    completed_at: str = ""
    findings: list[Finding] = Field(default_factory=list)
    chains: list[dict[str, Any]] = Field(default_factory=list)
    endpoints_discovered: int = 0
    files_analyzed: int = 0
    provider: str = ""
    model: str = ""

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")
