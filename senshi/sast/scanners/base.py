"""
Base SAST scanner — all SAST scanners inherit from this.

Pattern:
1. Load and parse source files
2. Build context (imports, functions, routes, data flow)
3. Send code chunks to LLM with security-focused prompts
4. LLM identifies potential vulnerabilities
5. Validation LLM confirms or rejects
6. Return findings with file/line references
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from senshi.ai.brain import Brain
from senshi.ai.code_analyzer import CodeAnalyzer
from senshi.ai.false_positive_filter import FalsePositiveFilter
from senshi.reporters.models import Finding
from senshi.sast.context_builder import CodeContext
from senshi.sast.file_parser import ParsedFile
from senshi.utils.logger import get_logger, print_finding

logger = get_logger("senshi.sast.scanners.base")


class BaseSastScanner(ABC):
    """
    Base class for all SAST scanners.

    Subclasses must implement:
    - get_scanner_name() -> str
    - get_analysis_prompt() -> str
    """

    def __init__(
        self,
        brain: Brain,
        files: list[ParsedFile],
        context: CodeContext,
    ) -> None:
        self.brain = brain
        self.files = files
        self.context = context

        self.code_analyzer = CodeAnalyzer(brain)
        self.fp_filter = FalsePositiveFilter(brain)
        self.findings: list[Finding] = []

    @abstractmethod
    def get_scanner_name(self) -> str:
        """Return scanner display name."""
        ...

    @abstractmethod
    def get_analysis_prompt(self) -> str:
        """Return additional analysis prompt for this scanner type."""
        ...

    def filter_relevant_files(self) -> list[ParsedFile]:
        """Filter files relevant to this scanner. Override for specifics."""
        return self.files

    def analyze_files(self) -> list[Finding]:
        """Send files to LLM for analysis in batches."""
        relevant_files = self.filter_relevant_files()

        if not relevant_files:
            logger.info(f"{self.get_scanner_name()}: No relevant files found")
            return []

        logger.info(
            f"{self.get_scanner_name()}: Analyzing {len(relevant_files)} files"
        )

        # Build file dicts for batch analysis
        file_dicts = [
            {"path": f.path, "content": f.content}
            for f in relevant_files
        ]

        findings = self.code_analyzer.batch_analyze(
            files=file_dicts,
            language=self.context.language,
            framework=self.context.framework,
            app_description=self.context.app_description,
        )

        for finding in findings:
            print_finding(
                finding.severity.value,
                finding.title,
                finding.file_path,
            )

        return findings

    def validate_findings(self, findings: list[Finding]) -> list[Finding]:
        """2nd pass validation with code context."""
        if not findings:
            return []

        return self.fp_filter.validate_batch(findings)

    def scan(self) -> list[Finding]:
        """Full SAST scan pipeline."""
        scanner_name = self.get_scanner_name()
        logger.info(f"{scanner_name}: Starting scan")

        raw = self.analyze_files()
        validated = self.validate_findings(raw)
        self.findings = validated

        logger.info(
            f"✓ {scanner_name}: {len(validated)} findings "
            f"({len(raw) - len(validated)} rejected)"
        )

        return validated
