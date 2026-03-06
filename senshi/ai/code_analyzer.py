"""
LLM code analyzer — analyze source code for vulnerabilities (SAST).

Sends code chunks to the LLM with security-focused analysis prompts.
"""

from __future__ import annotations

import json
from typing import Any

from senshi.ai.brain import Brain
from senshi.ai.prompts.sast_analysis import SAST_ANALYSIS_SYSTEM_PROMPT
from senshi.reporters.models import Confidence, Finding, ScanMode, Severity
from senshi.utils.logger import get_logger

logger = get_logger("senshi.ai.code_analyzer")


class CodeAnalyzer:
    """Analyze source code for vulnerabilities using LLM."""

    def __init__(self, brain: Brain) -> None:
        self.brain = brain

    def analyze_code(
        self,
        code: str,
        file_path: str,
        language: str = "python",
        framework: str = "unknown",
        app_description: str = "",
        dependencies: str = "",
    ) -> list[Finding]:
        """
        Analyze a code chunk for security vulnerabilities.

        Args:
            code: Source code to analyze.
            file_path: Path to the file.
            language: Programming language.
            framework: Detected framework.
            app_description: Description of the application.
            dependencies: Known dependencies.

        Returns:
            List of Finding objects.
        """
        system_prompt = SAST_ANALYSIS_SYSTEM_PROMPT.format(
            language=language,
            framework=framework,
            file_path=file_path,
            app_description=app_description or "Application under review",
            dependencies=dependencies or "Not specified",
            code_chunk=code,
        )

        user_prompt = (
            f"Review the code in {file_path} for security vulnerabilities. "
            "Focus on real, exploitable issues. Do not report style or quality issues."
        )

        try:
            result = self.brain.think(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                json_schema={"type": "object"},
            )

            if isinstance(result, dict):
                findings_data = result.get("findings", [])
                return [
                    self._result_to_finding(f, file_path)
                    for f in findings_data
                    if isinstance(f, dict)
                ]

            return []

        except Exception as e:
            logger.warning(f"Code analysis failed for {file_path}: {e}")
            return []

    def batch_analyze(
        self,
        files: list[dict[str, str]],
        language: str = "python",
        framework: str = "unknown",
        app_description: str = "",
    ) -> list[Finding]:
        """
        Analyze multiple files concurrently.

        Args:
            files: List of {"path": str, "content": str} dicts.
            language: Programming language.
            framework: Detected framework.
            app_description: Description of the application.

        Returns:
            Combined list of Finding objects from all files.
        """
        prompts: list[tuple[str, str]] = []

        for file_info in files:
            system_prompt = SAST_ANALYSIS_SYSTEM_PROMPT.format(
                language=language,
                framework=framework,
                file_path=file_info["path"],
                app_description=app_description or "Application under review",
                dependencies="Not specified",
                code_chunk=file_info["content"],
            )

            user_prompt = (
                f"Review the code in {file_info['path']} for security vulnerabilities. "
                "Focus on real, exploitable issues."
            )

            prompts.append((system_prompt, user_prompt))

        results = self.brain.batch_think(
            prompts=prompts,
            json_schema={"type": "object"},
        )

        all_findings: list[Finding] = []
        for i, result in enumerate(results):
            if isinstance(result, dict) and "error" not in result:
                findings_data = result.get("findings", [])
                for f in findings_data:
                    if isinstance(f, dict):
                        all_findings.append(
                            self._result_to_finding(f, files[i]["path"])
                        )

        return all_findings

    def _result_to_finding(self, data: dict[str, Any], file_path: str) -> Finding:
        """Convert LLM analysis result to Finding object."""
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
        }
        confidence_map = {
            "confirmed": Confidence.CONFIRMED,
            "likely": Confidence.LIKELY,
            "possible": Confidence.POSSIBLE,
        }

        return Finding(
            title=data.get("title", "Code vulnerability"),
            severity=severity_map.get(data.get("severity", "medium"), Severity.MEDIUM),
            confidence=confidence_map.get(data.get("confidence", "possible"), Confidence.POSSIBLE),
            category=data.get("category", "unknown"),
            description=data.get("description", ""),
            mode=ScanMode.SAST,
            file_path=file_path,
            line_number=data.get("line_number", 0),
            code_snippet=data.get("code_snippet", ""),
            evidence=data.get("attack_scenario", ""),
            cvss_estimate=data.get("cvss_estimate", 0.0),
            remediation=data.get("remediation", ""),
            llm_reasoning=data.get("description", ""),
        )
