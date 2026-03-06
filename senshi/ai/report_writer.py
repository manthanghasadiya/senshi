"""
LLM-powered report writer — generates bounty-ready vulnerability reports.
"""

from __future__ import annotations

import json

from senshi.ai.brain import Brain
from senshi.reporters.models import Finding
from senshi.utils.logger import get_logger

logger = get_logger("senshi.ai.report_writer")

REPORT_SYSTEM_PROMPT = """You are an expert bug bounty hunter writing a vulnerability report.

Write a professional, clear, and compelling vulnerability report suitable for
submission to a bug bounty program. The report should convince the security
team that this is a real, impactful vulnerability.

REPORT STRUCTURE:
1. **Title**: Clear, specific title
2. **Severity**: With CVSS justification
3. **Summary**: 2-3 sentence overview
4. **Impact**: What an attacker can achieve
5. **Steps to Reproduce**: Exact, reproducible steps
6. **Proof of Concept**: Technical evidence
7. **Remediation**: How to fix it
8. **References**: Relevant CWEs, CVEs, or documentation

WRITING GUIDELINES:
- Be concise but thorough
- Use technical language appropriately
- Include all evidence
- Don't sensationalize — let the impact speak
- Format for markdown rendering"""


class ReportWriter:
    """Generate bounty-ready reports from findings."""

    def __init__(self, brain: Brain) -> None:
        self.brain = brain

    def write_finding_report(
        self,
        finding: Finding,
        target: str = "",
        platform: str = "",
    ) -> str:
        """
        Generate a detailed report for a single finding.

        Args:
            finding: The finding to report on.
            target: Target URL or project.
            platform: Bug bounty platform (msrc, hackerone, bugcrowd).

        Returns:
            Markdown-formatted report string.
        """
        finding_json = json.dumps(finding.to_dict(), indent=2)

        user_prompt = (
            f"Write a bug bounty report for this finding.\n\n"
            f"Target: {target or 'Web application'}\n"
            f"Platform: {platform or 'General'}\n\n"
            f"FINDING:\n{finding_json}"
        )

        try:
            result = self.brain.think(
                system_prompt=REPORT_SYSTEM_PROMPT,
                user_prompt=user_prompt,
                temperature=0.3,
            )
            return str(result)
        except Exception as e:
            logger.warning(f"Report generation failed: {e}")
            return self._fallback_report(finding)

    def write_scan_summary(
        self,
        findings: list[Finding],
        chains: list[dict] | None = None,
        target: str = "",
    ) -> str:
        """
        Generate an executive summary of all scan findings.

        Returns markdown string.
        """
        findings_summary = json.dumps(
            [
                {
                    "title": f.title,
                    "severity": f.severity.value,
                    "confidence": f.confidence.value,
                    "category": f.category,
                }
                for f in findings
            ],
            indent=2,
        )

        user_prompt = (
            f"Write an executive summary for a security scan.\n\n"
            f"Target: {target or 'Web application'}\n"
            f"Total findings: {len(findings)}\n\n"
            f"FINDINGS:\n{findings_summary}\n\n"
        )

        if chains:
            user_prompt += f"EXPLOIT CHAINS:\n{json.dumps(chains, indent=2)}\n"

        try:
            result = self.brain.think(
                system_prompt=REPORT_SYSTEM_PROMPT,
                user_prompt=user_prompt,
                temperature=0.3,
            )
            return str(result)
        except Exception as e:
            logger.warning(f"Summary generation failed: {e}")
            return f"# Scan Summary\n\n{len(findings)} findings discovered.\n"

    def _fallback_report(self, finding: Finding) -> str:
        """Generate a basic report without LLM."""
        return f"""# {finding.title}

**Severity**: {finding.severity.value.upper()}
**Confidence**: {finding.confidence.value}
**Category**: {finding.category}

## Description

{finding.description}

## Evidence

{finding.evidence}

## Location

- **Endpoint**: {finding.endpoint or 'N/A'}
- **File**: {finding.file_path or 'N/A'}
- **Line**: {finding.line_number or 'N/A'}
- **Payload**: `{finding.payload or 'N/A'}`

## LLM Reasoning

{finding.llm_reasoning}

## Remediation

{finding.remediation}

## CVSS Estimate

{finding.cvss_estimate}
"""
