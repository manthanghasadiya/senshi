"""
False positive filter — 2nd LLM pass to eliminate false positives.

Every finding goes through this skeptical reviewer before being reported.
"""

from __future__ import annotations

import json

from senshi.ai.brain import Brain
from senshi.ai.prompts.false_positive import (
    BATCH_FP_SYSTEM_PROMPT,
    FALSE_POSITIVE_SYSTEM_PROMPT,
)
from senshi.reporters.models import Confidence, Finding, Severity
from senshi.utils.logger import get_logger

logger = get_logger("senshi.ai.false_positive_filter")


class FalsePositiveFilter:
    """Filter false positives using a skeptical LLM reviewer."""

    def __init__(self, brain: Brain) -> None:
        self.brain = brain

    def validate_finding(self, finding: Finding) -> Finding | None:
        """
        Validate a single finding. Returns the finding (possibly modified)
        if confirmed, or None if rejected as false positive.
        """
        finding_json = json.dumps(finding.to_dict(), indent=2)

        system_prompt = FALSE_POSITIVE_SYSTEM_PROMPT.format(
            finding_json=finding_json
        )

        user_prompt = (
            "Review this finding critically. Is this a real vulnerability "
            "or a false positive? Be skeptical."
        )

        try:
            result = self.brain.think(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                json_schema={"type": "object"},
            )

            if not isinstance(result, dict):
                return finding  # Keep on error

            verdict = result.get("verdict", "confirmed")

            if verdict == "reject":
                reason = result.get("if_rejected", "Rejected by FP filter")
                logger.debug(f"Rejected: {finding.title} — {reason}")
                return None

            # Apply revisions if downgraded
            if verdict == "downgrade" or verdict == "confirmed":
                revised_severity = result.get("revised_severity", "")
                revised_confidence = result.get("revised_confidence", "")

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

                if revised_severity in severity_map:
                    finding.severity = severity_map[revised_severity]
                if revised_confidence in confidence_map:
                    finding.confidence = confidence_map[revised_confidence]

                return finding

            return finding

        except Exception as e:
            logger.warning(f"FP filter error: {e}, keeping finding")
            return finding

    def validate_batch(self, findings: list[Finding]) -> list[Finding]:
        """
        Validate a batch of findings at once.

        More efficient than individual validation and allows
        the LLM to detect duplicates across findings.
        """
        if not findings:
            return []

        if len(findings) <= 3:
            # Small batch — validate individually for accuracy
            validated = []
            for finding in findings:
                result = self.validate_finding(finding)
                if result is not None:
                    validated.append(result)
            return validated

        # Larger batch — use batch prompt
        findings_json = json.dumps(
            [f.to_dict() for f in findings], indent=2
        )

        system_prompt = BATCH_FP_SYSTEM_PROMPT.format(
            findings_json=findings_json
        )

        user_prompt = (
            f"Review these {len(findings)} findings. Reject false positives, "
            "identify duplicates, and adjust severity/confidence as needed."
        )

        try:
            result = self.brain.think(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                json_schema={"type": "object"},
            )

            if not isinstance(result, dict):
                return findings

            reviews = result.get("reviews", [])
            duplicates = result.get("duplicates", [])

            # Build set of rejected and duplicate indices
            rejected_indices: set[int] = set()
            for review in reviews:
                idx = review.get("finding_index", -1)
                if review.get("verdict") == "reject" and 0 <= idx < len(findings):
                    rejected_indices.add(idx)

            # Mark duplicate indices (keep first, remove rest)
            for dup_group in duplicates:
                indices = dup_group.get("indices", [])
                for idx in indices[1:]:  # Keep first, remove rest
                    if 0 <= idx < len(findings):
                        rejected_indices.add(idx)

            # Apply revisions and filter
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

            validated = []
            for i, finding in enumerate(findings):
                if i in rejected_indices:
                    continue

                # Apply revisions from review
                for review in reviews:
                    if review.get("finding_index") == i:
                        sev = review.get("revised_severity", "")
                        conf = review.get("revised_confidence", "")
                        if sev in severity_map:
                            finding.severity = severity_map[sev]
                        if conf in confidence_map:
                            finding.confidence = confidence_map[conf]
                        break

                validated.append(finding)

            logger.info(
                f"FP filter: {len(findings)} → {len(validated)} findings "
                f"({len(findings) - len(validated)} rejected)"
            )
            return validated

        except Exception as e:
            logger.warning(f"Batch FP filter error: {e}, keeping all findings")
            return findings
