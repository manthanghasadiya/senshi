"""
Chain builder — identify and compose exploit chains from individual findings.

Chains individual vulnerabilities into high-impact attack paths.
"""

from __future__ import annotations

import json
from typing import Any

from senshi.ai.brain import Brain
from senshi.ai.prompts.chain_builder import CHAIN_BUILDER_SYSTEM_PROMPT
from senshi.reporters.models import Finding
from senshi.utils.logger import get_logger

logger = get_logger("senshi.ai.chain_builder")


class ChainBuilder:
    """Build exploit chains from individual findings."""

    def __init__(self, brain: Brain) -> None:
        self.brain = brain

    def build_chains(
        self,
        findings: list[Finding],
        target_description: str = "",
    ) -> list[dict[str, Any]]:
        """
        Analyze findings and identify exploit chains.

        Args:
            findings: All validated findings from the scan.
            target_description: Description of the target.

        Returns:
            List of chain dicts with steps, impact, CVSS, and narratives.
        """
        if len(findings) < 2:
            logger.debug("Need at least 2 findings to build chains")
            return []

        findings_json = json.dumps(
            [f.to_dict() for f in findings], indent=2
        )

        system_prompt = CHAIN_BUILDER_SYSTEM_PROMPT.format(
            all_findings_json=findings_json,
            target_description=target_description or "Web application",
        )

        user_prompt = (
            f"Analyze these {len(findings)} findings and identify potential "
            "exploit chains. Focus on realistic attack paths that combine "
            "multiple vulnerabilities for higher impact."
        )

        try:
            result = self.brain.think(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                json_schema={"type": "object"},
                temperature=0.2,
            )

            if isinstance(result, dict):
                chains = result.get("chains", [])
                logger.info(f"Found {len(chains)} potential exploit chains")
                return chains

            return []

        except Exception as e:
            logger.warning(f"Chain building failed: {e}")
            return []
