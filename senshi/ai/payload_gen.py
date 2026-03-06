"""
LLM-powered payload generator — generates context-aware payloads using Brain.

This replaces static wordlists with AI-generated, target-specific payloads.
"""

from __future__ import annotations

import json
from typing import Any

from senshi.ai.brain import Brain
from senshi.ai.prompts.payload_gen import (
    AI_PRODUCT_PAYLOAD_PROMPT,
    AUTH_PAYLOAD_PROMPT,
    DESERIALIZATION_PAYLOAD_PROMPT,
    IDOR_PAYLOAD_PROMPT,
    INJECTION_PAYLOAD_PROMPT,
    PAYLOAD_GEN_SYSTEM_PROMPT,
    SQLI_PAYLOAD_PROMPT,
    SSRF_PAYLOAD_PROMPT,
    XSS_PAYLOAD_PROMPT,
)
from senshi.utils.logger import get_logger
from senshi.utils.seed_payloads import get_seeds_for_category

logger = get_logger("senshi.ai.payload_gen")

# Map vulnerability class to its specialized prompt
VULN_PROMPTS: dict[str, str] = {
    "xss": XSS_PAYLOAD_PROMPT,
    "ssrf": SSRF_PAYLOAD_PROMPT,
    "sqli": SQLI_PAYLOAD_PROMPT,
    "idor": IDOR_PAYLOAD_PROMPT,
    "injection": INJECTION_PAYLOAD_PROMPT,
    "auth": AUTH_PAYLOAD_PROMPT,
    "deserialization": DESERIALIZATION_PAYLOAD_PROMPT,
    "ai_product": AI_PRODUCT_PAYLOAD_PROMPT,
}


class PayloadGenerator:
    """Generate context-aware payloads using LLM."""

    def __init__(self, brain: Brain) -> None:
        self.brain = brain

    def generate(
        self,
        vulnerability_class: str,
        endpoint: str,
        method: str = "GET",
        parameters: list[str] | None = None,
        tech_stack: str = "unknown",
        app_description: str = "",
        previous_findings: str = "",
        count: int = 15,
    ) -> list[dict[str, Any]]:
        """
        Generate payloads for a specific vulnerability class.

        Args:
            vulnerability_class: e.g., "xss", "ssrf", "sqli"
            endpoint: Target URL
            method: HTTP method
            parameters: Known parameters
            tech_stack: Detected technology stack
            app_description: Description of the application
            previous_findings: Previously found vulns for context
            count: Number of payloads to generate

        Returns:
            List of payload dicts with value, injection_point, technique, etc.
        """
        # Get seed payloads for inspiration
        seeds = get_seeds_for_category(vulnerability_class)
        seed_text = json.dumps(seeds[:5], indent=2) if seeds else "None available"

        # Get specialized prompt for this vuln class
        vuln_prompt = VULN_PROMPTS.get(vulnerability_class, "")

        # Build the system prompt
        system_prompt = PAYLOAD_GEN_SYSTEM_PROMPT.format(
            method=method,
            url=endpoint,
            parameters=json.dumps(parameters or []),
            tech_stack=tech_stack,
            app_description=app_description or "Web application",
            previous_findings=previous_findings or "None yet",
            count=count,
            vulnerability_class=vulnerability_class,
        )

        # Build user prompt with vuln-specific details
        user_prompt = vuln_prompt.format(seed_payloads=seed_text) if vuln_prompt else (
            f"Generate {count} {vulnerability_class} payloads for {method} {endpoint} "
            f"with parameters: {parameters}. Tech stack: {tech_stack}."
        )

        logger.debug(f"Generating {count} {vulnerability_class} payloads for {endpoint}")

        try:
            result = self.brain.think(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                json_schema={"type": "object"},
                temperature=0.3,  # Slightly creative for diverse payloads
            )

            if isinstance(result, dict):
                payloads = result.get("payloads", [])
                logger.debug(f"Generated {len(payloads)} payloads")
                return payloads

            return []

        except Exception as e:
            logger.warning(f"Payload generation failed: {e}")
            # Fall back to seed payloads
            return [
                {
                    "value": s if isinstance(s, str) else json.dumps(s),
                    "injection_point": parameters[0] if parameters else "body",
                    "technique": "seed_fallback",
                    "expected_indicator": "response change",
                    "bypass_method": "none",
                }
                for s in seeds[:count]
            ]
