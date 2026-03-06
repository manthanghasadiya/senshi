"""
PoCGenerator — generate reproducible proof-of-concept for each finding.

Generates three formats: curl command, Python script, browser steps.
Auth tokens are masked with <AUTH_TOKEN> placeholder.
"""

from __future__ import annotations

from typing import Any

from senshi.ai.brain import Brain
from senshi.reporters.models import Finding
from senshi.utils.logger import get_logger

logger = get_logger("senshi.poc.generator")

POC_SYSTEM_PROMPT = """You are a security researcher generating proof-of-concept exploits.
Generate COMPLETE, REPRODUCIBLE PoCs. They must work when copy-pasted.
Mask sensitive tokens with <AUTH_TOKEN> placeholder."""

POC_PROMPT = """Generate a proof-of-concept for this vulnerability:

TITLE: {title}
SEVERITY: {severity}
CATEGORY: {category}
ENDPOINT: {endpoint}
METHOD: {method}
PAYLOAD: {payload}
EVIDENCE: {evidence}
STATUS CODE: {status_code}

Generate THREE formats:
1. curl command — one-liner that reproduces the issue
2. Python script — standalone script using the 'requests' library
3. Browser steps — step-by-step instructions for manual reproduction

The PoC must be COMPLETE and REPRODUCIBLE.
Include all necessary headers, cookies, and payloads.
Mask any sensitive tokens with <AUTH_TOKEN> placeholder.

OUTPUT FORMAT (strict JSON):
{{
    "curl": "curl -X GET ...",
    "python_script": "import requests\\n...",
    "browser_steps": ["step 1", "step 2", ...],
    "impact_description": "what an attacker could achieve"
}}
"""


class PoCGenerator:
    """Generate reproducible PoC for findings."""

    def __init__(self, brain: Brain) -> None:
        self.brain = brain

    async def generate(self, finding: Finding) -> dict[str, Any]:
        """Generate PoC for a single finding."""
        prompt = POC_PROMPT.format(
            title=finding.title,
            severity=finding.severity.value,
            category=finding.category,
            endpoint=finding.endpoint or finding.file_path,
            method=getattr(finding, "method", "GET"),
            payload=finding.payload or "N/A",
            evidence=finding.evidence or "See response",
            status_code=getattr(finding, "status_code", "N/A"),
        )

        try:
            result = await self.brain.async_think(
                system_prompt=POC_SYSTEM_PROMPT,
                user_prompt=prompt,
                json_schema={"type": "object"},
            )
            if isinstance(result, dict):
                return result
        except Exception as e:
            logger.debug(f"PoC generation failed: {e}")

        # Fallback: generate basic curl PoC
        return self._basic_poc(finding)

    async def generate_batch(self, findings: list[Finding]) -> list[dict[str, Any]]:
        """Generate PoCs for multiple findings."""
        results = []
        for finding in findings:
            poc = await self.generate(finding)
            results.append(poc)
        return results

    @staticmethod
    def _basic_poc(finding: Finding) -> dict[str, Any]:
        """Generate a basic PoC without LLM."""
        endpoint = finding.endpoint or "https://target.com"
        method = getattr(finding, "method", "GET")
        payload = finding.payload or ""

        curl = f"curl -X {method} '{endpoint}'"
        if payload:
            if method == "GET":
                curl = f"curl '{endpoint}?{payload}'"
            else:
                curl += f" -d '{payload}'"

        python_script = (
            f"import requests\n\n"
            f"url = '{endpoint}'\n"
            f"response = requests.{method.lower()}(url"
            f"{', params={' + repr(payload) + ': True}' if method == 'GET' and payload else ''}"
            f")\n"
            f"print(response.status_code)\n"
            f"print(response.text[:1000])\n"
        )

        return {
            "curl": curl,
            "python_script": python_script,
            "browser_steps": [
                f"1. Open {endpoint} in a browser",
                f"2. {'Inject payload: ' + payload if payload else 'Observe the response'}",
                "3. Verify the vulnerability is present",
            ],
            "impact_description": f"{finding.category} vulnerability on {endpoint}",
        }
