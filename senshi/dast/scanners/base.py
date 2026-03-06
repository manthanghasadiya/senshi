"""
Base DAST scanner — all DAST scanners inherit from this.

Implements the standard scan pipeline:
1. Get context (endpoint, params, tech stack, previous findings)
2. Ask LLM to generate targeted payloads
3. Send payloads and collect responses
4. Ask LLM to analyze responses
5. Ask validation LLM to eliminate false positives
6. Return confirmed findings
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from senshi.ai.brain import Brain
from senshi.ai.false_positive_filter import FalsePositiveFilter
from senshi.ai.payload_gen import PayloadGenerator
from senshi.ai.response_analyzer import ResponseAnalyzer
from senshi.core.session import Session
from senshi.reporters.models import Finding
from senshi.utils.logger import get_logger, print_finding, print_status

logger = get_logger("senshi.dast.scanners.base")


class BaseDastScanner(ABC):
    """
    Base class for all DAST scanners.

    Subclasses must implement:
    - get_scanner_name() -> str
    - get_vulnerability_class() -> str
    - get_payload_prompt() -> str (optional override)
    - get_analysis_prompt() -> str (optional override)
    """

    def __init__(
        self,
        session: Session,
        brain: Brain,
        target_context: dict[str, Any],
        max_payloads: int = 15,
    ) -> None:
        self.session = session
        self.brain = brain
        self.context = target_context
        self.max_payloads = max_payloads

        # Components
        self.payload_gen = PayloadGenerator(brain)
        self.response_analyzer = ResponseAnalyzer(brain)
        self.fp_filter = FalsePositiveFilter(brain)

        self.findings: list[Finding] = []

    @abstractmethod
    def get_scanner_name(self) -> str:
        """Return scanner name for display."""
        ...

    @abstractmethod
    def get_vulnerability_class(self) -> str:
        """Return vulnerability class (e.g., 'xss', 'ssrf')."""
        ...

    def generate_payloads(self) -> list[dict[str, Any]]:
        """Ask LLM to generate context-aware payloads."""
        endpoint = self.context.get("endpoint", "")
        method = self.context.get("method", "GET")
        params = self.context.get("parameters", [])
        tech_stack = self.context.get("tech_stack", "unknown")
        app_desc = self.context.get("app_description", "")
        prev_findings = self.context.get("previous_findings", "")

        print_status(
            f"{self.get_scanner_name()}: generating {self.max_payloads} payloads "
            f"for {endpoint}..."
        )

        payloads = self.payload_gen.generate(
            vulnerability_class=self.get_vulnerability_class(),
            endpoint=endpoint,
            method=method,
            parameters=params,
            tech_stack=tech_stack,
            app_description=app_desc,
            previous_findings=prev_findings,
            count=self.max_payloads,
        )

        return payloads

    def send_and_analyze(self, payloads: list[dict[str, Any]]) -> list[Finding]:
        """Send payloads, collect responses, ask LLM to analyze."""
        findings: list[Finding] = []
        endpoint = self.context.get("endpoint", "")
        method = self.context.get("method", "GET")
        params = self.context.get("parameters", [])

        # Get baseline
        baseline = self.session.get_baseline(endpoint)

        for payload_data in payloads:
            value = payload_data.get("value", "")
            injection_point = payload_data.get("injection_point", "")
            technique = payload_data.get("technique", "")

            if not value:
                continue

            try:
                # Send the payload
                response = self._send_payload(
                    endpoint, method, value, injection_point, params
                )

                # Analyze the response
                finding = self.response_analyzer.analyze(
                    endpoint=endpoint,
                    method=method,
                    payload=value,
                    technique=technique,
                    baseline_status=baseline.status_code,
                    baseline_headers=baseline.headers,
                    baseline_body=baseline.body,
                    test_status=response.status_code,
                    test_headers=response.headers,
                    test_body=response.body,
                )

                if finding:
                    findings.append(finding)
                    print_finding(
                        finding.severity.value,
                        finding.title,
                        endpoint,
                    )

            except Exception as e:
                logger.debug(f"Payload send/analyze failed: {e}")
                continue

        return findings

    def _send_payload(
        self,
        endpoint: str,
        method: str,
        payload: str,
        injection_point: str,
        params: list[str],
    ) -> Any:
        """Send a payload to the target endpoint."""
        target_param = injection_point or (params[0] if params else "q")

        if method.upper() == "GET":
            return self.session.get(endpoint, params={target_param: payload})
        elif method.upper() == "POST":
            return self.session.post(endpoint, data={target_param: payload})
        else:
            return self.session.request(
                method, endpoint, data={target_param: payload}
            )

    def validate_findings(self, findings: list[Finding]) -> list[Finding]:
        """2nd LLM pass — eliminate false positives."""
        if not findings:
            return []

        print_status(f"Validating {len(findings)} findings with AI...")
        return self.fp_filter.validate_batch(findings)

    def scan(self) -> list[Finding]:
        """
        Full scan pipeline.

        1. Generate payloads
        2. Send and analyze
        3. Validate (eliminate FPs)
        4. Return confirmed findings
        """
        scanner_name = self.get_scanner_name()
        logger.info(f"{scanner_name}: Starting scan")

        payloads = self.generate_payloads()
        if not payloads:
            logger.info(f"{scanner_name}: No payloads generated")
            return []

        raw_findings = self.send_and_analyze(payloads)
        validated = self.validate_findings(raw_findings)

        self.findings = validated

        # Summary
        severity_counts = {}
        for f in validated:
            sev = f.severity.value.upper()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        count_str = ", ".join(f"{v} {k}" for k, v in severity_counts.items())
        logger.info(f"✓ {scanner_name}: {len(validated)} findings ({count_str})")

        return validated
