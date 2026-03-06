"""
Base DAST scanner — all DAST scanners inherit from this.

v0.2.0: Rewritten for batch analysis pipeline.
- 1 LLM call for payload generation (was 1)
- N HTTP calls to send payloads (no LLM, was N LLM calls)
- 1 LLM call for batch analysis (was N LLM calls)
- 1 LLM call for FP validation (was 1)

Total: 3 LLM calls per endpoint per scanner (was N+2).
"""

from __future__ import annotations

import re
import time
from abc import ABC, abstractmethod
from typing import Any

from senshi.ai.brain import Brain
from senshi.ai.false_positive_filter import FalsePositiveFilter
from senshi.ai.payload_gen import PayloadGenerator
from senshi.ai.response_analyzer import ResponseAnalyzer
from senshi.core.session import Session
from senshi.dast.crawler import DiscoveredEndpoint
from senshi.reporters.models import Finding
from senshi.utils.logger import get_logger, print_finding, print_status

logger = get_logger("senshi.dast.scanners.base")


class BaseDastScanner(ABC):
    """
    Base class for all DAST scanners.

    v0.2.0 pipeline per endpoint:
    1. Generate payloads (1 LLM call)
    2. Send ALL payloads to target (N HTTP calls, no LLM)
    3. Analyze ALL results in ONE LLM call (1 LLM call)
    4. Run heuristic checks (no LLM)
    5. Validate findings (1 LLM call)

    Subclasses must implement:
    - get_scanner_name() -> str
    - get_vulnerability_class() -> str

    Subclasses may override:
    - filter_relevant_endpoints() -> list[DiscoveredEndpoint]
    - run_heuristics() -> list[Finding]
    """

    def __init__(
        self,
        session: Session,
        brain: Brain,
        endpoints: list[DiscoveredEndpoint],
        tech_summary: str = "",
        max_payloads: int = 15,
        rate_limit: float = 1.0,
        on_finding: Any = None,
    ) -> None:
        self.session = session
        self.brain = brain
        self.endpoints = endpoints
        self.tech_summary = tech_summary
        self.max_payloads = max_payloads
        self.rate_limit = rate_limit
        self._on_finding = on_finding

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

    def filter_relevant_endpoints(
        self, endpoints: list[DiscoveredEndpoint]
    ) -> list[DiscoveredEndpoint]:
        """Filter endpoints relevant to this scanner. Override in subclasses."""
        return endpoints

    def run_heuristics(
        self,
        endpoint: DiscoveredEndpoint,
        baseline: Any,
        payload_results: list[dict[str, Any]],
    ) -> list[Finding]:
        """Run scanner-specific heuristic checks. Override in subclasses."""
        return []

    def scan(self) -> list[Finding]:
        """
        Full batched scan pipeline.

        1. Filter relevant endpoints
        2. For each endpoint:
           a. Get baseline
           b. Generate payloads (1 LLM call)
           c. Send ALL payloads (N HTTP calls)
           d. Analyze ALL results (1 LLM call)
           e. Run heuristics (0 LLM calls)
        3. Deduplicate
        4. Validate (1 LLM call)
        """
        scanner_name = self.get_scanner_name()

        # Step 1: Filter to relevant endpoints
        relevant = self.filter_relevant_endpoints(self.endpoints)
        if not relevant:
            logger.info(f"{scanner_name}: No relevant endpoints, skipping")
            return []

        logger.info(
            f"{scanner_name}: Scanning {len(relevant)} relevant endpoints "
            f"(of {len(self.endpoints)} total)"
        )

        all_findings: list[Finding] = []

        # Step 2: Process each endpoint
        for ep in relevant:
            try:
                ep_findings = self._scan_endpoint(ep)
                all_findings.extend(ep_findings)
            except Exception as e:
                logger.warning(f"{scanner_name} failed on {ep.url}: {e}")

        # Step 3: Deduplicate
        deduped = self._deduplicate_findings(all_findings)

        # Step 4: Validate (eliminate FPs)
        if deduped:
            print_status(f"Validating {len(deduped)} findings with AI...")
            validated = self.fp_filter.validate_batch(deduped)
        else:
            validated = []

        self.findings = validated

        severity_counts: dict[str, int] = {}
        for f in validated:
            sev = f.severity.value.upper()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        count_str = ", ".join(f"{v} {k}" for k, v in severity_counts.items())
        logger.info(
            f"✓ {scanner_name}: {len(validated)} findings "
            f"({len(all_findings) - len(validated)} rejected) [{count_str}]"
        )

        return validated

    def _scan_endpoint(self, ep: DiscoveredEndpoint) -> list[Finding]:
        """Scan a single endpoint with the batch pipeline."""
        scanner_name = self.get_scanner_name()

        # Step 2a: Get baseline response
        baseline = self.session.get_baseline(ep.url)

        # Step 2b: Generate payloads (1 LLM call)
        print_status(
            f"{scanner_name}: {ep.method} {ep.url} — generating payloads..."
        )
        payloads = self.payload_gen.generate(
            vulnerability_class=self.get_vulnerability_class(),
            endpoint=ep.url,
            method=ep.method,
            parameters=ep.params,
            tech_stack=self.tech_summary,
            count=self.max_payloads,
        )

        if not payloads:
            return []

        # Step 2c: Send ALL payloads (N HTTP calls, no LLM)
        print_status(
            f"{scanner_name}: Sending {len(payloads)} payloads to {ep.url}..."
        )
        payload_results = self._send_all_payloads(ep, payloads)

        if not payload_results:
            return []

        # Step 2d: Analyze ALL results (1 LLM call)
        print_status(
            f"{scanner_name}: Analyzing {len(payload_results)} responses..."
        )
        baseline_ct = ""
        if hasattr(baseline, "headers"):
            baseline_ct = baseline.headers.get("content-type", "")

        findings = self.response_analyzer.analyze_batch(
            endpoint=ep.url,
            method=ep.method,
            vuln_type=self.get_vulnerability_class(),
            baseline_status=baseline.status_code,
            baseline_content_type=baseline_ct,
            baseline_body=baseline.body,
            payload_results=payload_results,
        )

        # Step 2e: Run heuristic checks (0 LLM calls)
        heuristic_findings = self.run_heuristics(ep, baseline, payload_results)
        findings.extend(heuristic_findings)

        # Report finds immediately
        for f in findings:
            print_finding(f.severity.value, f.title, ep.url)
            if self._on_finding:
                self._on_finding(f)

        return findings

    def _send_all_payloads(
        self,
        ep: DiscoveredEndpoint,
        payloads: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Send all payloads sequentially, collect responses. No LLM calls."""
        results = []
        target_param = ep.params[0] if ep.params else "q"

        for payload_data in payloads:
            value = payload_data.get("value", "")
            injection_point = payload_data.get("injection_point", "")

            if not value:
                continue

            param = injection_point or target_param

            try:
                if ep.method.upper() == "GET":
                    response = self.session.get(ep.url, params={param: value})
                elif ep.method.upper() == "POST":
                    response = self.session.post(ep.url, data={param: value})
                else:
                    response = self.session.request(
                        ep.method, ep.url, data={param: value}
                    )

                results.append({
                    "payload": value,
                    "injection_point": param,
                    "technique": payload_data.get("technique", ""),
                    "response_status": response.status_code,
                    "response_body": response.body[:2000],
                    "content_type": response.headers.get("content-type", ""),
                    "response_headers": dict(response.headers),
                })

                # Rate limit between requests
                if self.rate_limit > 0:
                    time.sleep(self.rate_limit)

            except Exception as e:
                logger.debug(f"Payload send failed: {e}")
                continue

        return results

    def _deduplicate_findings(self, findings: list[Finding]) -> list[Finding]:
        """Deduplicate: same vuln at same endpoint = 1 finding (keep highest confidence)."""
        seen: dict[str, Finding] = {}
        for f in findings:
            key = f"{f.category}:{f.endpoint}"
            if key not in seen:
                seen[key] = f
            else:
                # Keep the one with higher severity
                if f.severity.rank > seen[key].severity.rank:
                    seen[key] = f
        return list(seen.values())
