"""
SSRF Scanner — internal URLs, cloud metadata, DNS rebind.

v0.2.0: Smart routing + heuristic checks using batch results.
"""

from __future__ import annotations

from typing import Any

from senshi.dast.crawler import DiscoveredEndpoint
from senshi.dast.scanners.base import BaseDastScanner
from senshi.reporters.models import Confidence, Finding, Severity, ScanMode
from senshi.utils.logger import get_logger

logger = get_logger("senshi.dast.scanners.ssrf")

# Known cloud metadata indicators
METADATA_INDICATORS = [
    "ami-id", "instance-id", "instance-type", "iam",
    "security-credentials", "meta-data", "user-data",
    "computeMetadata", "access-token", "service-accounts",
]

# Param names that suggest URL input
URL_PARAM_NAMES = {
    "url", "uri", "link", "href", "src", "dest", "redirect",
    "fetch", "proxy", "target", "path", "callback", "return",
    "next", "ref", "site", "html", "feed", "to", "out",
}


class SsrfScanner(BaseDastScanner):
    """SSRF scanner — internal URLs, cloud metadata, DNS rebinding."""

    def get_scanner_name(self) -> str:
        return "SSRF Scanner"

    def get_vulnerability_class(self) -> str:
        return "ssrf"

    def filter_relevant_endpoints(
        self, endpoints: list[DiscoveredEndpoint]
    ) -> list[DiscoveredEndpoint]:
        """SSRF is relevant for endpoints with URL-like parameters."""
        from urllib.parse import urlparse, parse_qs
        
        relevant = []
        for ep in endpoints:
            all_params = set(ep.params)
            
            # Parse params from URL in case the agent supplied them directly
            parsed = urlparse(ep.url)
            query_params = parse_qs(parsed.query)
            all_params.update(query_params.keys())
            
            # Update the endpoint object so the payload is injected correctly
            ep.params = list(all_params)
            
            if not all_params:
                continue
            if any(p.lower() in URL_PARAM_NAMES for p in all_params):
                relevant.append(ep)
            elif any(x in ep.url.lower() for x in ["fetch", "proxy", "redirect", "url"]):
                relevant.append(ep)
        return relevant

    def run_heuristics(
        self,
        endpoint: DiscoveredEndpoint,
        baseline: Any,
        payload_results: list[dict[str, Any]],
    ) -> list[Finding]:
        """Check for cloud metadata and internal service indicators."""
        findings = []
        baseline_body = baseline.body if hasattr(baseline, "body") else ""

        for pr in payload_results:
            payload = pr.get("payload", "")
            body = pr.get("response_body", "")

            # Cloud metadata check
            for indicator in METADATA_INDICATORS:
                if indicator in body and indicator not in baseline_body:
                    findings.append(
                        Finding(
                            title=f"SSRF — Cloud metadata access via {endpoint.url}",
                            severity=Severity.CRITICAL,
                            confidence=Confidence.CONFIRMED,
                            category="ssrf",
                            description=(
                                f"Cloud metadata indicator '{indicator}' found. "
                                f"Server is making requests to internal/cloud URLs."
                            ),
                            mode=ScanMode.DAST,
                            endpoint=endpoint.url,
                            method=endpoint.method,
                            payload=payload,
                            response_snippet=body[:500],
                            status_code=pr.get("response_status", 0),
                            evidence=f"Cloud metadata indicator: {indicator}",
                            cvss_estimate=9.1,
                        )
                    )
                    break

            # Internal service indicators
            internal_indicators = [
                "root:", "/etc/passwd", "Connection refused", "No route to host",
            ]
            for indicator in internal_indicators:
                if indicator in body and indicator not in baseline_body:
                    findings.append(
                        Finding(
                            title=f"SSRF — Internal service access via {endpoint.url}",
                            severity=Severity.HIGH,
                            confidence=Confidence.LIKELY,
                            category="ssrf",
                            description=f"Internal indicator '{indicator}' found.",
                            mode=ScanMode.DAST,
                            endpoint=endpoint.url,
                            method=endpoint.method,
                            payload=payload,
                            response_snippet=body[:500],
                            status_code=pr.get("response_status", 0),
                            evidence=f"Internal indicator: {indicator}",
                            cvss_estimate=7.5,
                        )
                    )
                    break

        return findings
