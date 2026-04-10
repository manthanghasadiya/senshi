"""
Fast deterministic pre-fuzzer — sends known-good payloads before LLM analysis.

Hybrid mode: sends payloads fast, then uses LLM for structured batch analysis.
"""

from __future__ import annotations

from typing import Any

from senshi.ai.brain import Brain
from senshi.core.session import Session
from senshi.reporters.models import Confidence, Finding, ScanMode, Severity
from senshi.utils.logger import get_logger

logger = get_logger("senshi.dast.fuzzer")

# Deterministic payload sets — fast delivery, smart analysis
FUZZ_PAYLOADS = {
    "sqli": [
        ("'", "Single quote"),
        ("\"", "Double quote"),
        ("' OR '1'='1", "Classic OR bypass"),
        ("'; DROP TABLE --", "DROP TABLE"),
        ("1 UNION SELECT NULL--", "UNION SELECT"),
        ("1' AND SLEEP(5)--", "Blind time-based"),
    ],
    "xss": [
        ("<script>alert(1)</script>", "Basic script tag"),
        ('"><img src=x onerror=alert(1)>', "Event handler"),
        ("{{7*7}}", "SSTI / template injection"),
        ("${7*7}", "Expression language"),
        ("javascript:alert(1)", "JS protocol"),
    ],
    "path_traversal": [
        ("../../../etc/passwd", "Linux passwd"),
        ("..\\..\\..\\windows\\win.ini", "Windows win.ini"),
        ("....//....//....//etc/passwd", "Double-dot bypass"),
        ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "URL-encoded"),
    ],
    "cmdi": [
        ("; id", "Semicolon id"),
        ("| id", "Pipe id"),
        ("$(id)", "Command substitution"),
        ("`id`", "Backtick"),
        ("|| whoami", "OR whoami"),
    ],
    "ssrf": [
        ("http://169.254.169.254/latest/meta-data/", "AWS metadata"),
        ("http://metadata.google.internal/", "GCP metadata"),
        ("http://100.100.100.200/latest/meta-data/", "Alibaba metadata"),
        ("http://127.0.0.1:80", "Localhost"),
        ("http://[::1]", "IPv6 localhost"),
    ],
}


class DeterministicFuzzer:
    """
    Fast payload delivery — NO detection logic.

    This fuzzer sends payloads and collects responses.
    Detection is handled by the LLM analyzer.
    """

    def __init__(self, session: Session, brain: Brain | None = None) -> None:
        self.session = session
        self.brain = brain  # For batch analysis

    def fuzz_endpoint(
        self,
        url: str,
        method: str = "GET",
        params: list[str] | None = None,
        vuln_types: list[str] | None = None,
    ) -> list[Finding]:
        """
        Fuzz an endpoint and return findings.

        1. Get baseline response
        2. Send all payloads, collect responses
        3. Send to LLM for batch analysis
        4. Return findings
        """
        if not params:
            return []

        types = vuln_types or list(FUZZ_PAYLOADS.keys())

        # Phase 1: Baseline
        try:
            baseline = self.session.get(url)
        except Exception:
            return []

        # Phase 2: Fuzz (fast, no analysis)
        results = []
        for param in params:
            for vuln_type in types:
                payloads = FUZZ_PAYLOADS.get(vuln_type, [])
                for payload_value, technique in payloads:
                    try:
                        if method.upper() == "GET":
                            response = self.session.get(url, params={param: payload_value})
                        else:
                            response = self.session.post(url, data={param: payload_value})

                        results.append({
                            "param": param,
                            "vuln_type": vuln_type,
                            "payload": payload_value,
                            "technique": technique,
                            "status_code": response.status_code,
                            "content_type": response.headers.get("Content-Type", ""),
                            "body": response.body[:2000],
                            "headers": dict(response.headers),
                        })
                    except Exception as e:
                        logger.debug(f"Fuzz error for {payload_value}: {e}")

        # Phase 3: LLM Analysis
        if self.brain and results:
            return self._analyze_with_llm(url, method, params, baseline, results)
        
        return []

    def _analyze_with_llm(self, url: str, method: str, params: list[str], baseline: Any, results: list[dict]) -> list[Finding]:
        """Send all results to LLM for intelligent analysis."""
        context = {
            "endpoint": url,
            "method": method,
            "params": params,
            "baseline": {
                "status": baseline.status_code,
                "content_type": baseline.headers.get("Content-Type", ""),
                "body_preview": baseline.body[:500],
            },
            "results": results,
        }

        try:
            response = self.brain.batch_analyze_fuzz_results(context)
            findings = self._parse_llm_findings(response, url, method, results)
            return findings
        except Exception as e:
            logger.warning(f"Batch analysis failed: {e}")
            return []

    def _parse_llm_findings(self, response: dict, url: str, method: str, results: list[dict]) -> list[Finding]:
        """Parse LLM response into Finding objects."""
        findings = []
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

        CMDI_EVIDENCE_PATTERNS = ["uid=", "gid=", "groups=", "root:", "www-data", 
                                  "Directory of", "Volume Serial Number", "command not found"]

        for item in response.get("findings", []):
            if not item.get("is_vulnerable"):
                continue
            
            idx = item.get("payload_index", 0)
            if 0 <= idx < len(results):
                res = results[idx]
                
                # STRICT CMDi verification — require actual command output
                if res.get("vuln_type") == "cmdi" or item.get("vulnerability_type") == "cmdi" or item.get("vuln_type") == "cmdi":
                    has_evidence = any(pattern in res.get("body", "") for pattern in CMDI_EVIDENCE_PATTERNS)
                    if not has_evidence:
                        logger.debug(f"CMDi rejected — no command output in response: {res.get('payload', '')}")
                        continue
                
                finding = Finding(
                    title=item.get("title", f"{item.get('vuln_type', 'vuln').upper()} detected"),
                    severity=severity_map.get(item.get("severity", "medium"), Severity.MEDIUM),
                    confidence=confidence_map.get(item.get("confidence", "possible"), Confidence.POSSIBLE),
                    category=item.get("vuln_type", "unknown"),
                    description=item.get("reasoning", ""),
                    mode=ScanMode.DAST,
                    endpoint=url,
                    method=method,
                    payload=f"{res['param']}={res['payload']}",
                    status_code=res["status_code"],
                    response_snippet=res["body"][:300],
                    evidence=item.get("evidence", ""),
                    llm_reasoning=item.get("reasoning", ""),
                )
                findings.append(finding)
        
        return findings
