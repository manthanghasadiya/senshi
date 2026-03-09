import json
import re
from pathlib import Path
from senshi.modules.base import VulnModule, TestResult
from senshi.reporters.models import Finding, Severity, Confidence


class InfoDisclosureModule(VulnModule):
    name = "info_disclosure"
    description = "Information Disclosure"
    severity = Severity.MEDIUM
    cwe_id = 200
    payloads_dir = "info_disclosure"
    techniques = ["files", "endpoints", "secrets_regex"]
    
    # Critical secret patterns
    SECRET_PATTERNS = [
        (r'["\']?api[_-]?key["\']?\s*[:=]\s*["\'][^"\']{20,}["\']', "API Key", Severity.CRITICAL),
        (r'sk-[a-zA-Z0-9-]{20,}', "API Key (sk- prefix)", Severity.CRITICAL),
        (r'["\']?secret[_-]?key["\']?\s*[:=]\s*["\'][^"\']{20,}["\']', "Secret Key", Severity.CRITICAL),
        (r'["\']?api[_-]?secret["\']?\s*[:=]\s*["\'][^"\']{20,}["\']', "API Secret", Severity.CRITICAL),
        (r'AKIA[0-9A-Z]{16}', "AWS Access Key", Severity.CRITICAL),
        (r'Bearer\s+[a-zA-Z0-9_-]{20,}', "Bearer Token", Severity.HIGH),
        (r'["\']?password["\']?\s*[:=]\s*["\'][^"\']{4,}["\']', "Password", Severity.HIGH),
        (r'["\']?token["\']?\s*[:=]\s*["\'][^"\']{20,}["\']', "Auth Token", Severity.HIGH),
        (r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----', "Private Key", Severity.CRITICAL),
    ]
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._patterns = []
        self._load_patterns()
        
    def _load_patterns(self):
        """Load regex patterns for secrets."""
        path = Path(__file__).parent.parent / "payloads" / "info_disclosure" / "secrets_regex.json"
        if path.exists():
            try:
                data = json.loads(path.read_text())
                self._patterns = data.get("patterns", [])
            except:
                pass

    def is_applicable(self, endpoint: dict, tech_stack: dict) -> float:
        return 1.0 # Always check for info disclosure in responses
    
    def get_injection_points(self, endpoint: dict) -> list[dict]:
        # Sensitive file discovery
        return [{"location": "path", "name": "sensitive_file"}]
    
    def test(self, endpoint: dict, tech_stack: dict) -> list[Finding]:
        """Run tests, including a passive scan of the baseline response."""
        # 1. Passive scan of baseline
        findings = []
        baseline = self.session.get_baseline(endpoint["url"])
        if baseline:
            result = TestResult(
                payload="Passive Scan",
                technique="baseline",
                request={"url": endpoint["url"], "method": endpoint.get("method", "GET")},
                response={
                    "status": baseline.status_code,
                    "body": baseline.body,
                    "headers": baseline.headers,
                    "length": len(baseline.body),
                }
            )
            finding = self.analyze_result(result)
            if finding:
                findings.append(finding)

        # 2. Active scan for sensitive files
        active_findings = super().test(endpoint, tech_stack)
        findings.extend(active_findings)
        
        return findings

    def analyze_result(self, result: TestResult) -> Finding | None:
        """Scan response body for secrets."""
        body = result.response["body"]
        
        # 1. Check hardcoded critical patterns
        for regex, name, severity in self.SECRET_PATTERNS:
            if re.search(regex, body):
                return Finding(
                    title=f"Sensitive Information Disclosure — {name}",
                    severity=severity,
                    confidence=Confidence.CONFIRMED,
                    category="info_disclosure",
                    description=f"Critical {name} detected in response body.",
                    endpoint=result.request["url"],
                    payload="Regex Scan",
                    evidence=f"Matched pattern: {regex}",
                )

        # 2. Check patterns from JSON database
        for p in self._patterns:
            matches = re.findall(p["regex"], body)
            if matches:
                return Finding(
                    title=f"Sensitive Information Disclosure — {p['name']}",
                    severity=self._parse_severity(p.get("severity", "medium")),
                    confidence=Confidence.LIKELY,
                    category="info_disclosure",
                    description=f"Potential {p['name']} detected in response body.",
                    endpoint=result.request["url"],
                    payload="Regex Scan",
                    evidence=f"Matched pattern: {p['regex']}",
                )
        return None

    def _parse_severity(self, sev: str) -> Severity:
        mapping = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.LOW
        }
        return mapping.get(sev.lower(), Severity.MEDIUM)
