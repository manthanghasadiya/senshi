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
    
    def analyze_result(self, result: TestResult) -> Finding | None:
        """Scan response body for secrets."""
        body = result.response["body"]
        
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
