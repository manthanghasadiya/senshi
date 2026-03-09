from senshi.modules.base import VulnModule, TestResult
from senshi.reporters.models import Finding, Severity, Confidence


class IDORModule(VulnModule):
    name = "idor"
    description = "Insecure Direct Object Reference"
    severity = Severity.HIGH
    cwe_id = 639
    payloads_dir = "auth"
    techniques = ["idor_patterns"]
    
    def is_applicable(self, endpoint: dict, tech_stack: dict) -> float:
        """IDOR is possible if URL has numeric/UUID-like paths or params."""
        url = endpoint.get("url", "")
        if "/api/" in url.lower():
            if any(c.isdigit() for c in url):
                return 0.8
        for param in endpoint.get("params", []):
            if param.lower() in ["id", "user_id", "order_id", "uid"]:
                return 0.9
        return 0.2
    
    def get_injection_points(self, endpoint: dict) -> list[dict]:
        points = []
        for param in endpoint.get("params", []):
            if param.lower() in ["id", "uid", "user_id", "order_id"]:
                points.append({"location": "param", "name": param})
        return points
    
    def analyze_result(self, result: TestResult) -> Finding | None:
        """Check for IDOR by comparing responses for different IDs."""
        # This module needs multi-request logic or ID incrementing
        # For v0.5.0 we'll rely on the engine or implement it in test()
        return None

    def test(self, endpoint: dict, tech_stack: dict) -> list[Finding]:
        """Override test for custom IDOR logic."""
        if self.is_applicable(endpoint, tech_stack) < 0.3:
            return []
            
        findings = []
        url = endpoint["url"]
        
        # Try to find numeric ID in URL or params
        for param in endpoint.get("params", []):
            if param.lower() in ["id", "uid", "user_id"]:
                # Try simple ID+1 / ID-1
                # This is a bit complex for a stateless module
                pass
                
        return findings
