from senshi.modules.base import VulnModule, TestResult
from senshi.reporters.models import Finding, Severity, Confidence


class AuthBypassModule(VulnModule):
    name = "auth_bypass"
    description = "Authentication Bypass / Missing Auth"
    severity = Severity.HIGH
    cwe_id = 287
    payloads_dir = "auth"
    techniques = ["jwt_attacks", "session_fixation"]
    
    def is_applicable(self, endpoint: dict, tech_stack: dict) -> float:
        """Always applicable for sensitive paths."""
        url = endpoint.get("url", "").lower()
        if any(x in url for x in ["admin", "user", "profile", "settings", "api/v"]):
            return 0.8
        return 0.3
    
    def get_injection_points(self, endpoint: dict) -> list[dict]:
        return [{"location": "header", "name": "Authorization"}]
    
    def analyze_result(self, result: TestResult) -> Finding | None:
        """Check if endpoint is accessible without/with modified auth."""
        # Handled in custom test() logic
        return None

    def test(self, endpoint: dict, tech_stack: dict) -> list[Finding]:
        """Custom logic for testing missing auth."""
        # 1. Test without auth
        response = self.session.request(
            method=endpoint.get("method", "GET"),
            path=endpoint["url"],
            skip_auth=True
        )
        
        if response.status_code == 200:
            # Sensitive path accessible without auth?
            url = endpoint["url"].lower()
            if any(x in url for x in ["admin", "settings", "secret", "config"]):
                return [Finding(
                    title="Missing Authentication on Sensitive Endpoint",
                    severity=Severity.HIGH,
                    confidence=Confidence.LIKELY,
                    category="auth",
                    description=f"Sensitive endpoint {endpoint['url']} is accessible without authentication.",
                    endpoint=endpoint["url"],
                    payload="No Auth Header",
                    evidence=f"Status 200 returned for unauthenticated request",
                )]
        
        return []
