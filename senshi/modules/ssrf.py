from senshi.modules.base import VulnModule, TestResult
from senshi.reporters.models import Finding, Severity, Confidence


class SSRFModule(VulnModule):
    name = "ssrf"
    description = "Server-Side Request Forgery"
    severity = Severity.HIGH
    cwe_id = 918
    payloads_dir = "ssrf"
    techniques = ["cloud_aws", "cloud_gcp", "internal", "protocols"]
    
    def is_applicable(self, endpoint: dict, tech_stack: dict) -> float:
        """SSRF is possible if params look like URLs."""
        score = 0.0
        params = endpoint.get("params", [])
        if not params:
            return 0.0
            
        url_indicators = ["url", "uri", "link", "goto", "redirect", "fetch", "proxy", "src"]
        if any(ind in p.lower() for p in params for ind in url_indicators):
            score += 0.8
        else:
            score += 0.2
            
        return min(score, 1.0)
    
    def get_injection_points(self, endpoint: dict) -> list[dict]:
        points = []
        for param in endpoint.get("params", []):
            points.append({"location": "param", "name": param})
        return points
    
    def analyze_result(self, result: TestResult) -> Finding | None:
        """Check for SSRF indicators."""
        response_body = result.response["body"]
        payload = result.payload
        
        # 1. Cloud Metadata Indicators
        cloud_indicators = [
            "ami-id", "instance-id", "latest/meta-data",
            "computeMetadata/v1", "instance/service-accounts",
            "microsoft.compute", "identity/oauth2/token"
        ]
        if any(ind in response_body for ind in cloud_indicators):
            return Finding(
                title="Server-Side Request Forgery (SSRF) — Cloud Metadata",
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category="ssrf",
                description="Target is vulnerable to SSRF and can access cloud metadata services.",
                endpoint=result.request["url"],
                payload=payload,
                evidence="Cloud metadata service response detected in body",
            )
            
        # 2. OOB Callback (the most reliable)
        if result.callback_received:
            return Finding(
                title="Server-Side Request Forgery (SSRF) — Out-of-Band",
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                category="ssrf",
                description="Target made an out-of-band request to controller, confirming SSRF.",
                endpoint=result.request["url"],
                payload=payload,
                evidence="OOB callback received",
            )
            
        # 3. Content-Type / Status change detection via LLM
        return None
