import time
from senshi.modules.base import VulnModule, TestResult
from senshi.reporters.models import Finding, Severity, Confidence


class CommandInjectionModule(VulnModule):
    name = "cmdi"
    description = "OS Command Injection"
    severity = Severity.HIGH
    cwe_id = 78
    payloads_dir = "cmdi"
    techniques = ["linux", "windows", "blind_sleep"]
    
    def is_applicable(self, endpoint: dict, tech_stack: dict) -> float:
        """CMDi is possible if params exist and look like system commands."""
        score = 0.0
        params = endpoint.get("params", [])
        if not params:
            return 0.0
            
        cmd_indicators = ["cmd", "exec", "run", "file", "path", "ip", "host", "ping", "system"]
        if any(ind in p.lower() for p in params for ind in cmd_indicators):
            score += 0.7
        else:
            score += 0.2
            
        return min(score, 1.0)
    
    def get_injection_points(self, endpoint: dict) -> list[dict]:
        points = []
        for param in endpoint.get("params", []):
            points.append({"location": "param", "name": param})
        return points
    
    def analyze_result(self, result: TestResult) -> Finding | None:
        """Check for CMDi indicators."""
        response_body = result.response["body"]
        payload = result.payload
        
        # 1. Output-based detection
        cmdi_indicators = [
            "root:x:0:0:",  # /etc/passwd
            "Windows IP Configuration",  # ipconfig
            "uid=", "gid=", "groups=",  # id
        ]
        if any(ind in response_body for ind in cmdi_indicators):
            return Finding(
                title="OS Command Injection",
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category="cmdi",
                description="Successfully executed OS commands on the server.",
                endpoint=result.request["url"],
                payload=payload,
                evidence="Command output detected in response body",
                response_snippet=response_body[:500],
            )
            
        # 2. Blind Time-based detection
        if result.technique == "blind_sleep":
            # If response took 5+ seconds
            if result.elapsed_time >= 5.0:
                return Finding(
                    title="Blind OS Command Injection (Time-based)",
                    severity=Severity.HIGH,
                    confidence=Confidence.LIKELY,
                    category="cmdi",
                    description=f"Response delayed by {result.elapsed_time:.1f}s, indicating successful sleep command execution.",
                    endpoint=result.request["url"],
                    payload=payload,
                    evidence=f"Time delay of {result.elapsed_time:.1f}s observed",
                )
                
        return None
