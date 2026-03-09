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
        confirmed_patterns = [
            r"root:x:0:0:",                   # /etc/passwd
            r"Windows IP Configuration",       # ipconfig
            r"uid=\d+",                        # Linux id
            r"gid=\d+",                        # Linux id
            r"[a-zA-Z0-9_-]+\\[a-zA-Z0-9_-]+", # Windows domain\user
            r"COMPUTERNAME=",                  # Windows env
            r"USERNAME=",                      # Windows env
            r"bin/bash",                       # Shell path
            r"Directory of ",                  # Windows dir
        ]
        
        import re
        for pattern in confirmed_patterns:
            if re.search(pattern, response_body):
                return Finding(
                    title="Command Injection Confirmed",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    category="cmdi",
                    description="Successfully executed OS commands on the server.",
                    endpoint=result.request["url"],
                    payload=payload,
                    evidence=f"Command output detected: {response_body[:100].strip()}",
                    response_snippet=response_body[:500],
                )

        # Check for shell errors (also confirmed attempted execution)
        error_patterns = [
            "not recognized as an internal or external command",
            "command not found",
            "No such file or directory",
            "Permission denied",
        ]
        if any(err in response_body for err in error_patterns):
            return Finding(
                title="Command Injection (Error-Based)",
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category="cmdi",
                description="Server attempted to execute command but failed with shell error.",
                endpoint=result.request["url"],
                payload=payload,
                evidence=f"Shell error detected: {response_body[:100].strip()}",
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
