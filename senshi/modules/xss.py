import re
from senshi.modules.base import VulnModule, TestResult
from senshi.reporters.models import Finding, Severity, Confidence


class XSSModule(VulnModule):
    name = "xss"
    description = "Cross-Site Scripting"
    severity = Severity.HIGH
    cwe_id = 79
    payloads_dir = "xss"
    techniques = ["basic", "event_handlers", "dom", "mutation"]
    
    def is_applicable(self, endpoint: dict, tech_stack: dict) -> float:
        """XSS is possible if response is HTML and params exist."""
        score = 0.0
        if "html" in endpoint.get("content_type", "").lower():
            score += 0.5
        if endpoint.get("params"):
            score += 0.3
        return min(score, 1.0)
    
    def get_injection_points(self, endpoint: dict) -> list[dict]:
        points = []
        for param in endpoint.get("params", []):
            points.append({"location": "param", "name": param})
        return points
    
    def analyze_result(self, result: TestResult) -> Finding | None:
        """Check for XSS indicators."""
        response_body = result.response["body"]
        payload = result.payload
        
        # Reflected XSS check
        if payload in response_body:
            # Check context via LLM or basic rules
            # We already have filters in BatchAnalyzer but here we should be proactive
            
            # Simple heuristic: is it injected into a tag or script?
            # For v0.5.0 we use LLM for smart analysis
            prompt = f"""
            Analyze this XSS test result:
            Payload: {payload}
            Response Content-Type: {result.response.get('headers', {}).get('Content-Type', 'unknown')}
            
            Response Snippet:
            {response_body[:2000]}
            
            Is the payload reflected in a way that executes JavaScript? 
            Return JSON: {{"vulnerable": true/false, "reason": "...", "severity": "..."}}
            """
            try:
                analysis = self.brain.think(
                    system_prompt="You are an expert XSS analyzer.",
                    user_prompt=prompt,
                    json_schema={"type": "object"}
                )
                if isinstance(analysis, dict) and analysis.get("vulnerable"):
                    return Finding(
                        title="Reflected Cross-Site Scripting (XSS)",
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        category="xss",
                        description=analysis.get("reason", "Payload reflected in vulnerable context."),
                        endpoint=result.request["url"],
                        payload=payload,
                        evidence="Payload reflected unencoded in HTML response",
                        response_snippet=response_body[:500],
                        llm_reasoning=analysis.get("reason"),
                    )
            except:
                pass

        return None
