import re
from senshi.modules.base import VulnModule, TestResult
from senshi.reporters.models import Finding, Severity, Confidence


class SQLInjectionModule(VulnModule):
    name = "sqli"
    description = "SQL Injection"
    severity = Severity.HIGH
    cwe_id = 89
    payloads_dir = "sqli"
    techniques = ["error_based", "blind_boolean", "blind_time", "union_based", "stacked"]
    
    # Common SQL error patterns
    ERROR_PATTERNS = [
        "SQL syntax",
        "mysql_fetch",
        "ORA-",
        "PostgreSQL query failed",
        "SQLite3::Exception",
        "System.Data.SqlClient",
        "Microsoft OLE DB Provider",
    ]
    
    def is_applicable(self, endpoint: dict, tech_stack: dict) -> float:
        """SQLi is possible if params exist."""
        score = 0.0
        if endpoint.get("params"):
            score += 0.5
            
        # Check for DB-related keywords
        url_lower = endpoint.get("url", "").lower()
        if any(x in url_lower for x in ["id", "query", "search", "filter", "order", "sort"]):
            score += 0.3
            
        return min(score, 1.0)
    
    def get_injection_points(self, endpoint: dict) -> list[dict]:
        points = []
        for param in endpoint.get("params", []):
            points.append({"location": "param", "name": param})
        return points
    
    def analyze_result(self, result: TestResult) -> Finding | None:
        """Check for SQLi indicators."""
        response_body = result.response["body"]
        baseline_body = result.baseline["body"] if result.baseline else ""
        
        # 1. Error-based detection
        for pattern in self.ERROR_PATTERNS:
            if pattern.lower() in response_body.lower():
                # Ensure it wasn't in baseline
                if pattern.lower() not in baseline_body.lower():
                    return Finding(
                        title="SQL Injection (Error-based)",
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        category="sqli",
                        description=f"SQL error found in response: {pattern}",
                        endpoint=result.request["url"],
                        payload=result.payload,
                        evidence=f"Error pattern '{pattern}' detected",
                        response_snippet=response_body[:500],
                    )
        
        # 2. Boolean-based detection (simplified)
        # If payload is ' OR '1'='1 and response length is significantly different (or same as baseline if original was empty)
        # This usually needs more care, but LLM can help
        
        # fallback to LLM for complex cases
        if result.technique in ["blind_boolean", "blind_time", "union_based"]:
             prompt = f"""
             Analyze this SQLi test result:
             Payload: {result.payload}
             Technique: {result.technique}
             Baseline Length: {len(baseline_body)}
             Test Length: {len(response_body)}
             Test Status: {result.response['status']}
             Elapsed Time: {result.elapsed_time:.2f}s
             
             Response Snippet:
             {response_body[:1000]}
             
             Is this vulnerable to SQL Injection? Return JSON: {{"vulnerable": true/false, "reason": "..."}}
             """
             try:
                 analysis = self.brain.think(
                     system_prompt="You are an expert vulnerability analyzer.",
                     user_prompt=prompt,
                     json_schema={"type": "object"}
                 )
                 if isinstance(analysis, dict) and analysis.get("vulnerable"):
                     return Finding(
                         title=f"SQL Injection ({result.technique})",
                         severity=Severity.HIGH,
                         confidence=Confidence.LIKELY,
                         category="sqli",
                         description=analysis.get("reason", "Detected via LLM analysis of response behavior."),
                         endpoint=result.request["url"],
                         payload=result.payload,
                         llm_reasoning=analysis.get("reason"),
                     )
             except:
                 pass

        return None
