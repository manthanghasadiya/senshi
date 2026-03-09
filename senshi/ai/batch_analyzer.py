"""
Batch LLM analyzer for test results.

Takes deterministic test results and uses LLM to identify real vulnerabilities.
"""

import json
from senshi.ai.brain import Brain
from senshi.reporters.models import Finding, Severity, Confidence, ScanMode


BATCH_ANALYSIS_PROMPT = """You are analyzing security test results to identify real vulnerabilities.

## TEST RESULTS

{results_formatted}

## ANALYSIS RULES

For each test result, determine if it's a REAL vulnerability:

**SQLi:**
- Real: Response contains database error (syntax error, ORA-, SQL, query failed)
- Real: Boolean payload returns different data than baseline
- False positive: Error unrelated to database

**XSS:**
- Real: Payload reflected unencoded AND Content-Type is text/html
- False positive: Payload in JSON/XML (not exploitable)
- False positive: Payload is HTML-encoded

**SSRF:**
- Real: Server attempted fetch (connection error, timeout, DNS failure)
- False positive: URL just echoed in response without fetch attempt

**CMDi:**
- Real: Command output in response (uid=, whoami output, directory listing)
- Real: Shell error ("command not found", "not recognized")
- False positive: No evidence of command execution

**IDOR:**
- Real: Different ID returned different user's data (status 200 with content)
- False positive: Returns 404/403/401 (proper access control)
- False positive: Returns same data or empty

**Auth:**
- Real: Sensitive endpoint returns data without auth
- False positive: Returns 401/403 without auth (proper protection)

**Info Disclosure:**
- Real: Response contains API keys, passwords, internal IPs, secrets
- False positive: Placeholder values, documentation examples

## OUTPUT FORMAT

Return a JSON array of findings:

{{
  "findings": [
    {{
      "result_index": 0,
      "is_vulnerable": true,
      "vuln_type": "sqli",
      "severity": "high",
      "confidence": "confirmed",
      "title": "SQL Injection via OR bypass",
      "evidence": "specific evidence from response",
      "reasoning": "why this is a real vulnerability"
    }}
  ]
}}

Only include entries where is_vulnerable is true.
"""


class BatchAnalyzer:
    """Analyzes test results in batch using LLM."""
    
    def __init__(self, brain: Brain):
        self.brain = brain
    
    def analyze(self, results: list) -> list[Finding]:
        """
        Analyze all test results and return findings.
        
        Groups results by vuln_type for efficient analysis.
        """
        findings = []
        
        # Group by vuln_type for better LLM context
        by_type = {}
        for i, r in enumerate(results):
            vt = r.vuln_type
            if vt not in by_type:
                by_type[vt] = []
            by_type[vt].append((i, r))
        
        # Analyze each group
        for vuln_type, type_results in by_type.items():
            type_findings = self._analyze_group(vuln_type, type_results)
            findings.extend(type_findings)
        
        return findings
    
    def _analyze_group(self, vuln_type: str, results: list) -> list[Finding]:
        """Analyze a group of results for one vuln type."""
        
        # Format results for LLM
        formatted = []
        for idx, r in results:
            formatted.append({
                "index": idx,
                "endpoint": r.endpoint,
                "param": r.param,
                "vuln_type": r.vuln_type,
                "payload": r.payload,
                "technique": r.technique,
                "baseline": {
                    "status": r.baseline_status,
                    "content_type": r.baseline_content_type,
                    "body_preview": r.baseline_body[:500],
                    "length": r.baseline_length,
                },
                "test": {
                    "status": r.test_status,
                    "content_type": r.test_content_type,
                    "body_preview": r.test_body[:1000],
                    "length": r.test_length,
                    "headers": r.test_headers,
                },
            })
        
        # Split into batches of 10 for LLM token limits
        all_findings = []
        batch_size = 10
        for i in range(0, len(formatted), batch_size):
            batch = formatted[i:i + batch_size]
            
            prompt = BATCH_ANALYSIS_PROMPT.format(
                results_formatted=json.dumps(batch, indent=2)
            )
            
            response = self.brain.think(
                system_prompt="You are a security expert analyzing test results.",
                user_prompt=prompt,
            )
            
            # Parse response
            try:
                data = json.loads(self._extract_json(response))
                llm_findings = data.get("findings", [])
                
                # Convert to Finding objects
                for f in llm_findings:
                    if not f.get("is_vulnerable"):
                        continue
                    
                    # Get original result
                    result_idx = f.get("result_index")
                    if result_idx is None:
                        continue
                        
                    # original is the TestResult object (since the generator yields 'r')
                    r = next((r for idx, r in results if idx == result_idx), None)
                    if not r:
                        continue
                    
                    all_findings.append(Finding(
                        title=f.get("title", f"{r.vuln_type} in {r.endpoint}"),
                        severity=self._parse_severity(f.get("severity", "high")),
                        confidence=self._parse_confidence(f.get("confidence", "likely")),
                        category=r.vuln_type,
                        description=f.get("reasoning", ""),
                        mode=ScanMode.DAST,
                        endpoint=r.endpoint,
                        method=r.method,
                        payload=f"{r.param}={r.payload}" if r.param else r.payload,
                        status_code=r.test_status,
                        response_snippet=r.test_body[:500],
                        evidence=f.get("evidence", ""),
                        llm_reasoning=f.get("reasoning", ""),
                    ))
            except Exception as e:
                import logging
                logging.getLogger("senshi").warning(f"Failed to parse LLM batch analysis for {vuln_type}: {e}")
        
        return all_findings
    
    def _extract_json(self, text: str) -> str:
        """Extract JSON from LLM response."""
        # Find JSON block
        if "```json" in text:
            start = text.find("```json") + 7
            end = text.find("```", start)
            return text[start:end].strip()
        if "```" in text:
            start = text.find("```") + 3
            end = text.find("```", start)
            return text[start:end].strip()
        # Try to find raw JSON
        if "{" in text:
            start = text.find("{")
            end = text.rfind("}") + 1
            return text[start:end]
        return text
    
    def _parse_severity(self, s: str) -> Severity:
        s = s.lower() if s else "high"
        return {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
        }.get(s, Severity.HIGH)
    
    def _parse_confidence(self, c: str) -> Confidence:
        c = c.lower() if c else "likely"
        return {
            "confirmed": Confidence.CONFIRMED,
            "likely": Confidence.LIKELY,
            "possible": Confidence.POSSIBLE,
        }.get(c, Confidence.LIKELY)
