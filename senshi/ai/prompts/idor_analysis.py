"""
IDOR Analysis Prompt.

Used to analyze responses after manipulating resource IDs in the URL path.
"""

IDOR_ANALYSIS_PROMPT = """You are analyzing HTTP responses for IDOR (Insecure Direct Object Reference) vulnerabilities.

## CONTEXT
- Original endpoint: {endpoint}
- Original ID: {original_id}

## BASELINE RESPONSE (with original ID)
- Status: {baseline_status}
- Body length: {baseline_length}
- Body preview: {baseline_body}

## TEST RESULTS (with different IDs)
{test_results_json}

## YOUR TASK

Analyze if any test ID returned unauthorized data.

### IDOR INDICATORS

1. **Different data returned**: Test ID returns different user/resource data than original
2. **Status 200 with data**: Not 404, not 401/403, actual content returned
3. **Sensitive data exposed**: PII (email, phone, address), financial data, private info
4. **No authorization check**: Server didn't verify if requester owns this resource

### FALSE POSITIVE PREVENTION

1. **Public data**: If this is intentionally public data (e.g., product catalog), not IDOR
2. **Same data returned**: If test ID returns exact same data as original, not IDOR
3. **Error responses**: 404/401/403/500 are not IDOR (server is checking)
4. **Empty responses**: Empty array/object might just mean "no data" not "unauthorized access"

### SEVERITY ASSESSMENT

- CRITICAL: Accessed other users' PII, financial data, or auth tokens
- HIGH: Accessed other users' content, settings, or private info
- MEDIUM: Accessed metadata or non-sensitive info about other resources

## OUTPUT FORMAT

{{
  "findings": [
    {{
      "test_id": "the ID that exposed data",
      "is_vulnerable": true,
      "confidence": "confirmed|likely|possible",
      "severity": "critical|high|medium",
      "title": "IDOR in /api/users/{{id}} — accessed other user's data",
      "evidence": "specific data from response that proves unauthorized access",
      "data_exposed": "type of data exposed (PII, user content, etc.)",
      "reasoning": "why this is real IDOR"
    }}
  ],
  "not_vulnerable_reason": "if no IDOR found, explain why"
}}
"""
