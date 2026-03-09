IDOR_ANALYSIS_PROMPT = """You are analyzing HTTP responses for IDOR (Insecure Direct Object Reference).

## ENDPOINT
{endpoint}

## BASELINE (original ID)
Status: {baseline_status}
Body length: {baseline_length}
Body preview:
{baseline_body}

## TEST RESULTS (different IDs)
{test_results}

## ANALYSIS TASK

Determine if changing the ID returned unauthorized data.

IDOR CONFIRMED if:
- Different ID returned different data (not 404, not "unauthorized")
- Data appears to belong to another user/resource
- No authorization check prevented access

NOT IDOR if:
- Returns 404 or 403 (proper access control)
- Returns same data as baseline (ID not used)
- Returns empty/error response
- Data is intentionally public (product catalog, etc.)

## OUTPUT (JSON)
{{
  "is_vulnerable": true/false,
  "confidence": "confirmed|likely|possible",
  "severity": "critical|high|medium",
  "title": "IDOR in [endpoint] — accessed [resource type]",
  "evidence": "specific data that proves unauthorized access",
  "test_id_used": "the ID that worked",
  "data_exposed": "type of data (PII, user content, etc.)",
  "reasoning": "why this is IDOR"
}}
"""

AUTH_ANALYSIS_PROMPT = """You are analyzing an endpoint for missing authentication.

## ENDPOINT
{endpoint}

## RESPONSE WITH AUTH
Status: {with_auth_status}
Body length: {with_auth_length}
Body preview:
{with_auth_body}

## RESPONSE WITHOUT AUTH
Status: {no_auth_status}
Body length: {no_auth_length}
Body preview:
{no_auth_body}

## ANALYSIS TASK

Determine if this endpoint should require auth but doesn't.

MISSING AUTH if:
- Endpoint path suggests sensitivity (/admin, /users, /config, /internal)
- Returns 200 with actual data when accessed without auth
- No redirect to login page
- Contains sensitive info (user lists, config, secrets)

NOT MISSING AUTH if:
- Returns 401/403 without auth (proper protection)
- Redirects to /login
- Intentionally public endpoint (/health, /public/*, /docs)
- Returns only non-sensitive data

## OUTPUT (JSON)
{{
  "is_vulnerable": true/false,
  "should_require_auth": true/false,
  "confidence": "confirmed|likely|possible",
  "severity": "critical|high|medium",
  "title": "Missing Authentication on [endpoint]",
  "evidence": "what sensitive data is returned",
  "impact": "what attacker could do",
  "reasoning": "why auth should be required"
}}
"""

INFO_DISCLOSURE_PROMPT = """You are analyzing an HTTP response for information disclosure.

## ENDPOINT
{endpoint}

## RESPONSE
Status: {status}
Headers: {headers}
Body:
{body}

## ANALYSIS TASK

Identify any sensitive information leaked in this response.

SENSITIVE DATA includes:
- API keys (api_key, apiKey, sk-, pk_, aws_, secret_)
- Credentials (password, token, bearer, jwt, session)
- Internal IPs (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
- Internal hostnames (*.internal, *.local, *.corp)
- Database connection strings
- File paths (/var/www, /home/, C:\\Users)
- Stack traces with code paths
- Debug flags (debug=true)

NOT SENSITIVE:
- Placeholder values (<API_KEY>, your-key-here)
- Documentation examples
- Intentionally public info

## OUTPUT (JSON)
{{
  "findings": [
    {{
      "is_vulnerable": true,
      "data_type": "api_key|credential|internal_ip|debug_info|pii",
      "severity": "critical|high|medium|low",
      "title": "Information Disclosure — [type] exposed",
      "evidence": "the specific value found (partially redacted)",
      "location": "where in response",
      "reasoning": "why this is sensitive"
    }}
  ]
}}
"""

OPEN_REDIRECT_PROMPT = """You are analyzing responses for open redirect vulnerabilities.

## ENDPOINT
{endpoint}

## PARAMETER TESTED
{param}

## TEST RESULTS
{results}

## ANALYSIS TASK

Determine if the application redirects to attacker-controlled URLs.

OPEN REDIRECT if:
- 3xx status with Location header pointing to evil.com
- Payload URL appears in Location without validation
- JavaScript redirect to attacker URL in response body

NOT OPEN REDIRECT if:
- Application ignores the URL parameter
- Only redirects to internal paths
- URL is validated/blocked
- Returns error for external URLs

## OUTPUT (JSON)
{{
  "is_vulnerable": true/false,
  "confidence": "confirmed|likely|possible",
  "severity": "medium",
  "title": "Open Redirect via [param] parameter",
  "payload_that_worked": "the payload",
  "evidence": "Location header or response showing redirect",
  "reasoning": "why this is exploitable"
}}
"""
