"""
Auth Analysis Prompt.

Used to test for missing authentication on sensitive endpoints.
"""

AUTH_ANALYSIS_PROMPT = """You are analyzing an endpoint for missing authentication vulnerabilities.

## CONTEXT
- Endpoint: {endpoint}
- Endpoint appears to be: {endpoint_type} (based on URL path)

## RESPONSE WITHOUT AUTH
- Status: {no_auth_status}
- Body length: {no_auth_length}
- Body preview: {no_auth_body}

## RESPONSE WITH AUTH (for comparison)
- Status: {with_auth_status}
- Body length: {with_auth_length}
- Body preview: {with_auth_body}

## YOUR TASK

Determine if this endpoint should require authentication but doesn't.

### MISSING AUTH INDICATORS

1. **Sensitive endpoint accessible**: Admin, config, user management endpoints return data without auth
2. **Same response with/without auth**: No difference = no auth check
3. **No redirect to login**: Should redirect to /login but returns data instead
4. **Sensitive data in response**: User lists, config values, API keys, internal data

### ENDPOINT CLASSIFICATION

Endpoints that SHOULD require auth:
- `/admin/*`, `/manage/*`, `/internal/*`
- `/api/users`, `/api/config`, `/api/settings`
- `/debug/*`, `/metrics`, `/health` (with sensitive data)
- Any endpoint returning user data, config, or internal info

Endpoints that might be intentionally public:
- `/login`, `/register`, `/forgot-password`
- `/api/products`, `/api/public/*`
- `/health` (basic OK response only)
- Static assets, documentation

### SEVERITY ASSESSMENT

- CRITICAL: Admin functionality accessible, can modify data/users
- HIGH: Sensitive data exposed (user lists, config, internal data)
- MEDIUM: Metadata or limited info exposed

## OUTPUT FORMAT

{{
  "endpoint_should_require_auth": true/false,
  "endpoint_type": "admin|config|user_management|internal|public",
  "findings": [
    {{
      "is_vulnerable": true,
      "confidence": "confirmed|likely|possible",
      "severity": "critical|high|medium",
      "title": "Missing Authentication on {endpoint}",
      "evidence": "what sensitive data is returned",
      "impact": "what an attacker could do",
      "reasoning": "why this endpoint should require auth"
    }}
  ]
}}
"""
