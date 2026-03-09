"""
Information Disclosure Analysis Prompt.

Used to analyze responses for leaked sensitive data (API keys, secrets, etc.).
"""

INFO_DISCLOSURE_PROMPT = """You are analyzing an HTTP response for information disclosure vulnerabilities.

## CONTEXT
- Endpoint: {endpoint}

## RESPONSE
- Status: {status}
- Headers: {headers}
- Body: {body}

## YOUR TASK

Identify any sensitive information leaked in this response.

### SENSITIVE DATA PATTERNS

1. **Credentials/Secrets**:
   - API keys: `api_key`, `apiKey`, `api-key`, `sk-`, `pk_`, `secret_`
   - AWS: `AKIA`, `aws_access_key`, `aws_secret`
   - Tokens: `token`, `bearer`, `jwt`, `session`
   - Passwords: `password`, `passwd`, `pwd`

2. **Internal Infrastructure**:
   - Internal IPs: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
   - Internal hostnames: `internal.`, `.local`, `.corp`
   - Database connection strings
   - File paths: `/var/www/`, `/home/`, `C:\\Users\\`

3. **Debug Information**:
   - Stack traces
   - Error messages with code paths
   - Version numbers (if exploitable)
   - Debug flags: `debug=true`, `DEBUG`

4. **User Data**:
   - Emails, phone numbers
   - User IDs, session tokens
   - Personal info that shouldn't be exposed

### SEVERITY ASSESSMENT

- CRITICAL: Credentials, API keys, database passwords leaked
- HIGH: Internal infrastructure details, session tokens
- MEDIUM: Debug info, internal paths, version numbers
- LOW: Non-sensitive metadata

### FALSE POSITIVE PREVENTION

- Example/placeholder values: `<API_KEY>`, `your-api-key-here`
- Intentionally public info
- Documentation showing example values

## OUTPUT FORMAT

{{
  "findings": [
    {{
      "is_vulnerable": true,
      "data_type": "api_key|credential|internal_ip|debug_info|pii",
      "severity": "critical|high|medium|low",
      "title": "Information Disclosure — API key exposed",
      "evidence": "the specific sensitive value found (redact partially if needed)",
      "location": "where in the response it was found",
      "reasoning": "why this is sensitive"
    }}
  ]
}}
"""
