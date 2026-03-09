"""
Open Redirect vulnerability detection module.

Detects when applications redirect users to attacker-controlled URLs,
enabling phishing attacks and OAuth token theft.
"""

from __future__ import annotations

from senshi.modules.base import VulnModule, TestResult
from senshi.reporters.models import Finding, Severity, Confidence


class OpenRedirectModule(VulnModule):
    """Detect open redirect vulnerabilities."""
    
    name = "open_redirect"
    description = "Open Redirect"
    severity = Severity.MEDIUM
    cwe_id = 601
    payloads_dir = "open_redirect"
    techniques = ["external_redirect"]
    
    # Params that commonly control redirects
    REDIRECT_PARAMS = [
        "url", "redirect", "redirect_url", "redirect_uri",
        "next", "next_url", "return", "return_url", "returnto",
        "goto", "go", "dest", "destination", "target",
        "redir", "rurl", "out", "link", "forward",
        "continue", "callback", "path", "uri",
    ]
    
    # Payloads to test
    PAYLOADS = [
        # Basic external URLs
        ("https://evil.com", "external_https"),
        ("http://evil.com", "external_http"),
        ("//evil.com", "protocol_relative"),
        
        # Bypass techniques
        ("/\\evil.com", "backslash_bypass"),
        ("////evil.com", "multi_slash"),
        ("/\\/\\/evil.com", "mixed_slash"),
        ("https:evil.com", "missing_slash"),
        ("https:/evil.com", "single_slash"),
        
        # URL encoding bypasses
        ("https://evil.com%00", "null_byte"),
        ("https://evil.com%0d%0a", "crlf"),
        ("https:%2f%2fevil.com", "encoded_slashes"),
        
        # Subdomain/path confusion
        ("https://legitimate.com.evil.com", "subdomain_confusion"),
        ("https://evil.com#legitimate.com", "fragment_confusion"),
        ("https://evil.com?legitimate.com", "query_confusion"),
        ("https://legitimate.com@evil.com", "credential_confusion"),
        
        # JavaScript protocol (XSS via redirect)
        ("javascript:alert(1)", "javascript_protocol"),
        ("data:text/html,alert(1)", "data_protocol"),
    ]
    
    def is_applicable(self, endpoint: dict, tech_stack: dict) -> float:
        """Check if endpoint might have redirect functionality."""
        score = 0.0
        
        url_lower = endpoint.get("url", "").lower()
        params = [p.lower() for p in endpoint.get("params", [])]
        
        # Check for redirect-like params
        for param in params:
            if param in self.REDIRECT_PARAMS:
                score += 0.5
            elif any(r in param for r in ["url", "redirect", "next", "return", "goto"]):
                score += 0.3
        
        # Check URL path for redirect indicators
        if any(x in url_lower for x in ["/redirect", "/redir", "/goto", "/out", "/forward", "/link"]):
            score += 0.4
        
        # OAuth/SSO endpoints often have redirects
        if any(x in url_lower for x in ["/oauth", "/login", "/auth", "/sso", "/callback"]):
            score += 0.3
        
        return min(score, 1.0)
    
    def get_injection_points(self, endpoint: dict) -> list[dict]:
        """Return redirect-related params as injection points."""
        points = []
        
        for param in endpoint.get("params", []):
            param_lower = param.lower()
            # Prioritize known redirect params
            if param_lower in self.REDIRECT_PARAMS or \
               any(r in param_lower for r in ["url", "redirect", "next", "return"]):
                points.append({"location": "param", "name": param})
        
        return points
    
    def get_payloads(self, endpoint: dict, tech_stack: dict, max_payloads: int = 20) -> list[tuple[str, str]]:
        """Return redirect test payloads."""
        return self.PAYLOADS[:max_payloads]
    
    def analyze_result(self, result: TestResult) -> Finding | None:
        """Check if redirect to external domain occurred."""
        response = result.response
        payload = result.payload
        
        status = response.get("status", 0)
        headers = response.get("headers", {})
        
        # Get Location header (case-insensitive)
        location = None
        for key, value in headers.items():
            if key.lower() == "location":
                location = value
                break
        
        # Check for redirect status codes
        is_redirect = status in [301, 302, 303, 307, 308]
        
        if not is_redirect:
            # Also check for meta refresh or JS redirect in body
            body = response.get("body", "").lower()
            if "evil.com" in body and ("meta" in body or "location" in body or "redirect" in body):
                return Finding(
                    title="Open Redirect via Response Body",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.LIKELY,
                    category="open_redirect",
                    description="Application includes attacker-controlled URL in redirect mechanism within response body.",
                    endpoint=result.request.get("url", ""),
                    method=result.request.get("method", "GET"),
                    payload=payload,
                    evidence=f"External URL found in response body",
                    response_snippet=response.get("body", "")[:500],
                )
            return None
        
        if not location:
            return None
        
        # Check if Location header points to external domain
        external_indicators = [
            "evil.com",
            "//evil",
            "javascript:",
            "data:",
        ]
        
        location_lower = location.lower()
        
        for indicator in external_indicators:
            if indicator in location_lower:
                # Confirmed open redirect
                severity = Severity.HIGH if "javascript:" in location_lower else Severity.MEDIUM
                
                return Finding(
                    title="Open Redirect Vulnerability",
                    severity=severity,
                    confidence=Confidence.CONFIRMED,
                    category="open_redirect",
                    description=(
                        "Application redirects to attacker-controlled URL without validation. "
                        "This can be used for phishing attacks, OAuth token theft, or SSRF chains."
                    ),
                    endpoint=result.request.get("url", ""),
                    method=result.request.get("method", "GET"),
                    payload=payload,
                    status_code=status,
                    evidence=f"Location header: {location}",
                    response_snippet=f"HTTP {status} → Location: {location}",
                    poc_curl=f"curl -v '{result.request.get('url', '')}' | grep -i location",
                )
        
        # Check if Location matches our payload pattern but with different domain
        # (in case the app is on a different test domain)
        if payload.replace("evil.com", "") in location.lower():
            return Finding(
                title="Potential Open Redirect",
                severity=Severity.MEDIUM,
                confidence=Confidence.LIKELY,
                category="open_redirect",
                description="Application appears to redirect based on user input.",
                endpoint=result.request.get("url", ""),
                method=result.request.get("method", "GET"),
                payload=payload,
                status_code=status,
                evidence=f"Location header reflects payload pattern: {location}",
            )
        
        return None
