import json
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TYPE_CHECKING

from senshi.core.session import Session, Response
from senshi.reporters.models import Finding, Severity, Confidence, ScanMode

if TYPE_CHECKING:
    from senshi.ai.brain import Brain


@dataclass
class TestResult:
    """Result from a single payload test."""
    payload: str
    technique: str
    request: dict
    response: dict
    baseline: dict | None = None
    elapsed_time: float = 0.0
    callback_received: bool = False


class VulnModule(ABC):
    """Base class for all vulnerability detection modules."""
    
    name: str
    description: str
    severity: Severity = Severity.HIGH
    cwe_id: int = 0
    payloads_dir: str = ""
    techniques: list[str] = ["error_based"]
    
    def __init__(self, session: Session, brain: "Brain", callback_server: str | None = None):
        self.session = session
        self.brain = brain
        self.callback_server = callback_server
        self._payloads_cache: dict[str, list[str]] = {}
    
    # ── Abstract Methods ──────────────────────────────────────────
    
    @abstractmethod
    def is_applicable(self, endpoint: dict, tech_stack: dict) -> float:
        """
        Return likelihood (0-1) that this vuln type applies to this endpoint.
        """
        pass
    
    @abstractmethod
    def get_injection_points(self, endpoint: dict) -> list[dict]:
        """
        Return list of injection points for this endpoint.
        Each injection point: {"location": "param|header|path|body", "name": str}
        """
        pass
    
    @abstractmethod
    def analyze_result(self, result: TestResult) -> Finding | None:
        """
        Analyze a test result and return Finding if vulnerable.
        """
        pass
    
    # ── Payload Management ────────────────────────────────────────
    
    def load_payloads(self, filename: str) -> list[str]:
        """Load payloads from file, with caching."""
        if filename in self._payloads_cache:
            return self._payloads_cache[filename]
        
        # Path logic sensitive to the directory structure
        path = Path(__file__).parent.parent / "payloads" / self.payloads_dir / filename
        if not path.exists():
            return []
        
        payloads = [
            line.strip() 
            for line in path.read_text(encoding="utf-8").splitlines() 
            if line.strip() and not line.startswith("#")
        ]
        self._payloads_cache[filename] = payloads
        return payloads
    
    def get_payloads(self, endpoint: dict, tech_stack: dict, max_payloads: int = 30) -> list[tuple[str, str]]:
        """
        Get payloads for testing, optionally using LLM for smart selection.
        Returns: List of (payload, technique) tuples
        """
        all_payloads: list[tuple[str, str]] = []
        
        for technique in self.techniques:
            payloads = self.load_payloads(f"{technique}.txt")
            all_payloads.extend([(p, technique) for p in payloads])
        
        if len(all_payloads) == 0:
            return []

        if len(all_payloads) <= max_payloads:
            return all_payloads
        
        # Use LLM to select most likely payloads
        return self._smart_select_payloads(all_payloads, endpoint, tech_stack, max_payloads)
    
    def _smart_select_payloads(
        self, 
        payloads: list[tuple[str, str]], 
        endpoint: dict, 
        tech_stack: dict,
        max_payloads: int
    ) -> list[tuple[str, str]]:
        """Use LLM to select most effective payloads."""
        prompt = f"""
        Select the {max_payloads} most effective {self.name} payloads for this target:
        
        Endpoint: {endpoint.get('url')}
        Params: {endpoint.get('params', [])}
        Tech Stack: {tech_stack}
        
        Available payloads (index: payload):
        {chr(10).join(f"{i}: {p[0][:60]}... [{p[1]}]" for i, p in enumerate(payloads[:100]))}
        
        Return JSON array of indices, e.g.: [0, 5, 12, ...]
        
        Prioritize:
        1. Payloads matching detected tech stack
        2. Diverse techniques (mix of error-based, blind, etc.)
        3. Known effective payloads for this context
        """
        
        try:
            # Use Brain's core intelligence
            result = self.brain.think(
                system_prompt="You are a senior security researcher selecting the best payloads.",
                user_prompt=prompt,
                json_schema={"type": "object", "properties": {"indices": {"type": "array", "items": {"type": "integer"}}}}
            )
            
            indices = []
            if isinstance(result, dict):
                indices = result.get("indices", [])
            elif isinstance(result, list):
                indices = result
                
            return [payloads[i] for i in indices if i < len(payloads)][:max_payloads]
        except Exception:
            # Fallback: return first N payloads
            return payloads[:max_payloads]
    
    # ── Testing Methods ───────────────────────────────────────────
    
    def test(self, endpoint: dict, tech_stack: dict) -> list[Finding]:
        """Run all applicable tests on this endpoint."""
        if self.is_applicable(endpoint, tech_stack) < 0.3:
            return []
        
        findings = []
        injection_points = self.get_injection_points(endpoint)
        payloads = self.get_payloads(endpoint, tech_stack)
        
        for point in injection_points:
            for payload, technique in payloads:
                result = self._execute_test(endpoint, point, payload, technique)
                finding = self.analyze_result(result)
                if finding:
                    findings.append(finding)
                    break  # Found vuln on this injection point, move to next
        
        return findings
    
    def _execute_test(
        self, 
        endpoint: dict, 
        injection_point: dict, 
        payload: str,
        technique: str
    ) -> TestResult:
        """Execute a single payload test."""
        # Get baseline (endpoint is dict here, Session expects path or URL)
        url = endpoint["url"]
        method = endpoint.get("method", "GET")
        
        baseline_response = self.session.get_baseline(url)
        
        # Inject payload
        injected_url, injected_body, injected_headers = self._inject_payload(
            endpoint, injection_point, payload
        )
        
        # Send request
        start_time = time.time()
        response = self.session.request(
            method=method,
            path=injected_url,
            data=injected_body,
            headers=injected_headers,
            allow_redirects=(technique != "open_redirect"),
        )
        elapsed = time.time() - start_time
        
        # Check for OOB callback if applicable
        callback_received = False
        if technique == "oob" and self.callback_server:
            # Placeholder for OOB check logic
            pass
        
        return TestResult(
            payload=payload,
            technique=technique,
            request={
                "url": injected_url,
                "method": method,
                "injection_point": injection_point,
            },
            response={
                "status": response.status_code,
                "body": response.body,
                "headers": response.headers,
                "length": len(response.body),
            },
            baseline={
                "status": baseline_response.status_code,
                "body": baseline_response.body,
                "length": len(baseline_response.body),
            },
            elapsed_time=elapsed,
            callback_received=callback_received,
        )

    def _inject_payload(self, endpoint: dict, injection_point: dict, payload: str) -> tuple[str, Any, dict]:
        """Inject payload into the specified point."""
        url = endpoint["url"]
        body = None
        headers = {}
        
        loc = injection_point["location"]
        name = injection_point["name"]
        
        if loc == "param":
            # Simple URL param injection for now
            if "?" in url:
                url += f"&{name}={payload}"
            else:
                url += f"?{name}={payload}"
        elif loc == "body":
            body = {name: payload}
        elif loc == "header":
            headers[name] = payload
            
        return url, body, headers
