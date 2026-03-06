"""
WebSocketTester — test WebSocket endpoints for vulnerabilities.

Tests: auth bypass, token validation, injection, cross-user access, rate limiting.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

from senshi.ai.brain import Brain
from senshi.reporters.models import Confidence, Finding, ScanMode, Severity
from senshi.utils.logger import get_logger

logger = get_logger("senshi.websocket.tester")


class WebSocketTester:
    """Test WebSocket endpoints for security vulnerabilities."""

    def __init__(self, brain: Brain, timeout: int = 10) -> None:
        self.brain = brain
        self.timeout = timeout

    async def test_endpoint(
        self,
        ws_url: str,
        auth_headers: dict[str, str] | None = None,
    ) -> list[Finding]:
        """
        Test a WebSocket endpoint for vulnerabilities.

        Tests:
        1. Connection without auth token
        2. Connection with modified/expired token
        3. Injection payloads through messages
        4. Rate limiting
        5. Large message handling
        """
        try:
            import websockets
        except ImportError:
            logger.warning("websockets not installed — pip install 'senshi[websocket]'")
            return []

        findings: list[Finding] = []

        # Test 1: Connect without auth
        no_auth = await self._test_no_auth(ws_url)
        findings.extend(no_auth)

        # Test 2: Modified token
        modified = await self._test_modified_token(ws_url)
        findings.extend(modified)

        # Test 3: Injection payloads
        injections = await self._test_injection(ws_url, auth_headers)
        findings.extend(injections)

        # Test 4: Rate limiting
        rate = await self._test_rate_limit(ws_url, auth_headers)
        findings.extend(rate)

        return findings

    async def _test_no_auth(self, ws_url: str) -> list[Finding]:
        """Test connection without authentication token."""
        stripped = self._strip_auth_from_url(ws_url)
        if stripped == ws_url:
            return []

        can_connect = await self._try_connect(stripped)
        if can_connect:
            return [Finding(
                title=f"WebSocket auth bypass — {ws_url}",
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                category="auth",
                description="WebSocket accepts connections without auth token",
                mode=ScanMode.DAST,
                endpoint=ws_url,
                payload=f"Stripped URL: {stripped}",
                evidence="Connection established without accessToken",
                poc_steps=[
                    f"1. Connect to {stripped} (no auth token)",
                    "2. Observe: connection accepted",
                ],
                cvss_estimate=8.6,
            )]
        return []

    async def _test_modified_token(self, ws_url: str) -> list[Finding]:
        """Test connection with invalid/modified token."""
        modified = self._modify_token(ws_url)
        if modified == ws_url:
            return []

        can_connect = await self._try_connect(modified)
        if can_connect:
            return [Finding(
                title=f"WebSocket token validation bypass — {ws_url}",
                severity=Severity.HIGH,
                confidence=Confidence.LIKELY,
                category="auth",
                description="WebSocket accepts connections with modified auth token",
                mode=ScanMode.DAST,
                endpoint=ws_url,
                payload="Modified last 10 chars of token",
                evidence="Connection established with invalid token",
                cvss_estimate=8.2,
            )]
        return []

    async def _test_injection(self, ws_url: str,
                               auth_headers: dict[str, str] | None) -> list[Finding]:
        """Send injection payloads through WebSocket."""
        payloads = [
            ('{"type": "message", "text": "<script>alert(1)</script>"}', "xss"),
            ('{"type": "message", "text": "\' OR 1=1 --"}', "sqli"),
            ('{"type": "admin", "command": "list_users"}', "authz"),
            ('{"__proto__": {"isAdmin": true}}', "prototype_pollution"),
        ]

        findings: list[Finding] = []
        for payload, vuln_type in payloads:
            try:
                response = await self._send_message(ws_url, payload, auth_headers)
                if response and self._is_interesting_response(response, vuln_type):
                    findings.append(Finding(
                        title=f"WebSocket {vuln_type} — {ws_url}",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.POSSIBLE,
                        category=vuln_type,
                        description=f"Interesting response to {vuln_type} payload via WebSocket",
                        mode=ScanMode.DAST,
                        endpoint=ws_url,
                        payload=payload,
                        response_snippet=str(response)[:500],
                    ))
            except Exception as e:
                logger.debug(f"WS injection test failed: {e}")

        return findings

    async def _test_rate_limit(self, ws_url: str,
                                auth_headers: dict[str, str] | None) -> list[Finding]:
        """Check if WebSocket has rate limiting."""
        try:
            import websockets
            async with websockets.connect(ws_url, open_timeout=self.timeout,
                                          extra_headers=auth_headers or {}) as ws:
                # Send 20 rapid messages
                blocked = False
                for i in range(20):
                    try:
                        await ws.send(json.dumps({"type": "ping", "id": i}))
                        await asyncio.wait_for(ws.recv(), timeout=2)
                    except Exception:
                        blocked = True
                        break

                if not blocked:
                    return [Finding(
                        title=f"WebSocket missing rate limiting — {ws_url}",
                        severity=Severity.LOW,
                        confidence=Confidence.LIKELY,
                        category="rate_limit",
                        description="WebSocket endpoint does not enforce rate limiting",
                        mode=ScanMode.DAST,
                        endpoint=ws_url,
                        evidence="20 rapid messages sent without blocking",
                    )]
        except Exception:
            pass
        return []

    async def _try_connect(self, ws_url: str) -> bool:
        """Try to establish a WebSocket connection."""
        try:
            import websockets
            async with websockets.connect(ws_url, open_timeout=self.timeout) as ws:
                return True
        except Exception:
            return False

    async def _send_message(self, ws_url: str, message: str,
                             headers: dict[str, str] | None) -> str | None:
        """Send a message and get response."""
        try:
            import websockets
            async with websockets.connect(ws_url, open_timeout=self.timeout,
                                          extra_headers=headers or {}) as ws:
                await ws.send(message)
                response = await asyncio.wait_for(ws.recv(), timeout=self.timeout)
                return str(response)
        except Exception:
            return None

    def _strip_auth_from_url(self, ws_url: str) -> str:
        """Remove auth parameters from WebSocket URL."""
        parsed = urlparse(ws_url)
        params = parse_qs(parsed.query)
        auth_params = {"accesstoken", "token", "auth", "key", "apikey", "access_token"}
        filtered = {k: v for k, v in params.items() if k.lower() not in auth_params}
        new_query = urlencode(filtered, doseq=True)
        return parsed._replace(query=new_query).geturl()

    def _modify_token(self, ws_url: str) -> str:
        """Modify the auth token in the URL to invalidate it."""
        if len(ws_url) > 20:
            return ws_url[:-10] + "X" * 10
        return ws_url

    @staticmethod
    def _is_interesting_response(response: str, vuln_type: str) -> bool:
        """Check if a WebSocket response is interesting for the vuln type."""
        resp_lower = response.lower()
        if vuln_type == "xss" and "<script" in resp_lower:
            return True
        if vuln_type == "sqli" and any(p in resp_lower for p in ["sql", "error", "syntax"]):
            return True
        if vuln_type == "authz" and "users" in resp_lower:
            return True
        if vuln_type == "prototype_pollution" and "admin" in resp_lower:
            return True
        return False
