"""
Response Verifier - Confirms vulnerabilities with actual response evidence.

Enforces the "No Exploit, No Report" policy.
Each verifier method returns a VerificationResult with a confidence score and
a clear explanation of the evidence found (or not found).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class VerificationResult:
    """Result of verifying an exploitation attempt."""

    verified: bool
    confidence: float  # 0.0 to 1.0
    evidence_type: str  # "response_pattern", "execution", "boolean", "error", "none"
    evidence_detail: str
    false_positive_reason: Optional[str] = None


class ResponseVerifier:
    """
    Strictly verifies exploitation success from HTTP response content.

    Rules enforced:
      CMDi  - MUST see actual shell output (uid=, /etc/passwd content, dir listing)
      SQLi  - MUST see DB error with payload reflection OR data extraction
      XSS   - MUST see unencoded payload in HTML context OR confirmed browser execution
      LFI   - MUST see file content (root:x:0:0, [boot loader], <?php)
      SSRF  - MUST see internal service response or DNS/connection artifacts
    """

    # ── Pattern sets ─────────────────────────────────────────────────────────

    CMDI_STRONG = [
        r"uid=\d+\([^)]+\)\s+gid=\d+",        # linux id
        r"root:x:0:0:",                          # /etc/passwd
        r"Directory of [A-Z]:\\",               # windows dir
        r"Volume Serial Number",                 # windows dir
        r"total \d+\s+drwx",                    # ls -la
        r"www-data:x:\d+:\d+",                  # /etc/passwd www-data entry
    ]

    SQLI_ERROR = [
        r"you have an error in your sql syntax",
        r"warning: mysql",
        r"unclosed quotation mark after",
        r"quoted string not properly terminated",
        r"ora-\d{4,5}",
        r"pg::syntaxerror",
        r"sqlite3?::(?:sql)?exception",
        r"syntax error at or near",
        r"supplied argument is not a valid mysql",
        # SQLite (Node.js / Python)
        r"SQLITE_ERROR",
        r"SqliteError",
        r"SequelizeDatabaseError",
        r"near\s+[\"'].*[\"']\s*:\s*syntax error",
        r"unrecognized token",
    ]

    SQLI_STRONG_DATA = [
        r"admin.*password",
        r"\d+ rows? (in set|affected|returned)",
        r"UNION.*SELECT.*FROM",
    ]

    LFI_STRONG = [
        r"root:x:0:0:root:/root:",
        r"\[boot loader\]",
        r"<\?php",
        r"\[extensions\]\s*\r?\n",
        r"daemon:x:\d+:\d+",
    ]

    SSRF_STRONG = [
        r'"instanceId"',
        r"computeMetadata",
        r"AMI Launch",
        r"security-credentials",
        r'"mac":',
    ]

    # ── Public verify methods ─────────────────────────────────────────────────

    def verify_cmdi(self, response_body: str, payload: str, **kwargs) -> VerificationResult:
        """Verify command injection by requiring actual shell output."""
        for pattern in self.CMDI_STRONG:
            match = re.search(pattern, response_body, re.IGNORECASE)
            if match:
                return VerificationResult(
                    verified=True,
                    confidence=0.95,
                    evidence_type="response_pattern",
                    evidence_detail=f"Shell output matched: {match.group(0)[:80]}",
                )

        # Heuristic: 'id' payload but no uid= → almost certainly FP
        if re.search(r"\bid\b", payload) and "uid=" not in response_body.lower():
            return VerificationResult(
                verified=False,
                confidence=0.05,
                evidence_type="none",
                evidence_detail="",
                false_positive_reason="Payload 'id' sent but no 'uid=' found in response",
            )

        return VerificationResult(
            verified=False,
            confidence=0.0,
            evidence_type="none",
            evidence_detail="No shell output found in response",
            false_positive_reason="Response does not contain recognizable command execution output",
        )

    def verify_sqli(
        self,
        response_body: str,
        payload: str,
        baseline_body: Optional[str] = None,
    ) -> VerificationResult:
        """Verify SQL injection via actual SQL error messages.

        Rules:
        - Error-based: ONLY match real SQL error strings from SQLI_ERROR.
          The error string must NOT already appear in the baseline.
        - SQLI_STRONG_DATA is NOT used here — patterns like admin.*password
          match normal page content and produce massive false positives.
        - Boolean-based length diffs are NOT sufficient on their own.
        """
        body_lower = response_body.lower()
        baseline_lower = baseline_body.lower() if baseline_body else ""

        # Error-based: actual SQL error strings, not in baseline
        for pattern in self.SQLI_ERROR:
            match = re.search(pattern, body_lower)
            if match:
                # CRITICAL: error must NOT be in baseline
                if baseline_body and re.search(pattern, baseline_lower):
                    continue  # This error is always present — not from our payload
                return VerificationResult(
                    verified=True,
                    confidence=0.85,
                    evidence_type="error",
                    evidence_detail=f"DB error matched: {match.group(0)[:80]}",
                )

        return VerificationResult(
            verified=False,
            confidence=0.0,
            evidence_type="none",
            evidence_detail="No SQL injection evidence found",
        )

    def verify_xss(
        self,
        response_body: str,
        payload: str,
        executed_in_browser: bool = False,
        **kwargs,
    ) -> VerificationResult:
        """Verify XSS via browser execution confirmation or unencoded reflection."""
        if executed_in_browser:
            return VerificationResult(
                verified=True,
                confidence=0.99,
                evidence_type="execution",
                evidence_detail="JavaScript payload confirmed to execute in browser context",
            )

        if payload in response_body:
            if f"<script>{payload}" in response_body or f">{payload}<" in response_body:
                return VerificationResult(
                    verified=True,
                    confidence=0.90,
                    evidence_type="reflection",
                    evidence_detail="Payload reflected unencoded inside a script/HTML tag",
                )
            if f'="{payload}"' in response_body or f"='{payload}'" in response_body:
                return VerificationResult(
                    verified=True,
                    confidence=0.85,
                    evidence_type="reflection",
                    evidence_detail="Payload reflected unencoded inside an HTML attribute",
                )
            return VerificationResult(
                verified=True,
                confidence=0.60,
                evidence_type="reflection",
                evidence_detail="Payload reflected unencoded in response body",
            )

        return VerificationResult(
            verified=False,
            confidence=0.0,
            evidence_type="none",
            evidence_detail="Payload not found or was HTML-encoded in response",
        )

    def verify_lfi(self, response_body: str, payload: str, **kwargs) -> VerificationResult:
        """Verify LFI/path traversal by requiring recognizable file content."""
        for pattern in self.LFI_STRONG:
            match = re.search(pattern, response_body, re.IGNORECASE)
            if match:
                return VerificationResult(
                    verified=True,
                    confidence=0.95,
                    evidence_type="response_pattern",
                    evidence_detail=f"File content found: {match.group(0)[:60]}",
                )
        return VerificationResult(
            verified=False,
            confidence=0.0,
            evidence_type="none",
            evidence_detail="No recognizable file content found in response",
        )

    def verify_ssrf(self, response_body: str, payload: str, **kwargs) -> VerificationResult:
        """Verify SSRF by checking for internal service response artifacts.

        CRITICAL: Exclude matches that are just payload reflection.
        The payload URL may be echoed in error pages (e.g., Express error titles),
        sometimes with slight mangling (http:// -> http:/).  Any SSRF keyword
        that also appears inside the payload itself is NOT evidence of server fetch.
        """
        body_lower = response_body.lower()
        payload_lower = payload.lower()

        # Check if the payload itself (or a significant portion) is reflected
        payload_reflected = payload_lower in body_lower

        # Also detect partial reflection: key domain/path parts of the payload
        # appear in the body (e.g., "metadata.google.internal" from the URL)
        payload_parts_reflected = False
        # Extract distinctive parts from the payload (hostname, path segments)
        for part in payload_lower.replace("://", " ").replace("/", " ").split():
            if len(part) > 6 and part in body_lower:
                payload_parts_reflected = True
                break

        for pattern in self.SSRF_STRONG:
            match = re.search(pattern, response_body, re.IGNORECASE)
            if match:
                matched_text = match.group(0)

                # KEY CHECK: If the matched keyword is a substring of our payload,
                # it's almost certainly just our payload echoed back — NOT a real
                # server-side fetch. This catches both exact and partial reflection.
                if matched_text.lower() in payload_lower:
                    continue  # This keyword came from our own payload

                # If payload parts are reflected and the match is near them, skip
                if payload_reflected or payload_parts_reflected:
                    # Check if the match position overlaps with payload text
                    payload_pos = body_lower.find(payload_lower) if payload_reflected else -1
                    if payload_pos != -1:
                        match_start = match.start()
                        match_end = match.end()
                        payload_end = payload_pos + len(payload_lower)
                        if payload_pos <= match_start and match_end <= payload_end + 50:
                            continue  # Match is within or near the reflected payload

                # Match found OUTSIDE payload reflection — likely real SSRF
                return VerificationResult(
                    verified=True,
                    confidence=0.90,
                    evidence_type="response_pattern",
                    evidence_detail=f"Internal service response: {matched_text[:60]}",
                )

        # Connection error artifacts — only suppress if the EXACT full payload URL
        # is reflected (e.g., in an Express error title). Partial reflection (IP/host
        # appearing in the error message) is expected for real connection errors.
        if not payload_reflected:
            connection_errors = ["urlopen error", "connection refused", "econnrefused", "timed out"]
            for err in connection_errors:
                if err in body_lower:
                    return VerificationResult(
                        verified=True,
                        confidence=0.70,
                        evidence_type="error",
                        evidence_detail=f"Server attempted connection (error: {err})",
                    )

        return VerificationResult(
            verified=False,
            confidence=0.0,
            evidence_type="none",
            evidence_detail="No SSRF evidence — URL was reflected/echoed, not fetched by server",
        )

    def verify(self, vuln_type: str, response_body: str, payload: str, **kwargs) -> VerificationResult:
        """Dispatch to the correct verifier based on vuln_type."""
        dispatch = {
            "cmdi": self.verify_cmdi,
            "sqli": self.verify_sqli,
            "xss": self.verify_xss,
            "lfi": self.verify_lfi,
            "path_traversal": self.verify_lfi,
            "ssrf": self.verify_ssrf,
        }
        fn = dispatch.get(vuln_type.lower())
        if fn:
            return fn(response_body, payload, **kwargs)  # type: ignore[call-arg]
        # Unknown type — return unverified
        return VerificationResult(
            verified=False,
            confidence=0.0,
            evidence_type="none",
            evidence_detail=f"No verifier implemented for {vuln_type}",
        )
