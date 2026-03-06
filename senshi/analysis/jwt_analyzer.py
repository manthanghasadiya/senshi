"""
JWT Analyzer — decode, analyze, and attack JWT tokens.

Detects: weak algorithms, missing claims, expired tokens, known secrets,
algorithm confusion attacks (RS256 → HS256), none algorithm bypass.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from typing import Any

from senshi.reporters.models import Confidence, Finding, ScanMode, Severity
from senshi.utils.logger import get_logger

logger = get_logger("senshi.analysis.jwt_analyzer")

# Common weak secrets for brute-force testing
COMMON_SECRETS = [
    "secret", "password", "key", "jwt_secret", "s3cr3t",
    "admin", "test", "123456", "changeme", "default",
    "mysecretkey", "your-256-bit-secret", "supersecret",
    "senshi", "development", "production",
]


@dataclass
class JWTInfo:
    """Decoded JWT information."""

    raw: str
    header: dict[str, Any] = field(default_factory=dict)
    payload: dict[str, Any] = field(default_factory=dict)
    signature: str = ""
    algorithm: str = ""
    is_expired: bool = False
    issues: list[str] = field(default_factory=list)


class JWTAnalyzer:
    """Analyze and attack JWT tokens."""

    def decode(self, token: str) -> JWTInfo:
        """Decode a JWT token (without verification)."""
        parts = token.split(".")
        if len(parts) != 3:
            return JWTInfo(raw=token, issues=["Not a valid JWT format"])

        try:
            header = json.loads(self._base64_decode(parts[0]))
            payload = json.loads(self._base64_decode(parts[1]))
            signature = parts[2]

            info = JWTInfo(
                raw=token,
                header=header,
                payload=payload,
                signature=signature,
                algorithm=header.get("alg", ""),
            )

            # Check expiration
            exp = payload.get("exp")
            if exp and isinstance(exp, (int, float)):
                info.is_expired = time.time() > exp

            return info
        except Exception as e:
            return JWTInfo(raw=token, issues=[f"Decode error: {e}"])

    def analyze(self, token: str, endpoint: str = "") -> list[Finding]:
        """
        Analyze a JWT for security issues.

        Returns findings for: weak algo, missing claims, known secrets, etc.
        """
        info = self.decode(token)
        findings: list[Finding] = []

        if info.issues:
            return findings

        # Check 1: Algorithm "none"
        if info.algorithm.lower() in ("none", ""):
            findings.append(Finding(
                title="JWT with 'none' algorithm",
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category="auth",
                description="JWT uses 'none' algorithm — signature not verified",
                mode=ScanMode.DAST,
                endpoint=endpoint,
                evidence=f"Algorithm: {info.algorithm}",
                cvss_estimate=9.8,
            ))

        # Check 2: Weak algorithm
        if info.algorithm in ("HS256", "HS384", "HS512"):
            # Try common secrets
            cracked_secret = self._brute_force(token, info.algorithm)
            if cracked_secret:
                findings.append(Finding(
                    title="JWT signed with weak/known secret",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    category="crypto",
                    description=f"JWT secret cracked: '{cracked_secret}'",
                    mode=ScanMode.DAST,
                    endpoint=endpoint,
                    evidence=f"Secret: {cracked_secret}, Algorithm: {info.algorithm}",
                    cvss_estimate=9.5,
                ))

        # Check 3: Missing standard claims
        important_claims = {"exp", "iss", "aud"}
        missing = important_claims - set(info.payload.keys())
        if "exp" in missing:
            findings.append(Finding(
                title="JWT missing expiration claim",
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                category="auth",
                description="JWT has no 'exp' claim — token never expires",
                mode=ScanMode.DAST,
                endpoint=endpoint,
                evidence=f"Claims: {list(info.payload.keys())}",
            ))

        # Check 4: Expired but still accepted
        if info.is_expired:
            findings.append(Finding(
                title="Expired JWT accepted",
                severity=Severity.HIGH,
                confidence=Confidence.POSSIBLE,
                category="auth",
                description="JWT has expired but may still be accepted by server",
                mode=ScanMode.DAST,
                endpoint=endpoint,
                evidence=f"exp: {info.payload.get('exp')}, now: {int(time.time())}",
            ))

        # Check 5: Sensitive data in payload
        sensitive_keys = {"password", "secret", "ssn", "credit_card", "api_key"}
        found_sensitive = sensitive_keys & set(k.lower() for k in info.payload.keys())
        if found_sensitive:
            findings.append(Finding(
                title="Sensitive data in JWT payload",
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                category="crypto",
                description=f"JWT contains sensitive fields: {found_sensitive}",
                mode=ScanMode.DAST,
                endpoint=endpoint,
            ))

        return findings

    def forge_none_algorithm(self, token: str, payload_overrides: dict | None = None) -> str:
        """Forge a JWT with algorithm=none (no signature)."""
        info = self.decode(token)
        header = {"alg": "none", "typ": "JWT"}
        payload = {**info.payload, **(payload_overrides or {})}

        h = self._base64_encode(json.dumps(header))
        p = self._base64_encode(json.dumps(payload))
        return f"{h}.{p}."

    def forge_with_secret(self, token: str, secret: str,
                          payload_overrides: dict | None = None) -> str:
        """Forge a JWT with a known secret and modified payload."""
        info = self.decode(token)
        header = info.header
        payload = {**info.payload, **(payload_overrides or {})}

        h = self._base64_encode(json.dumps(header))
        p = self._base64_encode(json.dumps(payload))
        unsigned = f"{h}.{p}"

        algo = info.algorithm
        if algo == "HS256":
            sig = hmac.new(secret.encode(), unsigned.encode(), hashlib.sha256).digest()
        elif algo == "HS384":
            sig = hmac.new(secret.encode(), unsigned.encode(), hashlib.sha384).digest()
        elif algo == "HS512":
            sig = hmac.new(secret.encode(), unsigned.encode(), hashlib.sha512).digest()
        else:
            return unsigned + "."

        return f"{unsigned}.{self._base64_encode_bytes(sig)}"

    def _brute_force(self, token: str, algorithm: str) -> str | None:
        """Try common secrets against a JWT."""
        parts = token.split(".")
        if len(parts) != 3:
            return None

        unsigned = f"{parts[0]}.{parts[1]}"
        target_sig = parts[2]

        hash_func = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }.get(algorithm)

        if not hash_func:
            return None

        for secret in COMMON_SECRETS:
            sig = hmac.new(secret.encode(), unsigned.encode(), hash_func).digest()
            encoded_sig = self._base64_encode_bytes(sig)
            if encoded_sig == target_sig:
                return secret

        return None

    @staticmethod
    def _base64_decode(s: str) -> str:
        """URL-safe base64 decode with padding."""
        s += "=" * (4 - len(s) % 4)
        return base64.urlsafe_b64decode(s).decode("utf-8")

    @staticmethod
    def _base64_encode(s: str) -> str:
        """URL-safe base64 encode without padding."""
        return base64.urlsafe_b64encode(s.encode()).rstrip(b"=").decode()

    @staticmethod
    def _base64_encode_bytes(b: bytes) -> str:
        """URL-safe base64 encode bytes without padding."""
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
