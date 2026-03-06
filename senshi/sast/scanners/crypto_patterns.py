"""
Crypto pattern scanner (SAST) — weak crypto, hardcoded secrets, insecure random.
"""

from __future__ import annotations

from senshi.sast.scanners.base import BaseSastScanner
from senshi.sast.file_parser import ParsedFile


class CryptoPatternScanner(BaseSastScanner):
    """Find cryptographic and secrets management issues."""

    def get_scanner_name(self) -> str:
        return "SAST Crypto Scanner"

    def get_analysis_prompt(self) -> str:
        return (
            "Focus specifically on CRYPTOGRAPHIC vulnerabilities: "
            "weak hashing algorithms (MD5, SHA1), hardcoded secrets and API keys, "
            "insecure random number generation, weak encryption (DES, RC4), "
            "missing salt in password hashing, and exposed credentials in code."
        )

    def filter_relevant_files(self) -> list[ParsedFile]:
        keywords = [
            "crypto", "hash", "md5", "sha1", "sha256", "encrypt", "decrypt",
            "random", "secret", "key", "token", "password", "api_key",
            "private_key", "certificate", "ssl", "tls", "hmac", "aes",
            "base64", "encode", "decode",
        ]
        return [
            f for f in self.files
            if any(kw in f.content.lower() for kw in keywords)
        ]
