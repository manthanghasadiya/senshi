"""
IDORTester — cross-account IDOR testing.

Uses two authenticated accounts to test if Account A can access Account B's
resources and vice versa.
"""

from __future__ import annotations

import re
from typing import Any

from senshi.auth.manager import AuthManager
from senshi.core.session import Session
from senshi.reporters.models import Confidence, Finding, ScanMode, Severity
from senshi.utils.logger import get_logger

logger = get_logger("senshi.auth.idor_tester")


class IDORTester:
    """Test for IDOR using multiple authenticated accounts."""

    def __init__(self, auth_manager: AuthManager, base_url: str, **session_kwargs: Any) -> None:
        self.auth = auth_manager
        self.base_url = base_url
        self.session_kwargs = session_kwargs

    async def test_cross_account(
        self,
        endpoint_template: str,
        resource_ids: dict[str, list[str]] | None = None,
    ) -> list[Finding]:
        """
        Test cross-account access.

        Args:
            endpoint_template: URL with {id} placeholder, e.g. "/api/users/{id}/data"
            resource_ids: {"account_a": ["id1"], "account_b": ["id2"]}
                          If None, auto-discovers IDs.
        """
        if not self.auth.has_multi_account:
            logger.info("IDOR test requires 2+ accounts, skipping")
            return []

        accounts = self.auth.get_account_names()
        findings: list[Finding] = []

        # Auto-discover resource IDs if not provided
        if not resource_ids:
            resource_ids = {}
            for acc in accounts:
                ids = await self._discover_ids(endpoint_template, acc)
                if ids:
                    resource_ids[acc] = ids

        if len(resource_ids) < 2:
            logger.debug("Could not discover IDs for cross-account test")
            return findings

        # Cross-test: Account A tries Account B's resources
        for owner, ids in resource_ids.items():
            other_accounts = [a for a in accounts if a != owner]

            for other in other_accounts:
                session = self.auth.get_session(other, base_url=self.base_url, **self.session_kwargs)

                for resource_id in ids:
                    url = endpoint_template.replace("{id}", resource_id)
                    try:
                        response = session.get(url)
                        if response.status_code == 200 and len(response.body) > 50:
                            # Verify it's actual data, not an error page
                            if self._has_real_data(response.body):
                                findings.append(Finding(
                                    title=f"IDOR: {other} can access {owner}'s resources",
                                    severity=Severity.CRITICAL,
                                    confidence=Confidence.CONFIRMED,
                                    category="idor",
                                    description=(
                                        f"Account '{other}' can access resources belonging to "
                                        f"'{owner}' at {endpoint_template}"
                                    ),
                                    mode=ScanMode.DAST,
                                    endpoint=url,
                                    method="GET",
                                    payload=f"ID: {resource_id} (belongs to {owner})",
                                    status_code=response.status_code,
                                    evidence=f"Response body: {response.body[:500]}",
                                    poc_steps=[
                                        f"1. Authenticate as '{other}'",
                                        f"2. GET {url}",
                                        f"3. Observe: response contains {owner}'s data",
                                    ],
                                    cvss_estimate=9.1,
                                ))
                    except Exception as e:
                        logger.debug(f"IDOR test error: {e}")

        return findings

    async def _discover_ids(self, endpoint_template: str, account: str) -> list[str]:
        """Discover resource IDs by making legitimate requests."""
        session = self.auth.get_session(account, base_url=self.base_url, **self.session_kwargs)
        ids: list[str] = []

        # Try common list endpoints
        base_path = re.sub(r'/\{id\}.*', '', endpoint_template)
        try:
            response = session.get(base_path)
            if response.status_code == 200:
                # Extract IDs from JSON response
                id_pattern = re.compile(r'"(?:id|_id|uuid)":\s*"?(\w+)"?')
                found = id_pattern.findall(response.body)
                ids.extend(found[:5])
        except Exception:
            pass

        return ids

    @staticmethod
    def _has_real_data(body: str) -> bool:
        """Check if response contains real data (not just an error)."""
        error_indicators = ["error", "not found", "unauthorized", "forbidden", "access denied"]
        body_lower = body.lower()
        if any(ind in body_lower for ind in error_indicators):
            if len(body) < 200:
                return False
        return True
