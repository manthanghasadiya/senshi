"""
InteractshClient — interact.sh integration for OOB detection.

Uses the public interact.sh service (or self-hosted) for blind
vulnerability detection when the callback server isn't reachable.
"""

from __future__ import annotations

import asyncio
import secrets
import time
from typing import Any
from urllib.parse import urljoin

import httpx

from senshi.utils.logger import get_logger

logger = get_logger("senshi.oob.interactsh_client")


class InteractshClient:
    """
    Client for interact.sh OOB interaction tracking.

    Generates unique subdomains for each payload.
    Polls the interact.sh API to check if any interactions occurred.
    """

    DEFAULT_SERVER = "https://oast.pro"

    def __init__(self, server: str = "", poll_interval: float = 5.0) -> None:
        self.server = server or self.DEFAULT_SERVER
        self.poll_interval = poll_interval
        self._correlation_id: str = ""
        self._session_token: str = ""
        self._registered = False

    async def register(self) -> str:
        """
        Register with interact.sh server and get a correlation ID.

        Returns the base interaction domain.
        """
        self._correlation_id = secrets.token_hex(10)

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.post(
                    f"{self.server}/register",
                    json={"correlation-id": self._correlation_id},
                )
                if response.status_code == 200:
                    data = response.json()
                    self._session_token = data.get("secret-key", "")
                    self._registered = True
                    domain = data.get("domain", f"{self._correlation_id}.oast.pro")
                    logger.info(f"Registered with interact.sh: {domain}")
                    return domain
        except Exception as e:
            logger.debug(f"interact.sh registration failed: {e}")

        # Fallback: use fake domain for testing
        self._registered = False
        return f"{self._correlation_id}.oast.pro"

    def generate_payload_domain(self, tag: str = "") -> str:
        """Generate a unique subdomain for a specific payload."""
        unique = secrets.token_hex(4)
        prefix = f"{tag}-{unique}" if tag else unique
        return f"{prefix}.{self._correlation_id}.oast.pro"

    async def poll_interactions(self, timeout: float = 30.0) -> list[dict[str, Any]]:
        """
        Poll for interaction data.

        Returns list of interactions (DNS, HTTP, SMTP).
        """
        if not self._registered:
            return []

        interactions: list[dict[str, Any]] = []
        start = time.time()

        while time.time() - start < timeout:
            try:
                async with httpx.AsyncClient(timeout=10) as client:
                    response = await client.get(
                        f"{self.server}/poll",
                        params={
                            "id": self._correlation_id,
                            "secret": self._session_token,
                        },
                    )
                    if response.status_code == 200:
                        data = response.json()
                        new_interactions = data.get("data", [])
                        if new_interactions:
                            interactions.extend(new_interactions)
                            return interactions
            except Exception:
                pass

            await asyncio.sleep(self.poll_interval)

        return interactions

    async def check_interaction(self, domain: str, timeout: float = 15.0) -> bool:
        """
        Check if a specific domain received any interaction.

        This is the simple "did it fire?" check for blind vuln detection.
        """
        interactions = await self.poll_interactions(timeout=timeout)
        for interaction in interactions:
            full_id = interaction.get("full-id", "")
            if domain in full_id or self._correlation_id in full_id:
                return True
        return False

    async def deregister(self) -> None:
        """Deregister from interact.sh server."""
        if not self._registered:
            return
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                await client.post(
                    f"{self.server}/deregister",
                    json={
                        "correlation-id": self._correlation_id,
                        "secret-key": self._session_token,
                    },
                )
        except Exception:
            pass
