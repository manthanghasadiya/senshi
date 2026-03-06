"""
Deserialization Scanner — pickle, JSON prototype pollution, YAML, XXE.
"""

from __future__ import annotations

from typing import Any

from senshi.dast.scanners.base import BaseDastScanner
from senshi.utils.logger import get_logger

logger = get_logger("senshi.dast.scanners.deserialization")


class DeserializationScanner(BaseDastScanner):
    """Deserialization attacks — prototype pollution, pickle, YAML, XXE."""

    def get_scanner_name(self) -> str:
        return "Deserialization Scanner"

    def get_vulnerability_class(self) -> str:
        return "deserialization"
