"""
JSON reporter — machine-readable JSON report output.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from senshi.reporters.models import ScanResult
from senshi.utils.logger import get_logger

logger = get_logger("senshi.reporters.json_report")


def generate_json_report(result: ScanResult, output_path: str | None = None) -> str:
    """
    Generate a JSON report from scan results.

    Args:
        result: Complete scan result.
        output_path: Optional file path to write the report to.

    Returns:
        JSON string of the report.
    """
    report = result.to_dict()
    json_str = json.dumps(report, indent=2, default=str)

    if output_path:
        Path(output_path).write_text(json_str, encoding="utf-8")
        logger.info(f"JSON report saved to {output_path}")

    return json_str


def load_findings_from_json(path: str) -> ScanResult:
    """Load scan results from a JSON report file."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return ScanResult.model_validate(data)
