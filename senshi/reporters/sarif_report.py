"""
SARIF reporter — SARIF format for CI/CD integration.

SARIF (Static Analysis Results Interchange Format) is a standard
used by GitHub, Azure DevOps, and other CI/CD tools.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from senshi import __version__
from senshi.reporters.models import ScanResult, Severity
from senshi.utils.logger import get_logger

logger = get_logger("senshi.reporters.sarif_report")

SARIF_SEVERITY_MAP = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def generate_sarif_report(
    result: ScanResult, output_path: str | None = None
) -> str:
    """Generate a SARIF report from scan results."""
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    rule_ids: set[str] = set()

    for i, finding in enumerate(result.findings):
        rule_id = f"senshi/{finding.category}/{i}"

        if rule_id not in rule_ids:
            rule_ids.add(rule_id)
            rules.append({
                "id": rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.description or finding.title},
                "defaultConfiguration": {
                    "level": SARIF_SEVERITY_MAP.get(finding.severity, "warning"),
                },
                "properties": {
                    "security-severity": str(finding.cvss_estimate or 5.0),
                    "tags": ["security", finding.category],
                },
            })

        sarif_result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": SARIF_SEVERITY_MAP.get(finding.severity, "warning"),
            "message": {
                "text": finding.description or finding.title,
            },
            "locations": [],
        }

        # Add location
        if finding.file_path:
            sarif_result["locations"].append({
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.file_path},
                    "region": {
                        "startLine": finding.line_number or 1,
                    },
                },
            })
        elif finding.endpoint:
            sarif_result["locations"].append({
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.endpoint},
                },
            })

        # Add properties
        sarif_result["properties"] = {
            "confidence": finding.confidence.value,
            "category": finding.category,
        }
        if finding.payload:
            sarif_result["properties"]["payload"] = finding.payload
        if finding.evidence:
            sarif_result["properties"]["evidence"] = finding.evidence

        results.append(sarif_result)

    sarif: dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Senshi",
                        "version": __version__,
                        "informationUri": "https://github.com/manthanghasadiya/senshi",
                        "rules": rules,
                    },
                },
                "results": results,
            },
        ],
    }

    json_str = json.dumps(sarif, indent=2)

    if output_path:
        Path(output_path).write_text(json_str, encoding="utf-8")
        logger.info(f"SARIF report saved to {output_path}")

    return json_str
