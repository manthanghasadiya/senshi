"""
Evidence export — bundle scan evidence into a zip file.

Collects: findings JSON, request/response logs, screenshots,
PoCs, and a summary report into a shareable evidence package.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Any

from senshi.reporters.models import Finding, ScanResult
from senshi.utils.logger import get_logger

logger = get_logger("senshi.core.evidence")


class EvidenceCollector:
    """Collect and export scan evidence."""

    def __init__(self, output_dir: str = "") -> None:
        self.output_dir = output_dir or os.path.join(tempfile.gettempdir(), "senshi_evidence")
        os.makedirs(self.output_dir, exist_ok=True)

        self._requests: list[dict[str, Any]] = []
        self._screenshots: list[str] = []

    def log_request(
        self,
        method: str,
        url: str,
        request_headers: dict[str, str],
        request_body: str | None,
        response_status: int,
        response_headers: dict[str, str],
        response_body: str,
        elapsed_ms: float,
    ) -> None:
        """Log an HTTP request/response pair."""
        self._requests.append({
            "timestamp": time.time(),
            "method": method,
            "url": url,
            "request_headers": request_headers,
            "request_body": request_body,
            "response_status": response_status,
            "response_headers": response_headers,
            "response_body": response_body[:5000],
            "elapsed_ms": elapsed_ms,
        })

    def add_screenshot(self, path: str) -> None:
        """Add a screenshot to the evidence collection."""
        if os.path.exists(path):
            self._screenshots.append(path)

    def export_har(self, output_path: str) -> None:
        """Export requests as a HAR (HTTP Archive) file."""
        har = {
            "log": {
                "version": "1.2",
                "creator": {"name": "Senshi", "version": "0.3.0"},
                "entries": [],
            }
        }

        for req in self._requests:
            entry = {
                "startedDateTime": time.strftime(
                    "%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(req["timestamp"])
                ),
                "time": req["elapsed_ms"],
                "request": {
                    "method": req["method"],
                    "url": req["url"],
                    "httpVersion": "HTTP/1.1",
                    "headers": [
                        {"name": k, "value": v}
                        for k, v in req["request_headers"].items()
                    ],
                    "queryString": [],
                    "bodySize": len(req.get("request_body", "") or ""),
                    "postData": {
                        "mimeType": "application/json",
                        "text": req.get("request_body", "") or "",
                    } if req.get("request_body") else {},
                },
                "response": {
                    "status": req["response_status"],
                    "statusText": "",
                    "httpVersion": "HTTP/1.1",
                    "headers": [
                        {"name": k, "value": v}
                        for k, v in req["response_headers"].items()
                    ],
                    "content": {
                        "size": len(req["response_body"]),
                        "mimeType": req["response_headers"].get("content-type", "text/html"),
                        "text": req["response_body"],
                    },
                    "bodySize": len(req["response_body"]),
                },
                "cache": {},
                "timings": {"send": 0, "wait": req["elapsed_ms"], "receive": 0},
            }
            har["log"]["entries"].append(entry)

        with open(output_path, "w") as f:
            json.dump(har, f, indent=2)

        logger.info(f"HAR file exported: {output_path} ({len(self._requests)} entries)")

    def export_bundle(self, result: ScanResult, output_path: str = "") -> str:
        """
        Export complete evidence bundle as a zip file.

        Contains:
        - findings.json — all findings
        - requests.har — HTTP traffic
        - screenshots/ — evidence screenshots
        - summary.md — human-readable summary
        """
        if not output_path:
            target_name = result.target.replace("https://", "").replace("http://", "")
            target_name = "".join(c if c.isalnum() else "_" for c in target_name)
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            output_path = f"senshi_evidence_{target_name}_{timestamp}.zip"

        with tempfile.TemporaryDirectory() as tmpdir:
            # Findings JSON
            findings_path = os.path.join(tmpdir, "findings.json")
            with open(findings_path, "w") as f:
                json.dump(
                    [fi.to_dict() for fi in result.findings],
                    f, indent=2,
                )

            # HAR file
            if self._requests:
                har_path = os.path.join(tmpdir, "requests.har")
                self.export_har(har_path)

            # Screenshots
            if self._screenshots:
                ss_dir = os.path.join(tmpdir, "screenshots")
                os.makedirs(ss_dir)
                for ss in self._screenshots:
                    if os.path.exists(ss):
                        shutil.copy2(ss, ss_dir)

            # Summary
            summary_path = os.path.join(tmpdir, "summary.md")
            with open(summary_path, "w") as f:
                f.write(self._generate_summary(result))

            # Create zip
            with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
                for root, dirs, files in os.walk(tmpdir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, tmpdir)
                        zf.write(file_path, arcname)

        logger.info(f"Evidence bundle exported: {output_path}")
        return output_path

    @staticmethod
    def _generate_summary(result: ScanResult) -> str:
        """Generate a markdown summary of findings."""
        lines = [
            f"# Senshi Scan Report — {result.target}",
            "",
            f"**Provider:** {result.provider} ({result.model})",
            f"**Findings:** {len(result.findings)}",
            f"**Chains:** {len(result.chains)}",
            "",
            "## Findings",
            "",
        ]

        for i, f in enumerate(result.findings, 1):
            lines.append(f"### {i}. [{f.severity.value.upper()}] {f.title}")
            lines.append(f"- **Category:** {f.category}")
            lines.append(f"- **Confidence:** {f.confidence.value}")
            if f.endpoint:
                lines.append(f"- **Endpoint:** {f.endpoint}")
            if f.payload:
                lines.append(f"- **Payload:** `{f.payload}`")
            if f.evidence:
                lines.append(f"- **Evidence:** {f.evidence}")
            if hasattr(f, "poc_curl") and f.poc_curl:
                lines.append(f"- **PoC:** `{f.poc_curl}`")
            lines.append("")

        return "\n".join(lines)
