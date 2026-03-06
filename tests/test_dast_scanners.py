"""Tests for DAST scanners."""

from __future__ import annotations

import pytest

from senshi.reporters.models import Finding, Severity, Confidence, ScanMode


class TestFindingModel:
    """Test the Finding data model."""

    def test_create_finding(self):
        finding = Finding(
            title="Test XSS",
            severity=Severity.HIGH,
            confidence=Confidence.LIKELY,
            category="xss",
            description="Test finding",
            mode=ScanMode.DAST,
            endpoint="/test",
            method="GET",
            payload="<script>alert(1)</script>",
        )
        assert finding.title == "Test XSS"
        assert finding.severity == Severity.HIGH
        assert finding.mode == ScanMode.DAST

    def test_finding_to_dict(self):
        finding = Finding(
            title="Test",
            severity=Severity.MEDIUM,
            confidence=Confidence.POSSIBLE,
        )
        d = finding.to_dict()
        assert d["title"] == "Test"
        assert d["severity"] == "medium"
        assert d["confidence"] == "possible"

    def test_finding_from_dict(self):
        data = {
            "title": "Test",
            "severity": "high",
            "confidence": "confirmed",
        }
        finding = Finding.from_dict(data)
        assert finding.severity == Severity.HIGH

    def test_summary_line(self):
        finding = Finding(
            title="XSS in search",
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            endpoint="/api/search",
        )
        line = finding.summary_line()
        assert "HIGH" in line
        assert "XSS in search" in line
        assert "/api/search" in line


class TestSeverity:
    """Test Severity enum."""

    def test_severity_ranking(self):
        assert Severity.CRITICAL.rank == 5
        assert Severity.HIGH.rank == 4
        assert Severity.INFO.rank == 1

    def test_severity_comparison(self):
        assert Severity.HIGH < Severity.CRITICAL
        assert Severity.LOW < Severity.MEDIUM
