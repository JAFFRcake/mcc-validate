"""Tests for the HTML reporter."""

from __future__ import annotations

from mcc_validate.models import (
    Finding,
    LayerResult,
    Severity,
    ValidationLayer,
    ValidationReport,
)
from mcc_validate.reporters import html_reporter


def _sample_report(valid: bool = True) -> ValidationReport:
    """Create a sample report for testing."""
    report = ValidationReport(
        certificate_id="test-001",
        certificate_name="TestModel",
        certificate_version="1.0.0",
        risk_tier=3,
        status="active",
        expires="2027-01-01",
    )
    lr1 = LayerResult(layer=ValidationLayer.SCHEMA, checks_passed=10)
    lr2 = LayerResult(layer=ValidationLayer.TIER_COMPLIANCE, checks_passed=20)
    if not valid:
        lr2.findings.append(Finding(
            rule_id="T3-DATA-001",
            layer=ValidationLayer.TIER_COMPLIANCE,
            severity=Severity.ERROR,
            message="Missing dataController for clinical dataset",
            path="trainingData.datasets[0].dataController",
            reference="MCC-STD-001 §5.4.3",
        ))
    report.layer_results = [lr1, lr2]
    return report


class TestHTMLReporter:
    """Test HTML report generation."""

    def test_valid_report_contains_valid(self) -> None:
        html = html_reporter.render_report(_sample_report(valid=True))
        assert "VALID" in html
        assert "<!DOCTYPE html>" in html

    def test_invalid_report_contains_invalid(self) -> None:
        html = html_reporter.render_report(_sample_report(valid=False))
        assert "INVALID" in html
        assert "T3-DATA-001" in html

    def test_contains_certificate_metadata(self) -> None:
        html = html_reporter.render_report(_sample_report())
        assert "test-001" in html
        assert "TestModel" in html
        assert "1.0.0" in html
        assert "High Risk" in html

    def test_contains_layer_info(self) -> None:
        html = html_reporter.render_report(_sample_report())
        assert "Schema Validation" in html or "Layer 1" in html

    def test_html_escaping(self) -> None:
        report = _sample_report()
        report.certificate_name = '<script>alert("xss")</script>'
        html = html_reporter.render_report(report)
        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    def test_skipped_layer_shown(self) -> None:
        report = _sample_report()
        report.layer_results.append(LayerResult(
            layer=ValidationLayer.CRYPTOGRAPHIC,
            skipped=True,
            skip_reason="use --weights",
        ))
        html = html_reporter.render_report(report)
        assert "Skipped" in html or "skipped" in html

    def test_not_applicable_layer_shown(self) -> None:
        report = _sample_report()
        report.layer_results.append(LayerResult(
            layer=ValidationLayer.COMPOSITIONAL,
            not_applicable=True,
        ))
        html = html_reporter.render_report(report)
        assert "Not Applicable" in html or "not applicable" in html

    def test_output_is_complete_html(self) -> None:
        html = html_reporter.render_report(_sample_report())
        assert html.strip().startswith("<!DOCTYPE html>")
        assert "</html>" in html

    def test_finding_details_in_html(self) -> None:
        html = html_reporter.render_report(_sample_report(valid=False))
        assert "dataController" in html
        assert "MCC-STD-001" in html
