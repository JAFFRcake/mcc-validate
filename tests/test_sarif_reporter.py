"""Tests for the SARIF reporter."""

from __future__ import annotations

import json

from mcc_validate.models import (
    Finding,
    LayerResult,
    Severity,
    ValidationLayer,
    ValidationReport,
)
from mcc_validate.reporters import sarif_reporter


def _sample_report() -> ValidationReport:
    """Create a sample report with findings for SARIF testing."""
    report = ValidationReport(
        certificate_id="test-001",
        certificate_name="TestModel",
        certificate_version="1.0.0",
        risk_tier=3,
        status="active",
        expires="2027-01-01",
    )
    lr = LayerResult(layer=ValidationLayer.TIER_COMPLIANCE, checks_passed=15)
    lr.findings.append(Finding(
        rule_id="T3-DATA-001",
        layer=ValidationLayer.TIER_COMPLIANCE,
        severity=Severity.ERROR,
        message="Missing dataController for clinical dataset",
        path="trainingData.datasets[0].dataController",
        reference="MCC-STD-001 §5.4.3",
        fix="Add dataController object with legalName and jurisdiction.",
    ))
    lr.findings.append(Finding(
        rule_id="T3-RUNT-001",
        layer=ValidationLayer.TIER_COMPLIANCE,
        severity=Severity.WARNING,
        message="Drift detection not configured",
        path="runtime.driftDetection",
        reference="MCC-STD-001 §5.7",
    ))
    report.layer_results = [lr]
    return report


class TestSARIFReporter:
    """Test SARIF report generation."""

    def test_valid_sarif_json(self) -> None:
        text = sarif_reporter.render_report(_sample_report())
        sarif = json.loads(text)
        assert sarif["version"] == "2.1.0"

    def test_has_runs(self) -> None:
        sarif = json.loads(sarif_reporter.render_report(_sample_report()))
        assert len(sarif["runs"]) == 1

    def test_tool_info(self) -> None:
        sarif = json.loads(sarif_reporter.render_report(_sample_report()))
        tool = sarif["runs"][0]["tool"]["driver"]
        assert tool["name"] == "mcc-validate"
        assert tool["version"] == "0.1.0"

    def test_results_count(self) -> None:
        sarif = json.loads(sarif_reporter.render_report(_sample_report()))
        results = sarif["runs"][0]["results"]
        assert len(results) == 2

    def test_error_severity_mapped(self) -> None:
        sarif = json.loads(sarif_reporter.render_report(_sample_report()))
        results = sarif["runs"][0]["results"]
        error_result = [r for r in results if r["ruleId"] == "T3-DATA-001"][0]
        assert error_result["level"] == "error"

    def test_warning_severity_mapped(self) -> None:
        sarif = json.loads(sarif_reporter.render_report(_sample_report()))
        results = sarif["runs"][0]["results"]
        warn_result = [r for r in results if r["ruleId"] == "T3-RUNT-001"][0]
        assert warn_result["level"] == "warning"

    def test_rules_deduplicated(self) -> None:
        sarif = json.loads(sarif_reporter.render_report(_sample_report()))
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = [r["id"] for r in rules]
        assert len(rule_ids) == len(set(rule_ids))

    def test_logical_location_path(self) -> None:
        sarif = json.loads(sarif_reporter.render_report(_sample_report()))
        results = sarif["runs"][0]["results"]
        first = results[0]
        logical = first["locations"][0]["logicalLocations"]
        assert len(logical) == 1
        assert "dataController" in logical[0]["fullyQualifiedName"]

    def test_fix_suggestion_present(self) -> None:
        sarif = json.loads(sarif_reporter.render_report(_sample_report()))
        results = sarif["runs"][0]["results"]
        error_result = [r for r in results if r["ruleId"] == "T3-DATA-001"][0]
        assert "fixes" in error_result
        assert "dataController" in error_result["fixes"][0]["description"]["text"]

    def test_certificate_path_in_location(self) -> None:
        sarif = json.loads(sarif_reporter.render_report(
            _sample_report(), certificate_path="my-cert.json"
        ))
        loc = sarif["runs"][0]["results"][0]["locations"][0]
        assert loc["physicalLocation"]["artifactLocation"]["uri"] == "my-cert.json"

    def test_empty_report_no_results(self) -> None:
        report = ValidationReport()
        sarif = json.loads(sarif_reporter.render_report(report))
        assert len(sarif["runs"][0]["results"]) == 0
        assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == 0

    def test_automation_details_present(self) -> None:
        sarif = json.loads(sarif_reporter.render_report(
            _sample_report(), certificate_path="test.json"
        ))
        run = sarif["runs"][0]
        assert "automationDetails" in run
        assert run["automationDetails"]["id"] == "mcc-validate/test.json"

    def test_custom_automation_id(self) -> None:
        sarif = json.loads(sarif_reporter.render_report(
            _sample_report(), certificate_path="test.json", automation_id="custom/run-1"
        ))
        assert sarif["runs"][0]["automationDetails"]["id"] == "custom/run-1"

    def test_version_from_package(self) -> None:
        from mcc_validate import __version__
        sarif = json.loads(sarif_reporter.render_report(_sample_report()))
        assert sarif["runs"][0]["tool"]["driver"]["version"] == __version__
