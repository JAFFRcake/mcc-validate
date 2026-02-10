"""Tests for the programmatic validation API."""

from __future__ import annotations

import json
from pathlib import Path

from mcc_validate.config import Config, RuleOverride
from mcc_validate.core import validate_certificate
from mcc_validate.models import Severity, ValidationReport

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestValidateCertificate:
    """Test the validate_certificate() pipeline function."""

    def test_valid_tier1_returns_valid_report(self) -> None:
        cert = json.loads((FIXTURES_DIR / "valid_tier1.json").read_text(encoding="utf-8"))
        report = validate_certificate(cert)
        assert isinstance(report, ValidationReport)
        assert report.is_valid

    def test_invalid_returns_errors(self) -> None:
        cert = json.loads(
            (FIXTURES_DIR / "invalid_missing_fields.json").read_text(encoding="utf-8")
        )
        report = validate_certificate(cert)
        assert not report.is_valid
        assert report.total_errors > 0

    def test_returns_all_five_layers(self) -> None:
        cert = json.loads((FIXTURES_DIR / "valid_tier1.json").read_text(encoding="utf-8"))
        report = validate_certificate(cert)
        assert len(report.layer_results) == 5

    def test_config_overrides_applied(self) -> None:
        cert = json.loads(
            (FIXTURES_DIR / "invalid_missing_fields.json").read_text(encoding="utf-8")
        )
        # Get base errors
        base_report = validate_certificate(cert)
        base_errors = base_report.total_errors

        # Now ignore a known rule
        rule_ids = [f.rule_id for f in base_report.all_findings if f.severity == Severity.ERROR]
        if rule_ids:
            cfg = Config(rule_overrides={
                rule_ids[0]: RuleOverride(rule_id=rule_ids[0], severity="ignore"),
            })
            report = validate_certificate(cert, config=cfg)
            # Should have fewer findings after ignore
            assert report.total_errors < base_errors or len(report.all_findings) < len(
                base_report.all_findings
            )

    def test_composite_with_components_dir(self) -> None:
        cert = json.loads(
            (FIXTURES_DIR / "composite_system.json").read_text(encoding="utf-8")
        )
        components = FIXTURES_DIR / "components"
        report = validate_certificate(cert, components_dir=components)
        # Layer 5 should not be skipped when components_dir is provided
        layer5 = report.layer_results[4]
        assert not layer5.skipped
        assert not layer5.not_applicable

    def test_default_config_when_none(self) -> None:
        cert = json.loads((FIXTURES_DIR / "valid_tier1.json").read_text(encoding="utf-8"))
        report = validate_certificate(cert, config=None)
        assert isinstance(report, ValidationReport)

    def test_report_metadata_populated(self) -> None:
        cert = json.loads((FIXTURES_DIR / "valid_tier3.json").read_text(encoding="utf-8"))
        report = validate_certificate(cert)
        assert report.certificate_id != ""
        assert report.risk_tier == 3
