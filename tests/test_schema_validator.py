"""Tests for Layer 1: JSON Schema validation."""

from __future__ import annotations

import copy

from mcc_validate.core.schema_validator import validate_schema
from mcc_validate.models import Severity, ValidationLayer


class TestSchemaValidation:
    """Test structural JSON Schema validation."""

    def test_valid_tier1_passes(self, valid_tier1: dict) -> None:
        result = validate_schema(valid_tier1)
        assert result.layer == ValidationLayer.SCHEMA
        assert not result.has_errors
        assert result.checks_passed > 0

    def test_valid_tier3_passes(self, valid_tier3: dict) -> None:
        result = validate_schema(valid_tier3)
        assert not result.has_errors
        assert result.checks_passed > 0

    def test_missing_required_field(self, valid_tier1: dict) -> None:
        cert = copy.deepcopy(valid_tier1)
        del cert["riskTier"]
        result = validate_schema(cert)
        assert result.has_errors
        assert any("riskTier" in f.message for f in result.errors)

    def test_invalid_risk_tier_value(self, valid_tier1: dict) -> None:
        cert = copy.deepcopy(valid_tier1)
        cert["riskTier"] = 5
        result = validate_schema(cert)
        assert result.has_errors

    def test_invalid_status_enum(self, valid_tier1: dict) -> None:
        cert = copy.deepcopy(valid_tier1)
        cert["status"] = "invalid-status"
        result = validate_schema(cert)
        assert result.has_errors

    def test_invalid_version_format(self, valid_tier1: dict) -> None:
        cert = copy.deepcopy(valid_tier1)
        cert["version"] = "not-semver"
        result = validate_schema(cert)
        assert result.has_errors

    def test_missing_identity(self, valid_tier1: dict) -> None:
        cert = copy.deepcopy(valid_tier1)
        del cert["identity"]
        result = validate_schema(cert)
        assert result.has_errors

    def test_missing_signature(self, valid_tier1: dict) -> None:
        cert = copy.deepcopy(valid_tier1)
        del cert["signature"]
        result = validate_schema(cert)
        assert result.has_errors

    def test_additional_property_rejected(self, valid_tier1: dict) -> None:
        cert = copy.deepcopy(valid_tier1)
        cert["unexpectedField"] = "should fail"
        result = validate_schema(cert)
        assert result.has_errors

    def test_empty_object_fails(self) -> None:
        result = validate_schema({})
        assert result.has_errors
        assert len(result.errors) > 0

    def test_findings_have_correct_layer(self, valid_tier1: dict) -> None:
        cert = copy.deepcopy(valid_tier1)
        del cert["riskTier"]
        result = validate_schema(cert)
        for finding in result.findings:
            assert finding.layer == ValidationLayer.SCHEMA
            assert finding.severity == Severity.ERROR
