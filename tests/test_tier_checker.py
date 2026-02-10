"""Tests for Layer 2: Tier-aware compliance checking."""

from __future__ import annotations

import copy

from mcc_validate.core.tier_checker import check_tier_compliance
from mcc_validate.models import Severity, ValidationLayer


class TestTierCompliance:
    """Test tier-aware compliance rules."""

    def test_valid_tier1_passes(self, valid_tier1: dict) -> None:
        result = check_tier_compliance(valid_tier1)
        assert result.layer == ValidationLayer.TIER_COMPLIANCE
        assert not result.has_errors

    def test_valid_tier3_passes(self, valid_tier3: dict) -> None:
        result = check_tier_compliance(valid_tier3)
        assert not result.has_errors
        assert result.checks_passed > 0

    def test_tier2_requires_layer_count(self, valid_tier1: dict) -> None:
        cert = copy.deepcopy(valid_tier1)
        cert["riskTier"] = 2
        # No layerCount in architecture
        result = check_tier_compliance(cert)
        rule_ids = [f.rule_id for f in result.findings]
        assert "T2-ARCH-001" in rule_ids

    def test_tier2_requires_datasets(self, valid_tier1: dict) -> None:
        cert = copy.deepcopy(valid_tier1)
        cert["riskTier"] = 2
        result = check_tier_compliance(cert)
        rule_ids = [f.rule_id for f in result.findings]
        assert "T2-DATA-001" in rule_ids

    def test_tier2_requires_demographic_stratification(self, valid_tier1: dict) -> None:
        cert = copy.deepcopy(valid_tier1)
        cert["riskTier"] = 2
        result = check_tier_compliance(cert)
        rule_ids = [f.rule_id for f in result.findings]
        assert "T2-EVAL-001" in rule_ids

    def test_tier2_requires_adversarial_assessment(self, valid_tier1: dict) -> None:
        cert = copy.deepcopy(valid_tier1)
        cert["riskTier"] = 2
        result = check_tier_compliance(cert)
        rule_ids = [f.rule_id for f in result.findings]
        assert "T2-EVAL-002" in rule_ids

    def test_tier2_requires_confidence_intervals(self, valid_tier1: dict) -> None:
        cert = copy.deepcopy(valid_tier1)
        cert["riskTier"] = 2
        result = check_tier_compliance(cert)
        rule_ids = [f.rule_id for f in result.findings]
        assert "X-METR-001" in rule_ids

    def test_tier3_requires_data_controller(self, invalid_missing_fields: dict) -> None:
        result = check_tier_compliance(invalid_missing_fields)
        rule_ids = [f.rule_id for f in result.findings]
        assert "T3-DATA-001" in rule_ids

    def test_tier3_requires_data_sharing_agreement(self, invalid_missing_fields: dict) -> None:
        result = check_tier_compliance(invalid_missing_fields)
        rule_ids = [f.rule_id for f in result.findings]
        assert "T3-DATA-002" in rule_ids

    def test_tier3_requires_processing_pipeline(self, invalid_missing_fields: dict) -> None:
        result = check_tier_compliance(invalid_missing_fields)
        rule_ids = [f.rule_id for f in result.findings]
        assert "T3-DATA-003" in rule_ids

    def test_tier3_requires_known_biases(self, invalid_missing_fields: dict) -> None:
        result = check_tier_compliance(invalid_missing_fields)
        rule_ids = [f.rule_id for f in result.findings]
        assert "T3-DATA-004" in rule_ids

    def test_tier3_requires_independent_evaluation(self, invalid_missing_fields: dict) -> None:
        result = check_tier_compliance(invalid_missing_fields)
        rule_ids = [f.rule_id for f in result.findings]
        assert "T3-EVAL-001" in rule_ids

    def test_tier3_requires_confidence_calibration(self, invalid_missing_fields: dict) -> None:
        result = check_tier_compliance(invalid_missing_fields)
        rule_ids = [f.rule_id for f in result.findings]
        assert "T3-EVAL-002" in rule_ids

    def test_tier3_requires_drift_detection(self, invalid_missing_fields: dict) -> None:
        result = check_tier_compliance(invalid_missing_fields)
        rule_ids = [f.rule_id for f in result.findings]
        assert "T3-RUNT-001" in rule_ids

    def test_expiry_too_long_for_tier(self, invalid_tier_mismatch: dict) -> None:
        """Tier 2 with 36-month validity should fail."""
        result = check_tier_compliance(invalid_tier_mismatch)
        rule_ids = [f.rule_id for f in result.findings]
        assert "X-EXPR-001" in rule_ids

    def test_transformer_requires_attention(self, invalid_tier_mismatch: dict) -> None:
        """Transformer model at Tier 2 without attentionMechanism."""
        result = check_tier_compliance(invalid_tier_mismatch)
        rule_ids = [f.rule_id for f in result.findings]
        assert "T2-ARCH-002" in rule_ids

    def test_cross_domain_hash_algorithm(self, valid_tier1: dict) -> None:
        cert = copy.deepcopy(valid_tier1)
        cert["identity"]["weightHash"]["algorithm"] = "MD5"
        # MD5 isn't in schema enum so schema validation would catch it too,
        # but tier checker should also flag it
        result = check_tier_compliance(cert)
        rule_ids = [f.rule_id for f in result.findings]
        assert "X-HASH-001" in rule_ids

    def test_valid_hash_algorithm_passes(self, valid_tier1: dict) -> None:
        result = check_tier_compliance(valid_tier1)
        rule_ids = [f.rule_id for f in result.findings]
        assert "X-HASH-001" not in rule_ids

    def test_findings_have_correct_metadata(self, invalid_missing_fields: dict) -> None:
        result = check_tier_compliance(invalid_missing_fields)
        for finding in result.findings:
            assert finding.layer == ValidationLayer.TIER_COMPLIANCE
            assert finding.rule_id
            assert finding.message
            assert finding.severity in (Severity.ERROR, Severity.WARNING, Severity.INFO)
