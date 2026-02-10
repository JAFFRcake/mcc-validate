"""Tests for the diff engine — certificate version comparison."""

from __future__ import annotations

import copy

from mcc_validate.core.diff_engine import (
    ChangeCategory,
    DiffReport,
    FieldChange,
    MetricChange,
    diff_certificates,
)


def _base_cert() -> dict:
    """Minimal certificate for diff testing."""
    return {
        "certificateId": "cert-001",
        "version": "1.0.0",
        "issued": "2026-01-01",
        "expires": "2027-01-01",
        "riskTier": 3,
        "status": "active",
        "identity": {
            "modelName": "TestModel",
            "modelVersion": "1.0.0",
            "weightHash": {
                "algorithm": "SHA-256",
                "value": "aabbccdd",
            },
        },
        "architecture": {
            "modelType": "transformer-decoder",
            "parameterCount": 7000000000,
            "layerCount": 32,
        },
        "evaluation": {
            "primaryMetrics": [
                {"metricName": "auroc", "value": 0.95},
                {"metricName": "sensitivity", "value": 0.92},
            ],
        },
        "trainingData": {
            "datasets": [
                {"datasetName": "Dataset-A", "category": "clinical"},
            ],
        },
        "approvedChangeEnvelope": {
            "permittedChanges": [
                {
                    "changeType": "retraining",
                    "bounds": {
                        "architectureChange": False,
                        "taxonomyChange": False,
                    },
                    "validationRequired": {
                        "regressionThreshold": 0.02,
                    },
                },
            ],
            "globalConstraints": {
                "performanceFloor": [
                    {"metricName": "auroc", "value": 0.90},
                    {"metricName": "sensitivity", "value": 0.85},
                ],
            },
        },
        "signature": {
            "algorithm": "ES256",
            "signatureValue": "abc123",
            "signedAt": "2026-01-01T00:00:00Z",
        },
    }


class TestDiffEngine:
    """Test certificate diff engine."""

    def test_identical_certificates_no_changes(self) -> None:
        cert = _base_cert()
        report = diff_certificates(cert, copy.deepcopy(cert))
        assert not report.has_changes
        assert len(report.changes) == 0
        assert len(report.metric_changes) == 0

    def test_version_bump(self) -> None:
        old = _base_cert()
        new = copy.deepcopy(old)
        new["version"] = "1.1.0"
        report = diff_certificates(old, new)
        assert report.has_changes
        assert report.old_version == "1.0.0"
        assert report.new_version == "1.1.0"
        version_changes = [c for c in report.changes if c.path == "version"]
        assert len(version_changes) == 1
        assert version_changes[0].old_value == "1.0.0"
        assert version_changes[0].new_value == "1.1.0"

    def test_weight_hash_change(self) -> None:
        old = _base_cert()
        new = copy.deepcopy(old)
        new["identity"]["weightHash"]["value"] = "eeff0011"
        report = diff_certificates(old, new)
        hash_changes = [c for c in report.changes if "weightHash" in c.path]
        assert len(hash_changes) == 1
        assert hash_changes[0].category == ChangeCategory.IDENTITY

    def test_architecture_change(self) -> None:
        old = _base_cert()
        new = copy.deepcopy(old)
        new["architecture"]["parameterCount"] = 13000000000
        report = diff_certificates(old, new)
        arch_changes = report.changes_in(ChangeCategory.ARCHITECTURE)
        assert len(arch_changes) >= 1
        param_change = [c for c in arch_changes if "parameterCount" in c.path]
        assert len(param_change) == 1
        assert param_change[0].old_value == 7000000000
        assert param_change[0].new_value == 13000000000

    def test_metric_improvement(self) -> None:
        old = _base_cert()
        new = copy.deepcopy(old)
        new["evaluation"]["primaryMetrics"][0]["value"] = 0.96  # auroc improved
        report = diff_certificates(old, new)
        assert len(report.metric_changes) >= 1
        auroc = [m for m in report.metric_changes if m.metric_name == "auroc"]
        assert len(auroc) == 1
        assert auroc[0].old_value == 0.95
        assert auroc[0].new_value == 0.96
        assert auroc[0].absolute_change > 0
        assert not auroc[0].is_regression

    def test_metric_regression(self) -> None:
        old = _base_cert()
        new = copy.deepcopy(old)
        new["evaluation"]["primaryMetrics"][0]["value"] = 0.93  # auroc dropped
        report = diff_certificates(old, new)
        auroc = [m for m in report.metric_changes if m.metric_name == "auroc"]
        assert len(auroc) == 1
        assert auroc[0].is_regression
        assert auroc[0].absolute_change < 0

    def test_metric_floor_breach(self) -> None:
        old = _base_cert()
        new = copy.deepcopy(old)
        new["evaluation"]["primaryMetrics"][0]["value"] = 0.88  # below floor 0.90
        report = diff_certificates(old, new)
        auroc = [m for m in report.metric_changes if m.metric_name == "auroc"]
        assert len(auroc) == 1
        assert auroc[0].breaches_floor
        assert auroc[0].floor_value == 0.90
        assert report.has_floor_breaches

    def test_no_floor_breach_when_above(self) -> None:
        old = _base_cert()
        new = copy.deepcopy(old)
        new["evaluation"]["primaryMetrics"][0]["value"] = 0.94  # still above 0.90
        report = diff_certificates(old, new)
        auroc = [m for m in report.metric_changes if m.metric_name == "auroc"]
        assert len(auroc) == 1
        assert not auroc[0].breaches_floor
        assert not report.has_floor_breaches

    def test_added_field(self) -> None:
        old = _base_cert()
        new = copy.deepcopy(old)
        new["architecture"]["attentionMechanism"] = "multi-head"
        report = diff_certificates(old, new)
        added = [c for c in report.changes if c.change_type == "added" and "attentionMechanism" in c.path]
        assert len(added) == 1

    def test_removed_field(self) -> None:
        old = _base_cert()
        new = copy.deepcopy(old)
        del new["architecture"]["layerCount"]
        report = diff_certificates(old, new)
        removed = [c for c in report.changes if c.change_type == "removed" and "layerCount" in c.path]
        assert len(removed) == 1

    def test_dataset_added(self) -> None:
        old = _base_cert()
        new = copy.deepcopy(old)
        new["trainingData"]["datasets"].append(
            {"datasetName": "Dataset-B", "category": "synthetic"}
        )
        report = diff_certificates(old, new)
        data_changes = report.changes_in(ChangeCategory.TRAINING_DATA)
        added = [c for c in data_changes if c.change_type == "added"]
        assert len(added) >= 1

    def test_dataset_removed(self) -> None:
        old = _base_cert()
        new = copy.deepcopy(old)
        new["trainingData"]["datasets"] = []
        report = diff_certificates(old, new)
        data_changes = report.changes_in(ChangeCategory.TRAINING_DATA)
        removed = [c for c in data_changes if c.change_type == "removed"]
        assert len(removed) >= 1

    def test_categories_changed_property(self) -> None:
        old = _base_cert()
        new = copy.deepcopy(old)
        new["architecture"]["parameterCount"] = 13000000000
        new["version"] = "2.0.0"
        report = diff_certificates(old, new)
        cats = report.categories_changed
        assert ChangeCategory.ARCHITECTURE in cats
        assert ChangeCategory.METADATA in cats

    def test_keyed_list_matching(self) -> None:
        """Metrics should be matched by metricName, not position."""
        old = _base_cert()
        new = copy.deepcopy(old)
        # Reverse the order — should still match by metricName
        new["evaluation"]["primaryMetrics"] = [
            {"metricName": "sensitivity", "value": 0.93},
            {"metricName": "auroc", "value": 0.96},
        ]
        report = diff_certificates(old, new)
        # Should detect changes to both metrics by name
        sens = [m for m in report.metric_changes if m.metric_name == "sensitivity"]
        auroc = [m for m in report.metric_changes if m.metric_name == "auroc"]
        assert len(sens) == 1
        assert len(auroc) == 1
        assert sens[0].new_value == 0.93
        assert auroc[0].new_value == 0.96

    def test_positional_list_fallback(self) -> None:
        """Lists without identifier keys fall back to positional diff."""
        old = {"items": ["a", "b", "c"]}
        new = {"items": ["a", "x", "c"]}
        report = diff_certificates(old, new)
        changes = [c for c in report.changes if "items" in c.path]
        assert len(changes) == 1
        assert changes[0].old_value == "b"
        assert changes[0].new_value == "x"

    def test_signature_changes_detected(self) -> None:
        old = _base_cert()
        new = copy.deepcopy(old)
        new["signature"]["signatureValue"] = "xyz789"
        report = diff_certificates(old, new)
        sig_changes = report.changes_in(ChangeCategory.SIGNATURE)
        assert len(sig_changes) >= 1

    def test_tier3_fixture_self_diff(self, valid_tier3: dict) -> None:
        """Diffing a fixture against itself should produce no changes."""
        report = diff_certificates(valid_tier3, copy.deepcopy(valid_tier3))
        assert not report.has_changes

    def test_field_change_str(self) -> None:
        c = FieldChange(path="a.b", category=ChangeCategory.METADATA, old_value=1, new_value=2)
        assert "1" in str(c) and "2" in str(c)

    def test_has_regressions_false_on_empty(self) -> None:
        report = DiffReport()
        assert not report.has_regressions
        assert not report.has_floor_breaches
