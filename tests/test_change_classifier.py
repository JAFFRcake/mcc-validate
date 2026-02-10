"""Tests for the change classifier — envelope-based change assessment."""

from __future__ import annotations

import copy

from mcc_validate.core.change_classifier import (
    ChangeClassification,
    ClassificationResult,
    classify_change,
)


def _base_cert() -> dict:
    """Minimal certificate with a change envelope."""
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
                    "description": "Retraining on additional data.",
                    "bounds": {
                        "architectureChange": False,
                        "taxonomyChange": False,
                    },
                    "validationRequired": {
                        "regressionThreshold": 0.02,
                    },
                },
                {
                    "changeType": "dependency-update",
                    "description": "Update runtime dependencies.",
                    "bounds": {},
                    "validationRequired": {
                        "regressionThreshold": 0,
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


class TestChangeClassifier:
    """Test change classification against approved change envelope."""

    def test_identical_is_immaterial(self) -> None:
        cert = _base_cert()
        result = classify_change(cert, copy.deepcopy(cert))
        assert result.classification == ChangeClassification.IMMATERIAL

    def test_only_signature_change_is_immaterial(self) -> None:
        old = _base_cert()
        new = copy.deepcopy(old)
        new["signature"]["signatureValue"] = "new-sig"
        new["signature"]["signedAt"] = "2026-06-01T00:00:00Z"
        result = classify_change(old, new)
        assert result.classification == ChangeClassification.IMMATERIAL

    def test_only_version_bump_is_immaterial(self) -> None:
        old = _base_cert()
        new = copy.deepcopy(old)
        new["version"] = "1.0.1"
        new["issued"] = "2026-06-01"
        new["expires"] = "2027-06-01"
        result = classify_change(old, new)
        assert result.classification == ChangeClassification.IMMATERIAL

    def test_retraining_within_envelope(self) -> None:
        """Weight hash + training data + metrics change — covered by retraining rule."""
        old = _base_cert()
        new = copy.deepcopy(old)
        new["identity"]["weightHash"]["value"] = "eeff0011"
        new["trainingData"]["datasets"].append(
            {"datasetName": "Dataset-B", "category": "clinical"}
        )
        new["evaluation"]["primaryMetrics"][0]["value"] = 0.96  # improved
        result = classify_change(old, new)
        assert result.classification == ChangeClassification.WITHIN_ENVELOPE
        assert len(result.covered_changes) >= 1

    def test_metric_regression_within_threshold(self) -> None:
        """Small regression within regressionThreshold is within envelope."""
        old = _base_cert()
        new = copy.deepcopy(old)
        new["identity"]["weightHash"]["value"] = "eeff0011"
        new["evaluation"]["primaryMetrics"][0]["value"] = 0.935  # -0.015, within 0.02
        result = classify_change(old, new)
        assert result.classification == ChangeClassification.WITHIN_ENVELOPE

    def test_metric_regression_exceeds_threshold(self) -> None:
        """Regression beyond regressionThreshold is outside envelope."""
        old = _base_cert()
        new = copy.deepcopy(old)
        new["identity"]["weightHash"]["value"] = "eeff0011"
        new["evaluation"]["primaryMetrics"][0]["value"] = 0.92  # -0.03 > 0.02
        result = classify_change(old, new)
        assert result.classification == ChangeClassification.OUTSIDE_ENVELOPE

    def test_floor_breach_is_outside_envelope(self) -> None:
        """Metric below performance floor is always outside envelope."""
        old = _base_cert()
        new = copy.deepcopy(old)
        new["identity"]["weightHash"]["value"] = "eeff0011"
        new["evaluation"]["primaryMetrics"][0]["value"] = 0.88  # below floor 0.90
        result = classify_change(old, new)
        assert result.classification == ChangeClassification.OUTSIDE_ENVELOPE
        assert len(result.floor_breaches) >= 1

    def test_architecture_change_during_retraining_outside(self) -> None:
        """Architecture change when retraining envelope says architectureChange=false."""
        old = _base_cert()
        new = copy.deepcopy(old)
        new["identity"]["weightHash"]["value"] = "eeff0011"
        new["architecture"]["parameterCount"] = 13000000000
        new["architecture"]["layerCount"] = 64
        result = classify_change(old, new)
        # Architecture changes are covered by retraining envelope but out of bounds
        assert result.classification in (
            ChangeClassification.OUTSIDE_ENVELOPE,
            ChangeClassification.INDETERMINATE,
        )

    def test_no_envelope_is_indeterminate(self) -> None:
        """Certificate without change envelope classifies everything as indeterminate."""
        old = _base_cert()
        del old["approvedChangeEnvelope"]
        new = copy.deepcopy(old)
        new["identity"]["weightHash"]["value"] = "eeff0011"
        result = classify_change(old, new)
        assert result.classification == ChangeClassification.INDETERMINATE
        assert len(result.envelope_notes) >= 1

    def test_usage_envelope_change_indeterminate(self) -> None:
        """Changes to usageEnvelope not covered by any envelope rule."""
        old = _base_cert()
        old["usageEnvelope"] = {
            "intendedPurpose": {"description": "Triage"},
        }
        new = copy.deepcopy(old)
        new["usageEnvelope"]["intendedPurpose"]["description"] = "Diagnosis"
        result = classify_change(old, new)
        # Usage envelope is not covered by retraining or dependency-update
        assert result.classification == ChangeClassification.INDETERMINATE

    def test_classification_result_summary(self) -> None:
        old = _base_cert()
        new = copy.deepcopy(old)
        new["identity"]["weightHash"]["value"] = "eeff0011"
        result = classify_change(old, new)
        summary = result.summary
        assert "Classification:" in summary

    def test_multiple_envelope_notes_on_floor_breach(self) -> None:
        old = _base_cert()
        new = copy.deepcopy(old)
        new["identity"]["weightHash"]["value"] = "eeff0011"
        new["evaluation"]["primaryMetrics"][0]["value"] = 0.88  # auroc below
        new["evaluation"]["primaryMetrics"][1]["value"] = 0.80  # sensitivity below
        result = classify_change(old, new)
        assert result.classification == ChangeClassification.OUTSIDE_ENVELOPE
        assert len(result.floor_breaches) == 2

    def test_tier3_fixture_self_classify(self, valid_tier3: dict) -> None:
        """Classifying a fixture against itself should be immaterial."""
        result = classify_change(valid_tier3, copy.deepcopy(valid_tier3))
        assert result.classification == ChangeClassification.IMMATERIAL
