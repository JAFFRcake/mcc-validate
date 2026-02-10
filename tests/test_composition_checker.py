"""Tests for Layer 5: Compositional integrity checking."""

from __future__ import annotations

import copy
import json
from pathlib import Path

from mcc_validate.core.composition_checker import check_composition
from mcc_validate.models import Severity


class TestCompositionChecker:
    """Test compositional integrity checks."""

    def test_no_composition_not_applicable(self) -> None:
        cert = {"certificateId": "test", "riskTier": 1}
        result = check_composition(cert)
        assert result.not_applicable

    def test_valid_composition_no_components_dir(self, composite_system: dict) -> None:
        result = check_composition(composite_system)
        assert not result.not_applicable
        assert not result.skipped
        # Should pass structural checks without --components
        assert result.checks_passed > 0

    def test_valid_composition_with_components(
        self, composite_system: dict, components_dir: Path
    ) -> None:
        result = check_composition(composite_system, components_dir)
        errors = [f for f in result.findings if f.severity == Severity.ERROR]
        assert len(errors) == 0
        assert result.checks_passed >= 5

    def test_fewer_than_two_components(self) -> None:
        cert = {
            "composition": {
                "components": [
                    {"componentName": "Only", "componentRole": "foundation-model"}
                ],
                "dataFlow": [],
            },
            "riskTier": 1,
        }
        result = check_composition(cert)
        errors = [f for f in result.findings if f.rule_id == "COMP-001"]
        assert len(errors) == 1

    def test_missing_component_name(self) -> None:
        cert = {
            "composition": {
                "components": [
                    {"componentRole": "foundation-model"},
                    {"componentName": "B", "componentRole": "guardrail"},
                ],
                "dataFlow": [],
            },
            "riskTier": 1,
        }
        result = check_composition(cert)
        errors = [f for f in result.findings if f.rule_id == "COMP-002"]
        assert len(errors) == 1

    def test_missing_component_role(self) -> None:
        cert = {
            "composition": {
                "components": [
                    {"componentName": "A"},
                    {"componentName": "B", "componentRole": "guardrail"},
                ],
                "dataFlow": [],
            },
            "riskTier": 1,
        }
        result = check_composition(cert)
        errors = [f for f in result.findings if f.rule_id == "COMP-002"]
        assert len(errors) == 1

    def test_data_flow_unknown_component(self) -> None:
        cert = {
            "composition": {
                "components": [
                    {"componentName": "A", "componentRole": "foundation-model"},
                    {"componentName": "B", "componentRole": "guardrail"},
                ],
                "dataFlow": [
                    {"from": "A", "to": "UNKNOWN", "dataType": "text"},
                ],
            },
            "riskTier": 1,
        }
        result = check_composition(cert)
        errors = [f for f in result.findings if f.rule_id == "COMP-003"]
        assert len(errors) == 1
        assert "UNKNOWN" in errors[0].message

    def test_circular_reference_detected(self) -> None:
        cert = {
            "composition": {
                "components": [
                    {"componentName": "A", "componentRole": "foundation-model"},
                    {"componentName": "B", "componentRole": "guardrail"},
                ],
                "dataFlow": [
                    {"from": "A", "to": "B", "dataType": "text"},
                    {"from": "B", "to": "A", "dataType": "text"},
                ],
            },
            "riskTier": 1,
        }
        result = check_composition(cert)
        cycle_errors = [f for f in result.findings if f.rule_id == "COMP-004"]
        assert len(cycle_errors) == 1

    def test_no_circular_reference_linear(self) -> None:
        cert = {
            "composition": {
                "components": [
                    {"componentName": "A", "componentRole": "input-processor"},
                    {"componentName": "B", "componentRole": "foundation-model"},
                    {"componentName": "C", "componentRole": "guardrail"},
                ],
                "dataFlow": [
                    {"from": "A", "to": "B", "dataType": "tensor"},
                    {"from": "B", "to": "C", "dataType": "prediction"},
                ],
            },
            "riskTier": 1,
        }
        result = check_composition(cert)
        cycle_errors = [f for f in result.findings if f.rule_id == "COMP-004"]
        assert len(cycle_errors) == 0

    def test_orphan_component_warning(self) -> None:
        cert = {
            "composition": {
                "components": [
                    {"componentName": "A", "componentRole": "foundation-model"},
                    {"componentName": "B", "componentRole": "guardrail"},
                    {"componentName": "Orphan", "componentRole": "other"},
                ],
                "dataFlow": [
                    {"from": "A", "to": "B", "dataType": "text"},
                ],
            },
            "riskTier": 1,
        }
        result = check_composition(cert)
        warnings = [f for f in result.findings if f.rule_id == "COMP-005"]
        assert len(warnings) == 1
        assert "Orphan" in warnings[0].message

    def test_unresolved_certificate_ref(
        self, composite_system: dict, components_dir: Path
    ) -> None:
        cert = copy.deepcopy(composite_system)
        cert["composition"]["components"][0]["certificateRef"] = "nonexistent-id"
        result = check_composition(cert, components_dir)
        errors = [f for f in result.findings if f.rule_id == "COMP-006"]
        assert len(errors) == 1

    def test_component_version_mismatch(
        self, composite_system: dict, components_dir: Path
    ) -> None:
        cert = copy.deepcopy(composite_system)
        cert["composition"]["components"][0]["version"] = "99.0.0"
        result = check_composition(cert, components_dir)
        errors = [f for f in result.findings if f.rule_id == "COMP-007"]
        assert len(errors) == 1

    def test_composite_tier_too_low(
        self, composite_system: dict, components_dir: Path
    ) -> None:
        cert = copy.deepcopy(composite_system)
        cert["riskTier"] = 1  # Component comp-model-001 is tier 3
        result = check_composition(cert, components_dir)
        errors = [f for f in result.findings if f.rule_id == "COMP-008"]
        assert len(errors) == 1

    def test_composite_tier_adequate(
        self, composite_system: dict, components_dir: Path
    ) -> None:
        cert = copy.deepcopy(composite_system)
        # riskTier 3 >= max component tier 3 — should pass
        result = check_composition(cert, components_dir)
        errors = [f for f in result.findings if f.rule_id == "COMP-008"]
        assert len(errors) == 0

    def test_invalid_components_dir(self, composite_system: dict) -> None:
        result = check_composition(composite_system, "/nonexistent/path")
        errors = [f for f in result.findings if f.rule_id == "COMP-006"]
        assert len(errors) == 1
