"""Change classifier — evaluates diffs against the approved change envelope.

Given two certificate versions, classifies whether the changes fall within
the pre-approved change envelope of the *old* certificate:

- IMMATERIAL:       No certificate-relevant fields changed.
- WITHIN_ENVELOPE:  All changes fall within approved bounds.
- OUTSIDE_ENVELOPE: Some changes exceed approved bounds or breach performance floor.
- INDETERMINATE:    Changes affect fields not covered by any envelope rule.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any

from mcc_validate.core.diff_engine import (
    ChangeCategory,
    DiffReport,
    FieldChange,
    MetricChange,
    diff_certificates,
)


class ChangeClassification(enum.Enum):
    """Overall classification of changes between certificate versions."""

    IMMATERIAL = "immaterial"
    WITHIN_ENVELOPE = "within_envelope"
    OUTSIDE_ENVELOPE = "outside_envelope"
    INDETERMINATE = "indeterminate"


@dataclass
class EnvelopeMatch:
    """A change matched to a specific envelope rule."""

    change: FieldChange
    change_type: str  # The envelope changeType that covers this change
    within_bounds: bool
    note: str = ""


@dataclass
class ClassificationResult:
    """Result of classifying changes against the approved change envelope."""

    classification: ChangeClassification = ChangeClassification.IMMATERIAL
    diff_report: DiffReport = field(default_factory=DiffReport)
    covered_changes: list[EnvelopeMatch] = field(default_factory=list)
    uncovered_changes: list[FieldChange] = field(default_factory=list)
    floor_breaches: list[MetricChange] = field(default_factory=list)
    envelope_notes: list[str] = field(default_factory=list)

    @property
    def summary(self) -> str:
        """One-line summary of the classification."""
        lines = [f"Classification: {self.classification.value.upper()}"]
        if self.covered_changes:
            lines.append(
                f"  {len(self.covered_changes)} change(s) covered by envelope"
            )
        if self.uncovered_changes:
            lines.append(
                f"  {len(self.uncovered_changes)} change(s) NOT covered by envelope"
            )
        if self.floor_breaches:
            names = ", ".join(m.metric_name for m in self.floor_breaches)
            lines.append(f"  Performance floor breaches: {names}")
        return "\n".join(lines)


# Fields that are always allowed to change without affecting classification.
_IMMATERIAL_FIELDS = frozenset({
    "signature",
    "signature.signatureValue",
    "signature.signedAt",
    "signature.keyId",
    "signature.certificateChain",
})

# Categories considered immaterial (signature always changes on re-issue).
_IMMATERIAL_CATEGORIES = frozenset({ChangeCategory.SIGNATURE})

# Map from envelope changeType to the categories it covers.
_ENVELOPE_COVERAGE: dict[str, set[ChangeCategory]] = {
    "retraining": {
        ChangeCategory.IDENTITY,      # weightHash changes
        ChangeCategory.TRAINING_DATA,  # new data
        ChangeCategory.EVALUATION,     # new metrics
    },
    "rag-corpus-update": {
        ChangeCategory.RUNTIME,
    },
    "dependency-update": {
        ChangeCategory.RUNTIME,
    },
    "fine-tuning": {
        ChangeCategory.IDENTITY,
        ChangeCategory.EVALUATION,
    },
    "architecture-update": {
        ChangeCategory.ARCHITECTURE,
        ChangeCategory.IDENTITY,
        ChangeCategory.EVALUATION,
    },
}


def classify_change(old: dict, new: dict) -> ClassificationResult:
    """Classify changes between two certificate versions.

    Parameters
    ----------
    old:
        The older certificate (dict).
    new:
        The newer certificate (dict).

    Returns
    -------
    ClassificationResult with the overall classification and details.
    """
    diff = diff_certificates(old, new)
    envelope = old.get("approvedChangeEnvelope", {})
    permitted = envelope.get("permittedChanges", [])

    result = ClassificationResult(
        diff_report=diff,
    )

    # Filter out immaterial changes (signature, metadata version bumps).
    material_changes = _filter_material_changes(diff.changes)

    if not material_changes:
        result.classification = ChangeClassification.IMMATERIAL
        return result

    # Check for performance floor breaches — immediate OUTSIDE_ENVELOPE.
    result.floor_breaches = [m for m in diff.metric_changes if m.breaches_floor]

    if result.floor_breaches:
        result.classification = ChangeClassification.OUTSIDE_ENVELOPE
        names = ", ".join(m.metric_name for m in result.floor_breaches)
        result.envelope_notes.append(
            f"Performance floor breached for: {names}. Immediate recertification required."
        )
        result.uncovered_changes = material_changes
        return result

    # No envelope at all — everything is indeterminate.
    if not permitted:
        result.classification = ChangeClassification.INDETERMINATE
        result.uncovered_changes = material_changes
        result.envelope_notes.append(
            "No approvedChangeEnvelope in old certificate; cannot classify changes."
        )
        return result

    # Try to match each material change to an envelope rule.
    for change in material_changes:
        match = _match_to_envelope(change, permitted, diff)
        if match is not None:
            result.covered_changes.append(match)
        else:
            result.uncovered_changes.append(change)

    # Determine overall classification.
    if result.uncovered_changes:
        # Check if *all* uncovered changes are in categories not covered by any rule.
        covered_categories = set()
        for p in permitted:
            ct = p.get("changeType", "")
            covered_categories.update(_ENVELOPE_COVERAGE.get(ct, set()))

        truly_outside = [
            c for c in result.uncovered_changes
            if c.category in covered_categories
        ]
        truly_unknown = [
            c for c in result.uncovered_changes
            if c.category not in covered_categories
        ]

        if truly_outside:
            result.classification = ChangeClassification.OUTSIDE_ENVELOPE
            result.envelope_notes.append(
                f"{len(truly_outside)} change(s) affect fields covered by envelope "
                f"rules but exceed approved bounds."
            )
        elif truly_unknown:
            result.classification = ChangeClassification.INDETERMINATE
            result.envelope_notes.append(
                f"{len(truly_unknown)} change(s) affect fields not covered by any "
                f"envelope rule; manual review needed."
            )
        else:
            result.classification = ChangeClassification.WITHIN_ENVELOPE
    else:
        # All material changes are covered.
        # But check regression thresholds.
        regression_violations = _check_regression_thresholds(diff, permitted)
        if regression_violations:
            result.classification = ChangeClassification.OUTSIDE_ENVELOPE
            result.envelope_notes.extend(regression_violations)
        else:
            result.classification = ChangeClassification.WITHIN_ENVELOPE

    return result


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _filter_material_changes(changes: list[FieldChange]) -> list[FieldChange]:
    """Filter out immaterial changes (signature, metadata-only)."""
    material: list[FieldChange] = []
    for c in changes:
        if c.category in _IMMATERIAL_CATEGORIES:
            continue
        if c.path in _IMMATERIAL_FIELDS:
            continue
        # Version/issued/expires bumps alone are metadata.
        if c.path in ("version", "issued", "expires", "status"):
            continue
        material.append(c)
    return material


def _match_to_envelope(
    change: FieldChange,
    permitted: list[dict],
    diff: DiffReport,
) -> EnvelopeMatch | None:
    """Try to match a change to an approved envelope rule."""
    for rule in permitted:
        change_type = rule.get("changeType", "")
        coverage = _ENVELOPE_COVERAGE.get(change_type, set())

        if change.category not in coverage:
            continue

        # Check specific bounds.
        bounds = rule.get("bounds", {})
        within = _check_bounds(change, bounds, change_type, diff)

        return EnvelopeMatch(
            change=change,
            change_type=change_type,
            within_bounds=within,
            note=rule.get("description", ""),
        )

    return None


def _check_bounds(
    change: FieldChange,
    bounds: dict,
    change_type: str,
    diff: DiffReport,
) -> bool:
    """Check whether a change is within the declared bounds."""
    # Architecture change not allowed for retraining.
    if change_type == "retraining":
        if bounds.get("architectureChange") is False:
            if change.category == ChangeCategory.ARCHITECTURE:
                return False
        if bounds.get("taxonomyChange") is False:
            if "outputModalities" in change.path or "vocabularySize" in change.path:
                return False

    return True


def _check_regression_thresholds(
    diff: DiffReport, permitted: list[dict]
) -> list[str]:
    """Check if metric regressions exceed per-rule regression thresholds."""
    violations: list[str] = []

    for rule in permitted:
        threshold = (
            rule.get("validationRequired", {}).get("regressionThreshold", 0)
        )
        if threshold <= 0:
            continue

        for mc in diff.metric_changes:
            if mc.is_regression and abs(mc.absolute_change) > threshold:
                violations.append(
                    f"Metric '{mc.metric_name}' regressed by "
                    f"{abs(mc.absolute_change):.4f}, exceeding "
                    f"regressionThreshold {threshold} for change type "
                    f"'{rule.get('changeType', '?')}'."
                )

    return violations
