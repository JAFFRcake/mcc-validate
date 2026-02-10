"""Diff engine for comparing two certificate versions.

Produces a structured delta report categorised by certificate domain,
with special handling for evaluation metric regressions.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class ChangeCategory(enum.Enum):
    """Certificate domain categories for grouping changes."""

    METADATA = "metadata"
    IDENTITY = "identity"
    ARCHITECTURE = "architecture"
    TRAINING_DATA = "trainingData"
    EVALUATION = "evaluation"
    USAGE_ENVELOPE = "usageEnvelope"
    RUNTIME = "runtime"
    CHANGE_ENVELOPE = "approvedChangeEnvelope"
    COMPOSITION = "composition"
    SIGNATURE = "signature"


# Map top-level JSON keys to categories.
_CATEGORY_MAP: dict[str, ChangeCategory] = {
    "@context": ChangeCategory.METADATA,
    "@type": ChangeCategory.METADATA,
    "certificateId": ChangeCategory.METADATA,
    "version": ChangeCategory.METADATA,
    "issued": ChangeCategory.METADATA,
    "expires": ChangeCategory.METADATA,
    "riskTier": ChangeCategory.METADATA,
    "status": ChangeCategory.METADATA,
    "identity": ChangeCategory.IDENTITY,
    "architecture": ChangeCategory.ARCHITECTURE,
    "trainingData": ChangeCategory.TRAINING_DATA,
    "evaluation": ChangeCategory.EVALUATION,
    "usageEnvelope": ChangeCategory.USAGE_ENVELOPE,
    "runtime": ChangeCategory.RUNTIME,
    "approvedChangeEnvelope": ChangeCategory.CHANGE_ENVELOPE,
    "composition": ChangeCategory.COMPOSITION,
    "signature": ChangeCategory.SIGNATURE,
}


@dataclass
class FieldChange:
    """A single field-level change between two certificates."""

    path: str
    category: ChangeCategory
    old_value: Any = None
    new_value: Any = None
    change_type: str = "modified"  # "added", "removed", "modified"

    def __str__(self) -> str:
        if self.change_type == "added":
            return f"+ {self.path}: {_summarise(self.new_value)}"
        if self.change_type == "removed":
            return f"- {self.path}: {_summarise(self.old_value)}"
        return f"~ {self.path}: {_summarise(self.old_value)} -> {_summarise(self.new_value)}"


@dataclass
class MetricChange:
    """A change in an evaluation metric between certificate versions."""

    metric_name: str
    old_value: float
    new_value: float
    absolute_change: float
    is_regression: bool
    breaches_floor: bool = False
    floor_value: float | None = None


@dataclass
class DiffReport:
    """Structured diff report between two certificate versions."""

    old_version: str = ""
    new_version: str = ""
    old_cert_id: str = ""
    new_cert_id: str = ""
    changes: list[FieldChange] = field(default_factory=list)
    metric_changes: list[MetricChange] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return len(self.changes) > 0

    @property
    def categories_changed(self) -> set[ChangeCategory]:
        return {c.category for c in self.changes}

    @property
    def has_regressions(self) -> bool:
        return any(m.is_regression for m in self.metric_changes)

    @property
    def has_floor_breaches(self) -> bool:
        return any(m.breaches_floor for m in self.metric_changes)

    def changes_in(self, category: ChangeCategory) -> list[FieldChange]:
        """Return changes in a specific category."""
        return [c for c in self.changes if c.category == category]


def diff_certificates(old: dict, new: dict) -> DiffReport:
    """Compare two certificate versions and produce a structured diff report.

    Parameters
    ----------
    old:
        The older certificate (dict parsed from JSON).
    new:
        The newer certificate (dict parsed from JSON).

    Returns
    -------
    DiffReport with all field-level changes and metric regression analysis.
    """
    report = DiffReport(
        old_version=old.get("version", ""),
        new_version=new.get("version", ""),
        old_cert_id=old.get("certificateId", ""),
        new_cert_id=new.get("certificateId", ""),
    )

    # Compute field-level diff.
    report.changes = _diff_values(old, new, path="")

    # Compute metric regression analysis.
    report.metric_changes = _analyse_metrics(old, new)

    return report


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _categorise(path: str) -> ChangeCategory:
    """Determine the category from a dotted JSON path."""
    top_key = path.split(".")[0] if path else ""
    return _CATEGORY_MAP.get(top_key, ChangeCategory.METADATA)


def _summarise(value: Any, max_len: int = 80) -> str:
    """Create a short string summary of a value for display."""
    if value is None:
        return "<absent>"
    s = str(value)
    if len(s) > max_len:
        return s[:max_len - 3] + "..."
    return s


def _diff_values(old: Any, new: Any, path: str) -> list[FieldChange]:
    """Recursively diff two values, producing FieldChange items."""
    changes: list[FieldChange] = []

    if isinstance(old, dict) and isinstance(new, dict):
        all_keys = sorted(set(old.keys()) | set(new.keys()))
        for key in all_keys:
            child_path = f"{path}.{key}" if path else key
            if key not in old:
                changes.append(FieldChange(
                    path=child_path,
                    category=_categorise(child_path),
                    new_value=new[key],
                    change_type="added",
                ))
            elif key not in new:
                changes.append(FieldChange(
                    path=child_path,
                    category=_categorise(child_path),
                    old_value=old[key],
                    change_type="removed",
                ))
            elif old[key] != new[key]:
                # Recurse into nested structures.
                if isinstance(old[key], dict) and isinstance(new[key], dict):
                    changes.extend(_diff_values(old[key], new[key], child_path))
                elif isinstance(old[key], list) and isinstance(new[key], list):
                    changes.extend(_diff_list(old[key], new[key], child_path))
                else:
                    changes.append(FieldChange(
                        path=child_path,
                        category=_categorise(child_path),
                        old_value=old[key],
                        new_value=new[key],
                        change_type="modified",
                    ))
    elif old != new:
        changes.append(FieldChange(
            path=path,
            category=_categorise(path),
            old_value=old,
            new_value=new,
            change_type="modified",
        ))

    return changes


def _diff_list(old: list, new: list, path: str) -> list[FieldChange]:
    """Diff two lists, attempting element-wise comparison for dicts with identifiers."""
    # Try to match list elements by identifier keys.
    id_keys = ("metricName", "datasetName", "datasetId", "changeType",
               "stratificationAxis", "benchmarkName", "stepName", "biasType",
               "metric", "stratumName")

    old_by_id, old_id_key = _index_by_id(old, id_keys)
    new_by_id, new_id_key = _index_by_id(new, id_keys)

    if old_id_key and new_id_key and old_id_key == new_id_key:
        return _diff_keyed_lists(old_by_id, new_by_id, path, old_id_key)

    # Fallback: positional comparison.
    return _diff_positional_list(old, new, path)


def _index_by_id(
    items: list, id_keys: tuple[str, ...]
) -> tuple[dict[str, Any], str | None]:
    """Index a list of dicts by the first matching id key."""
    if not items or not isinstance(items[0], dict):
        return {}, None
    for key in id_keys:
        if all(isinstance(item, dict) and key in item for item in items):
            return {item[key]: item for item in items}, key
    return {}, None


def _diff_keyed_lists(
    old_by_id: dict[str, Any],
    new_by_id: dict[str, Any],
    path: str,
    id_key: str,
) -> list[FieldChange]:
    """Diff two lists that are keyed by an identifier field."""
    changes: list[FieldChange] = []
    all_ids = sorted(set(old_by_id.keys()) | set(new_by_id.keys()))

    for item_id in all_ids:
        item_path = f"{path}[{id_key}={item_id}]"
        if item_id not in old_by_id:
            changes.append(FieldChange(
                path=item_path,
                category=_categorise(path),
                new_value=new_by_id[item_id],
                change_type="added",
            ))
        elif item_id not in new_by_id:
            changes.append(FieldChange(
                path=item_path,
                category=_categorise(path),
                old_value=old_by_id[item_id],
                change_type="removed",
            ))
        elif old_by_id[item_id] != new_by_id[item_id]:
            changes.extend(_diff_values(
                old_by_id[item_id], new_by_id[item_id], item_path,
            ))

    return changes


def _diff_positional_list(old: list, new: list, path: str) -> list[FieldChange]:
    """Diff two lists by position."""
    changes: list[FieldChange] = []
    max_len = max(len(old), len(new))

    for i in range(max_len):
        item_path = f"{path}[{i}]"
        if i >= len(old):
            changes.append(FieldChange(
                path=item_path,
                category=_categorise(path),
                new_value=new[i],
                change_type="added",
            ))
        elif i >= len(new):
            changes.append(FieldChange(
                path=item_path,
                category=_categorise(path),
                old_value=old[i],
                change_type="removed",
            ))
        elif old[i] != new[i]:
            if isinstance(old[i], dict) and isinstance(new[i], dict):
                changes.extend(_diff_values(old[i], new[i], item_path))
            else:
                changes.append(FieldChange(
                    path=item_path,
                    category=_categorise(path),
                    old_value=old[i],
                    new_value=new[i],
                    change_type="modified",
                ))

    return changes


def _analyse_metrics(old: dict, new: dict) -> list[MetricChange]:
    """Analyse evaluation metric changes between certificates.

    Extracts primaryMetrics from both and computes regression info.
    Also checks against globalConstraints.performanceFloor if present.
    """
    old_metrics = _extract_metrics(old)
    new_metrics = _extract_metrics(new)

    # Get performance floor from old certificate's change envelope.
    floors = _extract_performance_floor(old)

    metric_changes: list[MetricChange] = []
    all_names = sorted(set(old_metrics.keys()) | set(new_metrics.keys()))

    for name in all_names:
        if name in old_metrics and name in new_metrics:
            old_val = old_metrics[name]
            new_val = new_metrics[name]
            change = new_val - old_val
            if change == 0.0:
                continue  # No change — skip.
            floor = floors.get(name)
            mc = MetricChange(
                metric_name=name,
                old_value=old_val,
                new_value=new_val,
                absolute_change=change,
                is_regression=change < 0,
                breaches_floor=new_val < floor if floor is not None else False,
                floor_value=floor,
            )
            metric_changes.append(mc)

    return metric_changes


def _extract_metrics(cert: dict) -> dict[str, float]:
    """Extract primary metric values as {name: value}."""
    metrics: dict[str, float] = {}
    primary = cert.get("evaluation", {}).get("primaryMetrics", [])
    for m in primary:
        name = m.get("metricName", "")
        value = m.get("value")
        if name and isinstance(value, (int, float)):
            metrics[name] = float(value)
    return metrics


def _extract_performance_floor(cert: dict) -> dict[str, float]:
    """Extract performance floor from approvedChangeEnvelope.globalConstraints."""
    floors: dict[str, float] = {}
    envelope = cert.get("approvedChangeEnvelope", {})
    constraints = envelope.get("globalConstraints", {})
    for floor in constraints.get("performanceFloor", []):
        name = floor.get("metricName", "")
        value = floor.get("value")
        if name and isinstance(value, (int, float)):
            floors[name] = float(value)
    return floors
