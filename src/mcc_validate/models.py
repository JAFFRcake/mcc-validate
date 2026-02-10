"""Core data models for MCC validation findings and reports."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class Severity(enum.Enum):
    """Severity level for validation findings."""

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class ValidationLayer(enum.Enum):
    """Validation pipeline layers."""

    SCHEMA = 1
    TIER_COMPLIANCE = 2
    CRYPTOGRAPHIC = 3
    LIFECYCLE = 4
    COMPOSITIONAL = 5


@dataclass
class Finding:
    """A single validation finding."""

    rule_id: str
    layer: ValidationLayer
    severity: Severity
    message: str
    path: str = ""
    reference: str = ""
    fix: str = ""

    def __str__(self) -> str:
        parts = [f"{self.severity.value.upper()}  {self.rule_id}  {self.message}"]
        if self.path:
            parts.append(f"       Path: {self.path}")
        if self.reference:
            parts.append(f"       Ref:  {self.reference}")
        if self.fix:
            parts.append(f"       Fix:  {self.fix}")
        return "\n".join(parts)


@dataclass
class LayerResult:
    """Result from a single validation layer."""

    layer: ValidationLayer
    findings: list[Finding] = field(default_factory=list)
    checks_passed: int = 0
    skipped: bool = False
    skip_reason: str = ""
    not_applicable: bool = False

    @property
    def errors(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.ERROR]

    @property
    def warnings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.WARNING]

    @property
    def has_errors(self) -> bool:
        return len(self.errors) > 0


@dataclass
class ValidationReport:
    """Complete validation report aggregating all layers."""

    certificate_id: str = ""
    certificate_name: str = ""
    certificate_version: str = ""
    risk_tier: int = 0
    status: str = ""
    expires: str = ""
    layer_results: list[LayerResult] = field(default_factory=list)

    @property
    def all_findings(self) -> list[Finding]:
        findings = []
        for lr in self.layer_results:
            findings.extend(lr.findings)
        return findings

    @property
    def total_checks_passed(self) -> int:
        return sum(lr.checks_passed for lr in self.layer_results)

    @property
    def total_errors(self) -> int:
        return sum(len(lr.errors) for lr in self.layer_results)

    @property
    def total_warnings(self) -> int:
        return sum(len(lr.warnings) for lr in self.layer_results)

    @property
    def is_valid(self) -> bool:
        return self.total_errors == 0

    @property
    def exit_code(self) -> int:
        if self.total_errors > 0:
            return 1
        if self.total_warnings > 0:
            return 2
        return 0
