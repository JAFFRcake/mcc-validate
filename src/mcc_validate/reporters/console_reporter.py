"""Console reporter — human-readable terminal output using Rich."""

from __future__ import annotations

import sys

from rich.console import Console

from mcc_validate.models import (
    Finding,
    LayerResult,
    Severity,
    ValidationLayer,
    ValidationReport,
)


LAYER_NAMES = {
    ValidationLayer.SCHEMA: "Schema validation",
    ValidationLayer.TIER_COMPLIANCE: "Tier {tier} compliance",
    ValidationLayer.CRYPTOGRAPHIC: "Cryptographic verification",
    ValidationLayer.LIFECYCLE: "Lifecycle checks",
    ValidationLayer.COMPOSITIONAL: "Compositional integrity",
}

TIER_LABELS = {
    1: "Low Risk",
    2: "Moderate Risk",
    3: "High Risk",
    4: "Very High Risk",
}

# Use ASCII fallback on Windows when the terminal doesn't support Unicode
_SUPPORTS_UNICODE = sys.stdout.encoding and "utf" in sys.stdout.encoding.lower()
_RULE = "=" * 43 if not _SUPPORTS_UNICODE else "\u2501" * 43
_CHECK = "[bold green]v[/bold green]" if not _SUPPORTS_UNICODE else "[bold green]\u2713[/bold green]"
_CROSS = "[bold red]x[/bold red]" if not _SUPPORTS_UNICODE else "[bold red]\u2717[/bold red]"
_DASH = "-" if not _SUPPORTS_UNICODE else "\u2500"
_CIRCLE = "o" if not _SUPPORTS_UNICODE else "\u25CB"


def _severity_symbol(severity: Severity) -> str:
    return {
        Severity.ERROR: "[bold red]ERROR[/bold red] ",
        Severity.WARNING: "[bold yellow]WARN[/bold yellow]  ",
        Severity.INFO: "[bold blue]INFO[/bold blue]  ",
    }[severity]


def _layer_status(lr: LayerResult, tier: int) -> str:
    name = LAYER_NAMES.get(lr.layer, str(lr.layer))
    if "{tier}" in name:
        name = name.format(tier=tier)

    if lr.not_applicable:
        return f"  [dim]{_DASH}[/dim] Layer {lr.layer.value}: {name:<30s} [dim]not applicable[/dim]"
    if lr.skipped:
        reason = f" ({lr.skip_reason})" if lr.skip_reason else ""
        return f"  [dim]{_CIRCLE}[/dim] Layer {lr.layer.value}: {name:<30s} [dim]skipped{reason}[/dim]"
    if lr.has_errors:
        err_count = len(lr.errors)
        return f"  {_CROSS} Layer {lr.layer.value}: {name:<30s} {lr.checks_passed} passed, {err_count} error{'s' if err_count != 1 else ''}"
    warn_count = len(lr.warnings)
    if warn_count > 0:
        return f"  [bold yellow]![/bold yellow] Layer {lr.layer.value}: {name:<30s} {lr.checks_passed} passed, {warn_count} warning{'s' if warn_count != 1 else ''}"
    return f"  {_CHECK} Layer {lr.layer.value}: {name:<30s} {lr.checks_passed} checks passed"


def _render_finding(console: Console, finding: Finding) -> None:
    console.print(f"    {_severity_symbol(finding.severity)} {finding.rule_id}  {finding.message}")
    if finding.path:
        console.print(f"           [dim]Path: {finding.path}[/dim]")
    if finding.reference:
        console.print(f"           [dim]Ref:  {finding.reference}[/dim]")
    if finding.fix:
        console.print(f"           [dim]Fix:  {finding.fix}[/dim]")
    console.print()


def render_report(report: ValidationReport, verbose: int = 0) -> None:
    """Render a validation report to the terminal."""
    console = Console()

    console.print()
    console.print("  [bold]MCC Validator v0.1.0[/bold]")
    console.print(f"  {_RULE}")
    console.print()

    if report.certificate_name:
        console.print(f"  Certificate:  {report.certificate_name} (v{report.certificate_version})")
    if report.risk_tier:
        tier_label = TIER_LABELS.get(report.risk_tier, "Unknown")
        console.print(f"  Tier:         {report.risk_tier} ({tier_label})")
    if report.status:
        console.print(f"  Status:       {report.status}")
    if report.expires:
        from datetime import date

        try:
            exp = date.fromisoformat(report.expires)
            today = date.today()
            days = (exp - today).days
            console.print(f"  Expires:      {report.expires} ({days} days remaining)")
        except ValueError:
            console.print(f"  Expires:      {report.expires}")

    console.print()

    for lr in report.layer_results:
        console.print(_layer_status(lr, report.risk_tier))

        # Print findings for this layer
        if lr.findings and (lr.has_errors or verbose > 0):
            console.print()
            for finding in lr.findings:
                if finding.severity == Severity.ERROR or verbose > 0:
                    _render_finding(console, finding)

    console.print()
    console.print(f"  {_RULE}")

    if report.is_valid:
        if report.total_warnings > 0:
            console.print(
                f"  RESULT: VALID (with warnings) [bold yellow]![/bold yellow]   "
                f"{report.total_checks_passed} checks passed, "
                f"0 errors, {report.total_warnings} warning{'s' if report.total_warnings != 1 else ''}"
            )
        else:
            console.print(
                f"  RESULT: [bold green]VALID {_CHECK}[/bold green]   "
                f"{report.total_checks_passed} checks passed, "
                f"0 errors, 0 warnings"
            )
    else:
        console.print(
            f"  RESULT: [bold red]INVALID {_CROSS}[/bold red]   "
            f"{report.total_checks_passed} checks passed, "
            f"{report.total_errors} error{'s' if report.total_errors != 1 else ''}, "
            f"{report.total_warnings} warning{'s' if report.total_warnings != 1 else ''}"
        )

    console.print()
