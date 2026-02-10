"""JSON reporter — machine-readable structured report."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from mcc_validate.models import ValidationReport


def render_report(report: ValidationReport) -> str:
    """Render a validation report as a JSON string."""
    output = {
        "mccValidator": {
            "version": "0.1.0",
            "timestamp": datetime.now(UTC).isoformat(),
        },
        "certificate": {
            "certificateId": report.certificate_id,
            "name": report.certificate_name,
            "version": report.certificate_version,
            "riskTier": report.risk_tier,
            "status": report.status,
            "expires": report.expires,
        },
        "result": {
            "valid": report.is_valid,
            "exitCode": report.exit_code,
            "totalChecksPassed": report.total_checks_passed,
            "totalErrors": report.total_errors,
            "totalWarnings": report.total_warnings,
        },
        "layers": [],
        "findings": [],
    }

    for lr in report.layer_results:
        layer_info = {
            "layer": lr.layer.value,
            "name": lr.layer.name,
            "checksPassed": lr.checks_passed,
            "errors": len(lr.errors),
            "warnings": len(lr.warnings),
            "skipped": lr.skipped,
            "notApplicable": lr.not_applicable,
        }
        if lr.skip_reason:
            layer_info["skipReason"] = lr.skip_reason
        output["layers"].append(layer_info)

    for finding in report.all_findings:
        finding_info = {
            "ruleId": finding.rule_id,
            "layer": finding.layer.value,
            "severity": finding.severity.value,
            "message": finding.message,
        }
        if finding.path:
            finding_info["path"] = finding.path
        if finding.reference:
            finding_info["reference"] = finding.reference
        if finding.fix:
            finding_info["fix"] = finding.fix
        output["findings"].append(finding_info)

    return json.dumps(output, indent=2)
