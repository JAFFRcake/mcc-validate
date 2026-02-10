"""SARIF reporter — Static Analysis Results Interchange Format.

Produces SARIF v2.1.0 output suitable for GitHub Code Scanning,
Azure DevOps, and other CI/CD platforms.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from mcc_validate import __version__
from mcc_validate.models import (
    Finding,
    Severity,
    ValidationLayer,
    ValidationReport,
)

_SARIF_VERSION = "2.1.0"
_SARIF_SCHEMA = "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json"

_SEVERITY_MAP = {
    Severity.ERROR: "error",
    Severity.WARNING: "warning",
    Severity.INFO: "note",
}

_LAYER_NAMES = {
    ValidationLayer.SCHEMA: "Schema Validation",
    ValidationLayer.TIER_COMPLIANCE: "Tier Compliance",
    ValidationLayer.CRYPTOGRAPHIC: "Cryptographic Verification",
    ValidationLayer.LIFECYCLE: "Lifecycle Checks",
    ValidationLayer.COMPOSITIONAL: "Compositional Integrity",
}


def render_report(
    report: ValidationReport,
    certificate_path: str = "certificate.json",
    automation_id: str | None = None,
) -> str:
    """Render a validation report as a SARIF v2.1.0 JSON string.

    Parameters
    ----------
    report:
        The validation report to render.
    certificate_path:
        The file path of the certificate being validated (used in SARIF locations).
    automation_id:
        Optional automation run ID for GitHub Code Scanning correlation.
        Defaults to ``mcc-validate/{certificate_path}``.
    """
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for finding in report.all_findings:
        # Build rule entry (deduplicated by rule_id)
        if finding.rule_id not in rules:
            layer_name = _LAYER_NAMES.get(finding.layer, finding.layer.name)
            rules[finding.rule_id] = {
                "id": finding.rule_id,
                "shortDescription": {"text": finding.rule_id},
                "fullDescription": {"text": finding.message},
                "properties": {
                    "layer": layer_name,
                },
            }
            if finding.reference:
                rules[finding.rule_id]["helpUri"] = finding.reference

        # Build result
        result_entry: dict = {
            "ruleId": finding.rule_id,
            "level": _SEVERITY_MAP.get(finding.severity, "note"),
            "message": {"text": finding.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": certificate_path,
                        },
                    },
                    "logicalLocations": [],
                }
            ],
        }

        # Add JSON path as logical location
        if finding.path:
            result_entry["locations"][0]["logicalLocations"].append({
                "fullyQualifiedName": finding.path,
                "kind": "object",
            })

        # Add fix suggestion
        if finding.fix:
            result_entry["fixes"] = [
                {
                    "description": {"text": finding.fix},
                }
            ]

        results.append(result_entry)

    # Build ordered rule list
    rules_list = list(rules.values())

    run_automation_id = automation_id or f"mcc-validate/{certificate_path}"

    sarif = {
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcc-validate",
                        "version": __version__,
                        "informationUri": "https://github.com/mcc-standard/mcc-validate",
                        "rules": rules_list,
                    }
                },
                "automationDetails": {
                    "id": run_automation_id,
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.now(UTC).isoformat(),
                    }
                ],
            }
        ],
    }

    return json.dumps(sarif, indent=2)
