"""Click-based CLI entry point for mcc-validate."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from mcc_validate import __version__
from mcc_validate.config import Config, load_config
from mcc_validate.core import validate_certificate
from mcc_validate.core.change_classifier import ChangeClassification, classify_change
from mcc_validate.core.diff_engine import ChangeCategory, diff_certificates
from mcc_validate.models import ValidationReport
from mcc_validate.reporters import console_reporter, json_reporter
from mcc_validate.reporters import html_reporter, sarif_reporter


@click.group()
@click.version_option(version=__version__, prog_name="mcc-validate")
@click.option("--verbose", "-v", count=True, help="Increase output verbosity.")
@click.option("--quiet", "-q", is_flag=True, help="Suppress all output except errors and exit code.")
@click.option("--strict", is_flag=True, help="Treat warnings as errors (exit code 1).")
@click.option("--schema", "schema_path", type=click.Path(exists=True), default=None, help="Custom schema file.")
@click.option("--no-color", is_flag=True, help="Disable coloured terminal output.")
@click.option("--config", "config_path", type=click.Path(), default=None, help="Configuration file (.mcc-validate.yaml).")
@click.pass_context
def main(ctx: click.Context, verbose: int, quiet: bool, strict: bool, schema_path: str | None, no_color: bool, config_path: str | None) -> None:
    """MCC Validator — validate Model Context Certificates against MCC-STD-001."""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    ctx.obj["quiet"] = quiet
    ctx.obj["strict"] = strict
    ctx.obj["schema_path"] = schema_path
    ctx.obj["no_color"] = no_color
    ctx.obj["config"] = load_config(config_path)


@main.command()
@click.argument("certificate", type=click.Path(exists=True))
@click.option("--format", "output_format", type=click.Choice(["console", "json", "html", "sarif"]), default="console", help="Output format.")
@click.option("--output", "-o", "output_path", type=click.Path(), default=None, help="Write report to file.")
@click.option("--weights", "weights_path", type=click.Path(), default=None, help="Model weight file for hash verification.")
@click.option("--verify-signature", "public_key_path", type=click.Path(), default=None, help="PEM public key for signature verification.")
@click.option("--components", "components_dir", type=click.Path(), default=None, help="Directory containing component certificate files.")
@click.option("--ci", is_flag=True, help="CI mode: implies --format sarif --strict, writes to configured path.")
@click.pass_context
def check(ctx: click.Context, certificate: str, output_format: str, output_path: str | None, weights_path: str | None, public_key_path: str | None, components_dir: str | None, ci: bool) -> None:
    """Validate a Model Context Certificate."""
    verbose = ctx.obj["verbose"]
    quiet = ctx.obj["quiet"]
    strict = ctx.obj["strict"]
    schema_path = ctx.obj["schema_path"]
    config: Config = ctx.obj["config"]

    # CI mode overrides
    if ci:
        output_format = "sarif"
        strict = True
        if not output_path:
            output_path = config.ci_sarif_output or "mcc-validate.sarif"

    # Load certificate
    cert_path = Path(certificate)
    try:
        cert_data = json.loads(cert_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        if not quiet:
            click.echo(f"Error: Malformed JSON in {certificate}: {e}", err=True)
        sys.exit(3)
    except Exception as e:
        if not quiet:
            click.echo(f"Error: Could not read {certificate}: {e}", err=True)
        sys.exit(3)

    if not isinstance(cert_data, dict):
        if not quiet:
            click.echo(f"Error: Certificate must be a JSON object, got {type(cert_data).__name__}", err=True)
        sys.exit(3)

    # Run validation pipeline
    report = validate_certificate(
        cert_data,
        schema_path=schema_path,
        weights_path=weights_path,
        public_key_path=public_key_path,
        components_dir=components_dir,
        config=config,
    )

    # Determine exit code
    exit_code = report.exit_code
    if (strict or config.ci_fail_on_warnings) and report.total_warnings > 0:
        exit_code = 1

    # Output
    _output_report(report, output_format, output_path, quiet, verbose, certificate)
    sys.exit(exit_code)


@main.command()
@click.option("--tier", type=click.IntRange(1, 4), required=True, help="Risk tier (1-4).")
@click.option("--output", "-o", "output_path", type=click.Path(), default=None, help="Output file path.")
def init(tier: int, output_path: str | None) -> None:
    """Scaffold an empty certificate template at a given tier."""
    import uuid
    from datetime import date, timedelta

    max_months = {1: 36, 2: 24, 3: 12, 4: 12}
    today = date.today()
    expires = today + timedelta(days=max_months[tier] * 30)

    template: dict = {
        "@context": "https://mcc-standard.org/v1",
        "@type": "ModelContextCertificate",
        "certificateId": str(uuid.uuid4()),
        "version": "1.0.0",
        "issued": today.isoformat(),
        "expires": expires.isoformat(),
        "riskTier": tier,
        "status": "active",
        "identity": {
            "certificateAuthority": {
                "legalName": "TODO: Certificate Authority name",
                "jurisdiction": "TODO: e.g. GB",
            },
            "certificateHolder": {
                "legalName": "TODO: Organisation name",
                "jurisdiction": "TODO: e.g. GB",
            },
            "modelName": "TODO: Model name",
            "modelVersion": "TODO: e.g. 1.0.0",
            "weightHash": {
                "algorithm": "SHA-256",
                "value": "TODO: hex hash of model weights",
                "serialisationMethod": "TODO: e.g. safetensors-canonical",
            },
        },
        "architecture": {
            "modelType": "TODO: e.g. transformer-decoder, convolutional",
            "parameterCount": 0,
            "inputModalities": ["TODO"],
            "outputModalities": ["TODO"],
        },
        "trainingData": {
            "containsPatientData": False,
            "dataCategories": ["TODO"],
            "licensingCompliance": {
                "allDatasetsLicensed": True,
                "complianceStatement": "TODO: Describe licensing compliance.",
            },
        },
        "evaluation": {
            "methodology": "TODO: Describe evaluation methodology.",
            "primaryMetrics": [
                {
                    "metricName": "TODO",
                    "value": 0.0,
                }
            ],
            "limitations": ["TODO: List known limitations."],
        },
        "usageEnvelope": {
            "intendedPurpose": {
                "description": "TODO: Describe the intended clinical purpose.",
            },
            "approvedPopulations": {
                "ageRange": {"minimum": 0, "maximum": 120},
            },
            "excludedPopulations": ["TODO"],
            "inputSpecifications": {
                "dataFormats": ["TODO"],
            },
            "outputSpecifications": {
                "format": "TODO",
            },
            "humanInTheLoop": {
                "required": True,
            },
            "excludedUses": ["TODO: List excluded uses."],
        },
        "runtime": {
            "infrastructureRequirements": {
                "minimumCompute": "TODO",
            },
            "logging": {
                "requiredFields": ["inference_id", "timestamp"],
                "retentionPeriod": "TODO: e.g. 7 years",
            },
        },
        "signature": {
            "algorithm": "ES256",
            "keyId": "TODO: signing key identifier",
            "signatureValue": "TODO: base64url JWS signature",
            "signedAt": "TODO: ISO 8601 datetime",
        },
    }

    # Add tier-specific fields
    if tier >= 2:
        template["architecture"]["layerCount"] = 0
        template["trainingData"]["datasets"] = [
            {
                "datasetId": "TODO",
                "datasetName": "TODO",
                "category": "TODO",
            }
        ]
        template["evaluation"]["demographicStratification"] = [
            {"stratificationAxis": "sex", "strata": []},
            {"stratificationAxis": "age-group", "strata": []},
            {"stratificationAxis": "ethnicity", "strata": []},
        ]
        template["evaluation"]["adversarialAssessment"] = {
            "methodology": "TODO",
            "findings": "TODO",
        }
        template["evaluation"]["primaryMetrics"][0]["confidenceInterval"] = {
            "lower": 0.0,
            "upper": 0.0,
        }

    if tier >= 3:
        template["trainingData"]["dataProcessingPipeline"] = [
            {
                "stepOrder": 1,
                "stepName": "TODO",
                "description": "TODO",
            }
        ]
        template["trainingData"]["knownBiases"] = [
            {
                "biasType": "TODO",
                "description": "TODO",
            }
        ]
        template["evaluation"]["independentEvaluation"] = {
            "evaluator": {
                "legalName": "TODO",
                "jurisdiction": "TODO",
            },
            "dateCompleted": "TODO",
            "findings": "TODO",
        }
        template["evaluation"]["confidenceCalibration"] = {
            "methodology": "TODO",
            "expectedCalibrationError": 0.0,
            "findings": "TODO",
        }
        template["runtime"]["driftDetection"] = {
            "methodology": "TODO",
            "thresholds": [
                {
                    "metric": "TODO",
                    "criticalThreshold": 0.0,
                }
            ],
        }

    if tier >= 4:
        template["evaluation"]["clinicalEvidence"] = {
            "trialRegistration": "TODO: e.g. ISRCTN12345678",
            "trialDesign": "TODO",
            "results": "TODO",
        }

    output_text = json.dumps(template, indent=2)

    if output_path:
        Path(output_path).write_text(output_text, encoding="utf-8")
        click.echo(f"Tier {tier} certificate template written to {output_path}")
    else:
        click.echo(output_text)


@main.command()
@click.argument("certificate", type=click.Path(exists=True))
def status(certificate: str) -> None:
    """Check certificate expiry status."""
    from datetime import date

    cert_path = Path(certificate)
    try:
        cert_data = json.loads(cert_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, Exception) as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(3)

    name = cert_data.get("identity", {}).get("modelName", "Unknown")
    version = cert_data.get("version", "?")
    status_val = cert_data.get("status", "unknown")
    expires_str = cert_data.get("expires", "")

    click.echo(f"Certificate: {name} v{version}")
    click.echo(f"Status:      {status_val}")

    if expires_str:
        try:
            exp = date.fromisoformat(expires_str)
            today = date.today()
            days = (exp - today).days

            if days < 0:
                click.echo(f"Expires:     {expires_str} (EXPIRED {abs(days)} days ago)")
                sys.exit(1)
            elif days <= 30:
                click.echo(f"Expires:     {expires_str} (CRITICAL: {days} days remaining)")
                sys.exit(2)
            elif days <= 90:
                click.echo(f"Expires:     {expires_str} (WARNING: {days} days remaining)")
                sys.exit(2)
            else:
                click.echo(f"Expires:     {expires_str} ({days} days remaining)")
                sys.exit(0)
        except ValueError:
            click.echo(f"Expires:     {expires_str} (invalid date)")
            sys.exit(3)
    else:
        click.echo("Expires:     not specified")
        sys.exit(3)


def _load_cert(path_str: str, quiet: bool = False) -> dict:
    """Load and parse a certificate JSON file. Exits on error."""
    cert_path = Path(path_str)
    try:
        data = json.loads(cert_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        if not quiet:
            click.echo(f"Error: Malformed JSON in {path_str}: {e}", err=True)
        sys.exit(3)
    except Exception as e:
        if not quiet:
            click.echo(f"Error: Could not read {path_str}: {e}", err=True)
        sys.exit(3)

    if not isinstance(data, dict):
        if not quiet:
            click.echo(f"Error: Certificate must be a JSON object, got {type(data).__name__}", err=True)
        sys.exit(3)
    return data


def _output_report(
    report: ValidationReport,
    output_format: str,
    output_path: str | None,
    quiet: bool,
    verbose: int,
    certificate_path: str,
) -> None:
    """Render and output a validation report in the requested format."""
    if output_format == "json":
        report_text = json_reporter.render_report(report)
    elif output_format == "html":
        report_text = html_reporter.render_report(report)
    elif output_format == "sarif":
        report_text = sarif_reporter.render_report(report, certificate_path=certificate_path)
    else:
        report_text = None  # Console renders directly

    if report_text is not None:
        if output_path:
            Path(output_path).write_text(report_text, encoding="utf-8")
            if not quiet:
                click.echo(f"Report written to {output_path}")
        elif not quiet:
            click.echo(report_text)
    else:
        # Console format
        if output_path:
            fallback = json_reporter.render_report(report)
            Path(output_path).write_text(fallback, encoding="utf-8")
            if not quiet:
                click.echo(f"Report written to {output_path}")
        if not quiet:
            console_reporter.render_report(report, verbose=verbose)


@main.command()
@click.argument("old_certificate", type=click.Path(exists=True))
@click.argument("new_certificate", type=click.Path(exists=True))
@click.option("--format", "output_format", type=click.Choice(["console", "json"]), default="console", help="Output format.")
@click.option("--output", "-o", "output_path", type=click.Path(), default=None, help="Write diff report to file.")
@click.pass_context
def diff(ctx: click.Context, old_certificate: str, new_certificate: str, output_format: str, output_path: str | None) -> None:
    """Compare two certificate versions and show changes."""
    quiet = ctx.obj["quiet"]
    old_data = _load_cert(old_certificate, quiet)
    new_data = _load_cert(new_certificate, quiet)

    report = diff_certificates(old_data, new_data)

    if output_format == "json":
        result = {
            "oldVersion": report.old_version,
            "newVersion": report.new_version,
            "oldCertificateId": report.old_cert_id,
            "newCertificateId": report.new_cert_id,
            "totalChanges": len(report.changes),
            "categoriesChanged": sorted(c.value for c in report.categories_changed),
            "changes": [
                {
                    "path": c.path,
                    "category": c.category.value,
                    "changeType": c.change_type,
                    "oldValue": _json_safe(c.old_value),
                    "newValue": _json_safe(c.new_value),
                }
                for c in report.changes
            ],
            "metricChanges": [
                {
                    "metricName": m.metric_name,
                    "oldValue": m.old_value,
                    "newValue": m.new_value,
                    "absoluteChange": round(m.absolute_change, 6),
                    "isRegression": m.is_regression,
                    "breachesFloor": m.breaches_floor,
                    "floorValue": m.floor_value,
                }
                for m in report.metric_changes
            ],
        }
        text = json.dumps(result, indent=2)
        if output_path:
            Path(output_path).write_text(text, encoding="utf-8")
            if not quiet:
                click.echo(f"Diff report written to {output_path}")
        elif not quiet:
            click.echo(text)
    else:
        if not quiet:
            _render_diff_console(report)
        if output_path:
            # Write JSON to file even for console format
            result_json = json.dumps({
                "totalChanges": len(report.changes),
                "changes": [str(c) for c in report.changes],
            }, indent=2)
            Path(output_path).write_text(result_json, encoding="utf-8")
            click.echo(f"Diff report written to {output_path}")

    sys.exit(0 if not report.has_changes else 1)


@main.command(name="classify-change")
@click.argument("old_certificate", type=click.Path(exists=True))
@click.argument("new_certificate", type=click.Path(exists=True))
@click.option("--format", "output_format", type=click.Choice(["console", "json"]), default="console", help="Output format.")
@click.option("--output", "-o", "output_path", type=click.Path(), default=None, help="Write classification report to file.")
@click.pass_context
def classify_change_cmd(ctx: click.Context, old_certificate: str, new_certificate: str, output_format: str, output_path: str | None) -> None:
    """Classify changes between two certificate versions against the change envelope."""
    quiet = ctx.obj["quiet"]
    old_data = _load_cert(old_certificate, quiet)
    new_data = _load_cert(new_certificate, quiet)

    result = classify_change(old_data, new_data)

    exit_codes = {
        ChangeClassification.IMMATERIAL: 0,
        ChangeClassification.WITHIN_ENVELOPE: 0,
        ChangeClassification.OUTSIDE_ENVELOPE: 1,
        ChangeClassification.INDETERMINATE: 2,
    }

    if output_format == "json":
        output = {
            "classification": result.classification.value,
            "oldVersion": result.diff_report.old_version,
            "newVersion": result.diff_report.new_version,
            "totalChanges": len(result.diff_report.changes),
            "coveredChanges": len(result.covered_changes),
            "uncoveredChanges": len(result.uncovered_changes),
            "floorBreaches": [
                {
                    "metricName": m.metric_name,
                    "newValue": m.new_value,
                    "floorValue": m.floor_value,
                }
                for m in result.floor_breaches
            ],
            "notes": result.envelope_notes,
        }
        text = json.dumps(output, indent=2)
        if output_path:
            Path(output_path).write_text(text, encoding="utf-8")
            if not quiet:
                click.echo(f"Classification report written to {output_path}")
        elif not quiet:
            click.echo(text)
    else:
        if not quiet:
            _render_classification_console(result)
        if output_path:
            output_json = json.dumps({
                "classification": result.classification.value,
                "notes": result.envelope_notes,
            }, indent=2)
            Path(output_path).write_text(output_json, encoding="utf-8")
            click.echo(f"Classification report written to {output_path}")

    sys.exit(exit_codes.get(result.classification, 4))


# ---------------------------------------------------------------------------
# Console rendering helpers for diff and classify-change
# ---------------------------------------------------------------------------

_CATEGORY_LABELS = {
    ChangeCategory.METADATA: "Metadata",
    ChangeCategory.IDENTITY: "Identity & Provenance",
    ChangeCategory.ARCHITECTURE: "Architecture",
    ChangeCategory.TRAINING_DATA: "Training Data",
    ChangeCategory.EVALUATION: "Evaluation",
    ChangeCategory.USAGE_ENVELOPE: "Usage Envelope",
    ChangeCategory.RUNTIME: "Runtime & Monitoring",
    ChangeCategory.CHANGE_ENVELOPE: "Change Envelope",
    ChangeCategory.COMPOSITION: "Composition",
    ChangeCategory.SIGNATURE: "Signature",
}


def _json_safe(value: object) -> object:
    """Make a value JSON-serialisable by converting non-basic types to strings."""
    if isinstance(value, (str, int, float, bool, type(None))):
        return value
    if isinstance(value, (list, dict)):
        return value
    return str(value)


def _render_diff_console(report: "diff_certificates.__class__") -> None:
    """Render a diff report to the console."""
    from mcc_validate.core.diff_engine import DiffReport
    assert isinstance(report, DiffReport)

    click.echo()
    click.echo(f"  Diff: v{report.old_version} -> v{report.new_version}")
    click.echo(f"  {len(report.changes)} change(s) detected")
    click.echo()

    # Group by category
    for cat in ChangeCategory:
        cat_changes = report.changes_in(cat)
        if not cat_changes:
            continue
        label = _CATEGORY_LABELS.get(cat, cat.value)
        click.echo(f"  [{label}] ({len(cat_changes)} changes)")
        for c in cat_changes:
            click.echo(f"    {c}")
        click.echo()

    # Metric regressions
    if report.metric_changes:
        click.echo("  [Metric Analysis]")
        for mc in report.metric_changes:
            direction = "REGRESSION" if mc.is_regression else "improvement"
            floor_note = ""
            if mc.breaches_floor:
                floor_note = f" ** BREACHES FLOOR ({mc.floor_value}) **"
            click.echo(
                f"    {mc.metric_name}: {mc.old_value:.4f} -> {mc.new_value:.4f} "
                f"({mc.absolute_change:+.4f} {direction}){floor_note}"
            )
        click.echo()


def _render_classification_console(result: object) -> None:
    """Render a classification result to the console."""
    from mcc_validate.core.change_classifier import ClassificationResult
    assert isinstance(result, ClassificationResult)

    click.echo()
    label_map = {
        ChangeClassification.IMMATERIAL: "IMMATERIAL - No material changes",
        ChangeClassification.WITHIN_ENVELOPE: "WITHIN ENVELOPE - Certificate update required",
        ChangeClassification.OUTSIDE_ENVELOPE: "OUTSIDE ENVELOPE - Recertification required",
        ChangeClassification.INDETERMINATE: "INDETERMINATE - Manual review needed",
    }
    click.echo(f"  Classification: {label_map.get(result.classification, result.classification.value)}")
    click.echo(f"  Old version: v{result.diff_report.old_version}")
    click.echo(f"  New version: v{result.diff_report.new_version}")
    click.echo()

    if result.covered_changes:
        click.echo(f"  Covered by envelope ({len(result.covered_changes)}):")
        for em in result.covered_changes:
            bounds_str = "within bounds" if em.within_bounds else "EXCEEDS BOUNDS"
            click.echo(f"    [{em.change_type}] {em.change.path} ({bounds_str})")
        click.echo()

    if result.uncovered_changes:
        click.echo(f"  NOT covered by envelope ({len(result.uncovered_changes)}):")
        for c in result.uncovered_changes:
            click.echo(f"    {c}")
        click.echo()

    if result.floor_breaches:
        click.echo("  Performance floor breaches:")
        for m in result.floor_breaches:
            click.echo(f"    {m.metric_name}: {m.new_value} < floor {m.floor_value}")
        click.echo()

    for note in result.envelope_notes:
        click.echo(f"  Note: {note}")
    click.echo()


@main.command()
@click.option("--host", default="127.0.0.1", help="Host to bind to.")
@click.option("--port", default=8080, type=int, help="Port to bind to.")
@click.option("--debug", is_flag=True, help="Enable Flask debug mode.")
def serve(host: str, port: int, debug: bool) -> None:
    """Start the web-based certificate validator."""
    try:
        from mcc_validate.web.app import create_app
    except ImportError:
        click.echo(
            "Error: Web dependencies not installed. Run: pip install mcc-validate[web]",
            err=True,
        )
        sys.exit(1)

    app = create_app()
    click.echo(f"Starting MCC Validator web interface on http://{host}:{port}")
    app.run(host=host, port=port, debug=debug)
