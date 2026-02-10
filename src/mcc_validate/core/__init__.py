"""Core validation pipeline."""

from __future__ import annotations

from pathlib import Path

from mcc_validate.config import Config, apply_overrides
from mcc_validate.core.composition_checker import check_composition
from mcc_validate.core.expiry_checker import check_lifecycle
from mcc_validate.core.hash_verifier import verify_weight_hash
from mcc_validate.core.schema_validator import validate_schema
from mcc_validate.core.signature_verifier import verify_signature
from mcc_validate.core.tier_checker import check_tier_compliance
from mcc_validate.models import LayerResult, ValidationLayer, ValidationReport


def validate_certificate(
    cert_data: dict,
    schema_path: str | Path | None = None,
    weights_path: str | Path | None = None,
    public_key_path: str | Path | None = None,
    components_dir: str | Path | None = None,
    config: Config | None = None,
) -> ValidationReport:
    """Run the full 5-layer validation pipeline on a certificate dict.

    This is the primary programmatic API. The CLI and web app both call this.

    Parameters
    ----------
    cert_data:
        Parsed certificate as a Python dict.
    schema_path:
        Optional custom JSON Schema file path.
    weights_path:
        Optional model weight file for hash verification.
    public_key_path:
        Optional PEM public key for signature verification.
    components_dir:
        Optional directory containing component certificate JSON files.
    config:
        Optional configuration with rule overrides and CI settings.
    """
    if config is None:
        config = Config.default()

    report = ValidationReport(
        certificate_id=cert_data.get("certificateId", ""),
        certificate_name=cert_data.get("identity", {}).get("modelName", ""),
        certificate_version=cert_data.get("version", ""),
        risk_tier=cert_data.get("riskTier", 0),
        status=cert_data.get("status", ""),
        expires=cert_data.get("expires", ""),
    )

    # Layer 1: Schema validation
    layer1 = validate_schema(cert_data, schema_path)
    report.layer_results.append(layer1)

    # Layer 2: Tier-aware compliance
    layer2 = check_tier_compliance(cert_data)
    report.layer_results.append(layer2)

    # Layer 3: Cryptographic verification
    if weights_path or public_key_path:
        layer3 = LayerResult(layer=ValidationLayer.CRYPTOGRAPHIC)

        if weights_path:
            hash_result = verify_weight_hash(cert_data, weights_path)
            layer3.findings.extend(hash_result.findings)
            layer3.checks_passed += hash_result.checks_passed

        sig_result = verify_signature(cert_data, public_key_path)
        layer3.findings.extend(sig_result.findings)
        layer3.checks_passed += sig_result.checks_passed

        report.layer_results.append(layer3)
    else:
        layer3 = LayerResult(
            layer=ValidationLayer.CRYPTOGRAPHIC,
            skipped=True,
            skip_reason="use --weights or --verify-signature",
        )
        report.layer_results.append(layer3)

    # Layer 4: Lifecycle checks
    layer4 = check_lifecycle(cert_data)
    report.layer_results.append(layer4)

    # Layer 5: Compositional integrity
    has_composition = "composition" in cert_data
    if has_composition and components_dir:
        layer5 = check_composition(cert_data, components_dir)
    elif has_composition:
        layer5 = LayerResult(
            layer=ValidationLayer.COMPOSITIONAL,
            skipped=True,
            skip_reason="use --components",
        )
    else:
        layer5 = LayerResult(
            layer=ValidationLayer.COMPOSITIONAL,
            not_applicable=True,
        )
    report.layer_results.append(layer5)

    # Apply config rule overrides
    if config.rule_overrides:
        for lr in report.layer_results:
            lr.findings = apply_overrides(config, lr.findings)

    return report
