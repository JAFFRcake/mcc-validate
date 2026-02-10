"""Layer 2: Tier-aware compliance checking.

Goes beyond JSON Schema to enforce tier-conditional requirements
from MCC-STD-001.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from mcc_validate.models import Finding, LayerResult, Severity, ValidationLayer


@dataclass
class ComplianceRule:
    """A tier-aware compliance rule."""

    rule_id: str
    tier: int  # minimum tier this applies from
    domain: str
    description: str
    severity: Severity
    check: Callable[[dict], Finding | None]
    reference: str


def _get_nested(data: dict, path: str, default: Any = None) -> Any:
    """Safely traverse a dotted path into a nested dict."""
    parts = path.split(".")
    current = data
    for part in parts:
        if isinstance(current, dict):
            current = current.get(part, default)
        else:
            return default
    return current


# Well-known public/open licences where a formal data controller is not required
_PUBLIC_LICENCES = {
    "cc0", "cc0 1.0", "cc0 1.0 universal",
    "cc by", "cc by 4.0", "cc-by-4.0",
    "cc by-sa", "cc by-sa 4.0",
    "apache-2.0", "mit", "bsd",
    "physionet", "physionet credentialed health data license",
}


def _is_public_dataset(ds: dict) -> bool:
    """Check if a dataset is publicly/openly licensed (no formal DSA required)."""
    licence = ds.get("licence", "")
    if not licence:
        return False
    return any(pub in licence.lower() for pub in _PUBLIC_LICENCES)


def _has_field(data: dict, path: str) -> bool:
    """Check if a nested field exists and is not None."""
    val = _get_nested(data, path)
    return val is not None


def _has_nonempty_array(data: dict, path: str) -> bool:
    """Check if a nested field exists and is a non-empty array."""
    val = _get_nested(data, path)
    return isinstance(val, list) and len(val) > 0


# --------------------------------------------------------------------------
# Tier 2+ rules
# --------------------------------------------------------------------------

def _check_layer_count(cert: dict) -> Finding | None:
    val = _get_nested(cert, "architecture.layerCount")
    if val is None or (isinstance(val, int) and val <= 0):
        return Finding(
            rule_id="T2-ARCH-001",
            layer=ValidationLayer.TIER_COMPLIANCE,
            severity=Severity.ERROR,
            message="layerCount must be present and > 0 for Tier 2+",
            path="architecture.layerCount",
            reference="MCC-STD-001 §5.3.2",
            fix="Add layerCount with the total number of model layers.",
        )
    return None


def _check_attention_mechanism(cert: dict) -> Finding | None:
    model_type = _get_nested(cert, "architecture.modelType", "")
    is_transformer = "transformer" in model_type.lower() if isinstance(model_type, str) else False
    if is_transformer and not _has_field(cert, "architecture.attentionMechanism"):
        return Finding(
            rule_id="T2-ARCH-002",
            layer=ValidationLayer.TIER_COMPLIANCE,
            severity=Severity.ERROR,
            message="attentionMechanism must be specified for transformer models at Tier 2+",
            path="architecture.attentionMechanism",
            reference="MCC-STD-001 §5.3.2",
            fix="Add attentionMechanism object with type, headCount, etc.",
        )
    return None


def _check_datasets_present(cert: dict) -> Finding | None:
    if not _has_nonempty_array(cert, "trainingData.datasets"):
        return Finding(
            rule_id="T2-DATA-001",
            layer=ValidationLayer.TIER_COMPLIANCE,
            severity=Severity.ERROR,
            message="At least one named dataset must be present in datasets array for Tier 2+",
            path="trainingData.datasets",
            reference="MCC-STD-001 §5.4.2",
            fix="Add datasets array with at least one DatasetSpecification.",
        )
    return None


def _check_demographic_distribution(cert: dict) -> Finding | None:
    datasets = _get_nested(cert, "trainingData.datasets", [])
    if not isinstance(datasets, list):
        return None
    for i, ds in enumerate(datasets):
        contains_patient = ds.get("containsPatientData", False)
        if contains_patient and not _has_field(ds, "demographicDistribution"):
            return Finding(
                rule_id="T2-DATA-002",
                layer=ValidationLayer.TIER_COMPLIANCE,
                severity=Severity.ERROR,
                message=f"Dataset '{ds.get('datasetName', f'[{i}]')}' contains patient data but has no demographicDistribution",
                path=f"trainingData.datasets[{i}].demographicDistribution",
                reference="MCC-STD-001 §5.4.2",
                fix="Add demographicDistribution with age, sex, and ethnicity breakdowns.",
            )
    return None


def _check_demographic_stratification(cert: dict) -> Finding | None:
    strat = _get_nested(cert, "evaluation.demographicStratification", [])
    if not isinstance(strat, list) or len(strat) < 3:
        return Finding(
            rule_id="T2-EVAL-001",
            layer=ValidationLayer.TIER_COMPLIANCE,
            severity=Severity.ERROR,
            message="demographicStratification must have at least 3 stratification axes for Tier 2+",
            path="evaluation.demographicStratification",
            reference="MCC-STD-001 §5.5",
            fix="Add stratification for at least sex, age group, and ethnicity.",
        )
    return None


def _check_adversarial_assessment(cert: dict) -> Finding | None:
    if not _has_field(cert, "evaluation.adversarialAssessment"):
        return Finding(
            rule_id="T2-EVAL-002",
            layer=ValidationLayer.TIER_COMPLIANCE,
            severity=Severity.ERROR,
            message="adversarialAssessment must be present for Tier 2+",
            path="evaluation.adversarialAssessment",
            reference="MCC-STD-001 §5.5",
            fix="Add adversarialAssessment with methodology, attack vectors, and findings.",
        )
    return None


def _check_confidence_intervals(cert: dict) -> Finding | None:
    """All PerformanceMetric entries should have confidenceInterval for Tier 2+."""
    metrics = _get_nested(cert, "evaluation.primaryMetrics", [])
    if not isinstance(metrics, list):
        return None
    for i, m in enumerate(metrics):
        if not _has_field(m, "confidenceInterval"):
            return Finding(
                rule_id="X-METR-001",
                layer=ValidationLayer.TIER_COMPLIANCE,
                severity=Severity.ERROR,
                message=f"Metric '{m.get('metricName', f'[{i}]')}' missing confidenceInterval (required for Tier 2+)",
                path=f"evaluation.primaryMetrics[{i}].confidenceInterval",
                reference="MCC-STD-001 §5.5",
                fix="Add confidenceInterval with lower, upper, and level.",
            )
    return None


# --------------------------------------------------------------------------
# Tier 3+ rules
# --------------------------------------------------------------------------

def _check_data_controller(cert: dict) -> Finding | None:
    datasets = _get_nested(cert, "trainingData.datasets", [])
    if not isinstance(datasets, list):
        return None
    for i, ds in enumerate(datasets):
        contains_patient = ds.get("containsPatientData", False)
        if contains_patient and not _is_public_dataset(ds) and not _has_field(ds, "dataController"):
            return Finding(
                rule_id="T3-DATA-001",
                layer=ValidationLayer.TIER_COMPLIANCE,
                severity=Severity.ERROR,
                message=f"Clinical dataset '{ds.get('datasetName', f'[{i}]')}' missing dataController",
                path=f"trainingData.datasets[{i}].dataController",
                reference="MCC-STD-001 §5.4.3",
                fix="Add dataController object with legalName and jurisdiction.",
            )
    return None


def _check_data_sharing_agreement(cert: dict) -> Finding | None:
    datasets = _get_nested(cert, "trainingData.datasets", [])
    if not isinstance(datasets, list):
        return None
    for i, ds in enumerate(datasets):
        contains_patient = ds.get("containsPatientData", False)
        if contains_patient and not _is_public_dataset(ds) and not _has_field(ds, "dataSharingAgreement"):
            return Finding(
                rule_id="T3-DATA-002",
                layer=ValidationLayer.TIER_COMPLIANCE,
                severity=Severity.ERROR,
                message=f"Clinical dataset '{ds.get('datasetName', f'[{i}]')}' missing dataSharingAgreement",
                path=f"trainingData.datasets[{i}].dataSharingAgreement",
                reference="MCC-STD-001 §5.4.3",
                fix="Add dataSharingAgreement with reference, dateExecuted, and permittedUses.",
            )
    return None


def _check_data_processing_pipeline(cert: dict) -> Finding | None:
    if not _has_nonempty_array(cert, "trainingData.dataProcessingPipeline"):
        return Finding(
            rule_id="T3-DATA-003",
            layer=ValidationLayer.TIER_COMPLIANCE,
            severity=Severity.ERROR,
            message="dataProcessingPipeline must be present with at least 1 step for Tier 3+",
            path="trainingData.dataProcessingPipeline",
            reference="MCC-STD-001 §5.4.3",
            fix="Add dataProcessingPipeline array with ProcessingStep entries.",
        )
    return None


def _check_known_biases(cert: dict) -> Finding | None:
    if not _has_nonempty_array(cert, "trainingData.knownBiases"):
        return Finding(
            rule_id="T3-DATA-004",
            layer=ValidationLayer.TIER_COMPLIANCE,
            severity=Severity.ERROR,
            message="knownBiases array must be present and non-empty for Tier 3+",
            path="trainingData.knownBiases",
            reference="MCC-STD-001 §5.4.3",
            fix="Add knownBiases array documenting data biases and mitigations.",
        )
    return None


def _check_independent_evaluation(cert: dict) -> Finding | None:
    if not _has_field(cert, "evaluation.independentEvaluation"):
        return Finding(
            rule_id="T3-EVAL-001",
            layer=ValidationLayer.TIER_COMPLIANCE,
            severity=Severity.ERROR,
            message="independentEvaluation must be present for Tier 3+",
            path="evaluation.independentEvaluation",
            reference="MCC-STD-001 §5.5",
            fix="Add independentEvaluation with evaluator, dateCompleted, and findings.",
        )
    return None


def _check_confidence_calibration(cert: dict) -> Finding | None:
    if not _has_field(cert, "evaluation.confidenceCalibration"):
        return Finding(
            rule_id="T3-EVAL-002",
            layer=ValidationLayer.TIER_COMPLIANCE,
            severity=Severity.ERROR,
            message="confidenceCalibration must be present for Tier 3+",
            path="evaluation.confidenceCalibration",
            reference="MCC-STD-001 §5.5",
            fix="Add confidenceCalibration with methodology, ECE, and findings.",
        )
    return None


def _check_drift_detection(cert: dict) -> Finding | None:
    dd = _get_nested(cert, "runtime.driftDetection")
    if dd is None:
        return Finding(
            rule_id="T3-RUNT-001",
            layer=ValidationLayer.TIER_COMPLIANCE,
            severity=Severity.ERROR,
            message="driftDetection must be present for Tier 3+",
            path="runtime.driftDetection",
            reference="MCC-STD-001 §5.7",
            fix="Add driftDetection with methodology, thresholds, and response protocol.",
        )
    if isinstance(dd, dict):
        thresholds = dd.get("thresholds", [])
        if not isinstance(thresholds, list) or len(thresholds) < 1:
            return Finding(
                rule_id="T3-RUNT-001",
                layer=ValidationLayer.TIER_COMPLIANCE,
                severity=Severity.ERROR,
                message="driftDetection must have at least 1 threshold for Tier 3+",
                path="runtime.driftDetection.thresholds",
                reference="MCC-STD-001 §5.7",
                fix="Add at least one threshold entry to driftDetection.thresholds.",
            )
    return None


# --------------------------------------------------------------------------
# Tier 4 rules
# --------------------------------------------------------------------------

def _check_clinical_evidence(cert: dict) -> Finding | None:
    ce = _get_nested(cert, "evaluation.clinicalEvidence")
    if ce is None:
        return Finding(
            rule_id="T4-EVAL-001",
            layer=ValidationLayer.TIER_COMPLIANCE,
            severity=Severity.ERROR,
            message="clinicalEvidence must be present for Tier 4",
            path="evaluation.clinicalEvidence",
            reference="MCC-STD-001 §5.5",
            fix="Add clinicalEvidence with trial registration and results.",
        )
    if isinstance(ce, dict) and not ce.get("trialRegistration"):
        return Finding(
            rule_id="T4-EVAL-001",
            layer=ValidationLayer.TIER_COMPLIANCE,
            severity=Severity.ERROR,
            message="clinicalEvidence must include trialRegistration for Tier 4",
            path="evaluation.clinicalEvidence.trialRegistration",
            reference="MCC-STD-001 §5.5",
            fix="Add trialRegistration (e.g. ISRCTN or NCT ID).",
        )
    return None


def _check_real_world_evidence(cert: dict) -> Finding | None:
    if not _has_field(cert, "evaluation.realWorldEvidence"):
        return Finding(
            rule_id="T4-EVAL-002",
            layer=ValidationLayer.TIER_COMPLIANCE,
            severity=Severity.WARNING,
            message="realWorldEvidence recommended for Tier 4 (required for renewals)",
            path="evaluation.realWorldEvidence",
            reference="MCC-STD-001 §5.5",
            fix="Add realWorldEvidence for renewal submissions.",
        )
    return None


def _check_ethics_approval(cert: dict) -> Finding | None:
    datasets = _get_nested(cert, "trainingData.datasets", [])
    if not isinstance(datasets, list):
        return None
    for i, ds in enumerate(datasets):
        contains_patient = ds.get("containsPatientData", False)
        if contains_patient and not _has_field(ds, "ethicsApproval"):
            return Finding(
                rule_id="T4-DATA-001",
                layer=ValidationLayer.TIER_COMPLIANCE,
                severity=Severity.ERROR,
                message=f"Clinical dataset '{ds.get('datasetName', f'[{i}]')}' missing ethicsApproval (required for Tier 4)",
                path=f"trainingData.datasets[{i}].ethicsApproval",
                reference="MCC-STD-001 §5.4.4",
                fix="Add ethicsApproval with body, reference, and dateApproved.",
            )
    return None


# --------------------------------------------------------------------------
# Cross-domain rules
# --------------------------------------------------------------------------

def _check_expiry_duration(cert: dict) -> Finding | None:
    """Check that certificate validity duration does not exceed tier maximum."""
    from datetime import date

    issued_str = cert.get("issued", "")
    expires_str = cert.get("expires", "")
    tier = cert.get("riskTier", 1)

    if not issued_str or not expires_str:
        return None

    try:
        issued = date.fromisoformat(issued_str)
        expires = date.fromisoformat(expires_str)
    except ValueError:
        return None

    max_months = {1: 36, 2: 24, 3: 12, 4: 12}
    max_m = max_months.get(tier, 36)

    # Approximate month calculation
    months = (expires.year - issued.year) * 12 + (expires.month - issued.month)
    if expires.day > issued.day:
        months += 1  # partial month counts up

    if months > max_m:
        return Finding(
            rule_id="X-EXPR-001",
            layer=ValidationLayer.TIER_COMPLIANCE,
            severity=Severity.ERROR,
            message=f"Certificate validity ({months} months) exceeds Tier {tier} maximum ({max_m} months)",
            path="expires",
            reference="MCC-STD-001 §4",
            fix=f"Set expires to within {max_m} months of issued date.",
        )
    return None


def _check_hash_algorithm(cert: dict) -> Finding | None:
    algo = _get_nested(cert, "identity.weightHash.algorithm", "")
    approved = {"SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-512"}
    if algo and algo not in approved:
        return Finding(
            rule_id="X-HASH-001",
            layer=ValidationLayer.TIER_COMPLIANCE,
            severity=Severity.ERROR,
            message=f"weightHash algorithm '{algo}' is not approved (minimum SHA-256)",
            path="identity.weightHash.algorithm",
            reference="MCC-STD-001",
            fix=f"Use one of: {', '.join(sorted(approved))}",
        )
    return None


def _check_signature_algorithm(cert: dict) -> Finding | None:
    algo = _get_nested(cert, "signature.algorithm", "")
    approved = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}
    if algo and algo not in approved:
        return Finding(
            rule_id="X-SIGN-001",
            layer=ValidationLayer.TIER_COMPLIANCE,
            severity=Severity.ERROR,
            message=f"Signature algorithm '{algo}' does not meet minimum strength",
            path="signature.algorithm",
            reference="MCC-STD-001",
            fix=f"Use one of: {', '.join(sorted(approved))}",
        )
    return None


def _check_composition_refs(cert: dict) -> Finding | None:
    """Check that composition certificateRef values are valid UUIDs."""
    import re

    components = _get_nested(cert, "composition.components", [])
    if not isinstance(components, list):
        return None

    uuid_pattern = re.compile(
        r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    )

    for i, comp in enumerate(components):
        ref = comp.get("certificateRef")
        if ref and not uuid_pattern.match(ref):
            return Finding(
                rule_id="X-COMP-001",
                layer=ValidationLayer.TIER_COMPLIANCE,
                severity=Severity.ERROR,
                message=f"Component '{comp.get('componentName', f'[{i}]')}' has invalid certificateRef UUID",
                path=f"composition.components[{i}].certificateRef",
                reference="MCC-STD-001",
                fix="Use a valid UUID v4 format.",
            )
    return None


def _check_performance_floor(cert: dict) -> Finding | None:
    """Check that performanceFloor values don't exceed primary metric values."""
    floor_metrics = _get_nested(cert, "approvedChangeEnvelope.globalConstraints.performanceFloor", [])
    primary_metrics = _get_nested(cert, "evaluation.primaryMetrics", [])

    if not isinstance(floor_metrics, list) or not isinstance(primary_metrics, list):
        return None

    primary_map = {m["metricName"]: m["value"] for m in primary_metrics if "metricName" in m and "value" in m}

    for fm in floor_metrics:
        name = fm.get("metricName", "")
        floor_val = fm.get("value")
        if name in primary_map and floor_val is not None:
            if floor_val > primary_map[name]:
                return Finding(
                    rule_id="X-ENVE-001",
                    layer=ValidationLayer.TIER_COMPLIANCE,
                    severity=Severity.ERROR,
                    message=f"performanceFloor for '{name}' ({floor_val}) exceeds actual metric value ({primary_map[name]})",
                    path=f"approvedChangeEnvelope.globalConstraints.performanceFloor",
                    reference="MCC-STD-001",
                    fix="performanceFloor must be ≤ actual primary metric values.",
                )
    return None


def _check_excluded_populations_consistency(cert: dict) -> Finding | None:
    """Check that excludedPopulations and approvedPopulations.exclusions are both present when either is."""
    excluded = cert.get("usageEnvelope", {}).get("excludedPopulations", [])
    approved_exclusions = cert.get("usageEnvelope", {}).get("approvedPopulations", {}).get("exclusions", [])

    # Only flag if one field is populated and the other is completely empty
    if excluded and not approved_exclusions:
        return Finding(
            rule_id="X-POPU-001",
            layer=ValidationLayer.TIER_COMPLIANCE,
            severity=Severity.WARNING,
            message="excludedPopulations is specified but approvedPopulations.exclusions is empty",
            path="usageEnvelope.approvedPopulations.exclusions",
            reference="MCC-STD-001",
            fix="Add exclusions to approvedPopulations to match excludedPopulations.",
        )
    if approved_exclusions and not excluded:
        return Finding(
            rule_id="X-POPU-001",
            layer=ValidationLayer.TIER_COMPLIANCE,
            severity=Severity.WARNING,
            message="approvedPopulations.exclusions is specified but excludedPopulations is empty",
            path="usageEnvelope.excludedPopulations",
            reference="MCC-STD-001",
            fix="Add excludedPopulations to match approvedPopulations.exclusions.",
        )
    return None


# --------------------------------------------------------------------------
# Rule registry
# --------------------------------------------------------------------------

ALL_RULES: list[ComplianceRule] = [
    # Tier 2+
    ComplianceRule("T2-ARCH-001", 2, "architecture", "layerCount present and > 0", Severity.ERROR, _check_layer_count, "§5.3.2"),
    ComplianceRule("T2-ARCH-002", 2, "architecture", "attentionMechanism for transformers", Severity.ERROR, _check_attention_mechanism, "§5.3.2"),
    ComplianceRule("T2-DATA-001", 2, "trainingData", "At least one named dataset", Severity.ERROR, _check_datasets_present, "§5.4.2"),
    ComplianceRule("T2-DATA-002", 2, "trainingData", "demographicDistribution for patient data", Severity.ERROR, _check_demographic_distribution, "§5.4.2"),
    ComplianceRule("T2-EVAL-001", 2, "evaluation", "demographicStratification ≥3 axes", Severity.ERROR, _check_demographic_stratification, "§5.5"),
    ComplianceRule("T2-EVAL-002", 2, "evaluation", "adversarialAssessment present", Severity.ERROR, _check_adversarial_assessment, "§5.5"),
    ComplianceRule("X-METR-001", 2, "evaluation", "confidenceInterval on metrics", Severity.ERROR, _check_confidence_intervals, "§5.5"),

    # Tier 3+
    ComplianceRule("T3-DATA-001", 3, "trainingData", "dataController for clinical datasets", Severity.ERROR, _check_data_controller, "§5.4.3"),
    ComplianceRule("T3-DATA-002", 3, "trainingData", "dataSharingAgreement for clinical datasets", Severity.ERROR, _check_data_sharing_agreement, "§5.4.3"),
    ComplianceRule("T3-DATA-003", 3, "trainingData", "dataProcessingPipeline present", Severity.ERROR, _check_data_processing_pipeline, "§5.4.3"),
    ComplianceRule("T3-DATA-004", 3, "trainingData", "knownBiases non-empty", Severity.ERROR, _check_known_biases, "§5.4.3"),
    ComplianceRule("T3-EVAL-001", 3, "evaluation", "independentEvaluation present", Severity.ERROR, _check_independent_evaluation, "§5.5"),
    ComplianceRule("T3-EVAL-002", 3, "evaluation", "confidenceCalibration present", Severity.ERROR, _check_confidence_calibration, "§5.5"),
    ComplianceRule("T3-RUNT-001", 3, "runtime", "driftDetection with thresholds", Severity.ERROR, _check_drift_detection, "§5.7"),

    # Tier 4
    ComplianceRule("T4-EVAL-001", 4, "evaluation", "clinicalEvidence with trial registration", Severity.ERROR, _check_clinical_evidence, "§5.5"),
    ComplianceRule("T4-EVAL-002", 4, "evaluation", "realWorldEvidence present", Severity.WARNING, _check_real_world_evidence, "§5.5"),
    ComplianceRule("T4-DATA-001", 4, "trainingData", "ethicsApproval for clinical datasets", Severity.ERROR, _check_ethics_approval, "§5.4.4"),

    # Cross-domain (all tiers)
    ComplianceRule("X-EXPR-001", 1, "lifecycle", "Expiry within tier maximum", Severity.ERROR, _check_expiry_duration, "§4"),
    ComplianceRule("X-HASH-001", 1, "identity", "Approved hash algorithm", Severity.ERROR, _check_hash_algorithm, ""),
    ComplianceRule("X-SIGN-001", 1, "signature", "Minimum signature strength", Severity.ERROR, _check_signature_algorithm, ""),
    ComplianceRule("X-COMP-001", 1, "composition", "Valid certificateRef UUIDs", Severity.ERROR, _check_composition_refs, ""),
    ComplianceRule("X-ENVE-001", 1, "changeEnvelope", "performanceFloor ≤ metrics", Severity.ERROR, _check_performance_floor, ""),
    ComplianceRule("X-POPU-001", 2, "usageEnvelope", "Population exclusion consistency", Severity.WARNING, _check_excluded_populations_consistency, ""),
]


def check_tier_compliance(certificate: dict) -> LayerResult:
    """Run all tier-aware compliance rules against a certificate.

    Only runs rules whose minimum tier ≤ the certificate's declared riskTier.
    """
    result = LayerResult(layer=ValidationLayer.TIER_COMPLIANCE)
    tier = certificate.get("riskTier", 1)

    applicable_rules = [r for r in ALL_RULES if r.tier <= tier]

    for rule in applicable_rules:
        finding = rule.check(certificate)
        if finding is not None:
            result.findings.append(finding)
        else:
            result.checks_passed += 1

    return result
