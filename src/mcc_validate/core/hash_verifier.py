"""Layer 3a: Cryptographic hash verification of model weights.

Computes a hash of the model weight file using the declared algorithm
and compares it against the certificate's weightHash.value.

Supported serialisation formats:
- safetensors (read raw bytes)
- GGUF (read raw bytes)
- Generic (raw byte hashing for any format)
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from mcc_validate.models import Finding, LayerResult, Severity, ValidationLayer

# Map MCC algorithm names to hashlib names
_ALGORITHM_MAP = {
    "SHA-256": "sha256",
    "SHA-384": "sha384",
    "SHA-512": "sha512",
    "SHA3-256": "sha3_256",
    "SHA3-512": "sha3_512",
}

# Read in 8 MB chunks for large model files
_CHUNK_SIZE = 8 * 1024 * 1024


def _compute_file_hash(file_path: Path, algorithm: str) -> str:
    """Compute the hex digest of a file using the given algorithm."""
    hashlib_name = _ALGORITHM_MAP.get(algorithm)
    if hashlib_name is None:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")

    h = hashlib.new(hashlib_name)
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(_CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _validate_safetensors_header(file_path: Path) -> Finding | None:
    """Basic structural check for safetensors format."""
    try:
        with open(file_path, "rb") as f:
            header_size_bytes = f.read(8)
            if len(header_size_bytes) < 8:
                return Finding(
                    rule_id="HASH-002",
                    layer=ValidationLayer.CRYPTOGRAPHIC,
                    severity=Severity.WARNING,
                    message="Weight file too small to be valid safetensors format",
                    path="identity.weightHash",
                )
            header_size = int.from_bytes(header_size_bytes, byteorder="little")
            if header_size > 100_000_000:  # 100MB header is unreasonable
                return Finding(
                    rule_id="HASH-002",
                    layer=ValidationLayer.CRYPTOGRAPHIC,
                    severity=Severity.WARNING,
                    message=f"safetensors header size ({header_size} bytes) seems unreasonably large",
                    path="identity.weightHash",
                )
    except OSError as e:
        return Finding(
            rule_id="HASH-003",
            layer=ValidationLayer.CRYPTOGRAPHIC,
            severity=Severity.ERROR,
            message=f"Could not read weight file: {e}",
            path="identity.weightHash",
        )
    return None


def verify_weight_hash(
    certificate: dict,
    weights_path: str | Path,
) -> LayerResult:
    """Verify the model weight file hash against the certificate's declared hash.

    Returns a LayerResult with findings.
    """
    result = LayerResult(layer=ValidationLayer.CRYPTOGRAPHIC)
    weights_path = Path(weights_path)

    # Extract certificate hash info
    weight_hash = certificate.get("identity", {}).get("weightHash", {})
    declared_algo = weight_hash.get("algorithm", "")
    declared_value = weight_hash.get("value", "").lower()
    serialisation = weight_hash.get("serialisationMethod", "")

    # Validate algorithm is supported
    if declared_algo not in _ALGORITHM_MAP:
        result.findings.append(Finding(
            rule_id="HASH-001",
            layer=ValidationLayer.CRYPTOGRAPHIC,
            severity=Severity.ERROR,
            message=f"Unsupported hash algorithm in certificate: '{declared_algo}'",
            path="identity.weightHash.algorithm",
            fix=f"Use one of: {', '.join(sorted(_ALGORITHM_MAP.keys()))}",
        ))
        return result

    # Check file exists and is readable
    if not weights_path.exists():
        result.findings.append(Finding(
            rule_id="HASH-003",
            layer=ValidationLayer.CRYPTOGRAPHIC,
            severity=Severity.ERROR,
            message=f"Weight file not found: {weights_path}",
            path="identity.weightHash",
        ))
        return result

    if not weights_path.is_file():
        result.findings.append(Finding(
            rule_id="HASH-003",
            layer=ValidationLayer.CRYPTOGRAPHIC,
            severity=Severity.ERROR,
            message=f"Weight path is not a file: {weights_path}",
            path="identity.weightHash",
        ))
        return result

    result.checks_passed += 1  # File exists and is accessible

    # Optional format-specific validation
    if "safetensors" in serialisation.lower():
        format_finding = _validate_safetensors_header(weights_path)
        if format_finding:
            result.findings.append(format_finding)
        else:
            result.checks_passed += 1  # Format header OK

    # Compute actual hash
    try:
        actual_hash = _compute_file_hash(weights_path, declared_algo)
    except Exception as e:
        result.findings.append(Finding(
            rule_id="HASH-004",
            layer=ValidationLayer.CRYPTOGRAPHIC,
            severity=Severity.ERROR,
            message=f"Failed to compute hash of weight file: {e}",
            path="identity.weightHash",
        ))
        return result

    result.checks_passed += 1  # Hash computed successfully

    # Compare
    if actual_hash.lower() == declared_value:
        result.checks_passed += 1  # Hash matches
    else:
        result.findings.append(Finding(
            rule_id="HASH-005",
            layer=ValidationLayer.CRYPTOGRAPHIC,
            severity=Severity.ERROR,
            message=(
                f"Weight hash MISMATCH.\n"
                f"           Declared: {declared_value}\n"
                f"           Actual:   {actual_hash}"
            ),
            path="identity.weightHash.value",
            reference="MCC-STD-001 §5.1",
            fix="Recompute the weight hash or verify the correct model file is being checked.",
        ))

    return result
