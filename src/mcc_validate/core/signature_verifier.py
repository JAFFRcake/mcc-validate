"""Layer 3b: JWS digital signature verification.

Verifies the certificate's JWS signature using the declared algorithm
and certificate chain. Requires the `cryptography` optional dependency.

Phase 2 scope:
- Validate signature algorithm is approved
- Validate certificate chain is present and structurally valid
- Verify signature value (when public key is provided)
"""

from __future__ import annotations

from mcc_validate.models import Finding, LayerResult, Severity, ValidationLayer

_APPROVED_ALGORITHMS = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}

_ALGO_KEY_TYPES = {
    "RS256": "RSA", "RS384": "RSA", "RS512": "RSA",
    "ES256": "EC", "ES384": "EC", "ES512": "EC",
}

_ALGO_HASH_NAMES = {
    "RS256": "SHA-256", "RS384": "SHA-384", "RS512": "SHA-512",
    "ES256": "SHA-256", "ES384": "SHA-384", "ES512": "SHA-512",
}


def verify_signature(
    certificate: dict,
    public_key_path: str | None = None,
) -> LayerResult:
    """Verify the certificate's digital signature.

    Without a public key, performs structural validation only.
    With a public key, performs full cryptographic verification.
    """
    result = LayerResult(layer=ValidationLayer.CRYPTOGRAPHIC)

    sig = certificate.get("signature", {})
    if not sig:
        result.findings.append(Finding(
            rule_id="SIG-001",
            layer=ValidationLayer.CRYPTOGRAPHIC,
            severity=Severity.ERROR,
            message="Certificate has no signature block",
            path="signature",
            fix="Add a signature object with algorithm, keyId, signatureValue, and signedAt.",
        ))
        return result

    # Check algorithm
    algo = sig.get("algorithm", "")
    if algo not in _APPROVED_ALGORITHMS:
        result.findings.append(Finding(
            rule_id="SIG-002",
            layer=ValidationLayer.CRYPTOGRAPHIC,
            severity=Severity.ERROR,
            message=f"Signature algorithm '{algo}' is not approved",
            path="signature.algorithm",
            fix=f"Use one of: {', '.join(sorted(_APPROVED_ALGORITHMS))}",
        ))
    else:
        result.checks_passed += 1

    # Check keyId present
    if not sig.get("keyId"):
        result.findings.append(Finding(
            rule_id="SIG-003",
            layer=ValidationLayer.CRYPTOGRAPHIC,
            severity=Severity.ERROR,
            message="Signature missing keyId",
            path="signature.keyId",
            fix="Add keyId identifying the Certificate Authority's signing key.",
        ))
    else:
        result.checks_passed += 1

    # Check signatureValue present and non-empty
    sig_value = sig.get("signatureValue", "")
    if not sig_value:
        result.findings.append(Finding(
            rule_id="SIG-004",
            layer=ValidationLayer.CRYPTOGRAPHIC,
            severity=Severity.ERROR,
            message="Signature missing signatureValue",
            path="signature.signatureValue",
        ))
    else:
        result.checks_passed += 1

    # Check signedAt present and valid
    signed_at = sig.get("signedAt", "")
    if not signed_at:
        result.findings.append(Finding(
            rule_id="SIG-005",
            layer=ValidationLayer.CRYPTOGRAPHIC,
            severity=Severity.ERROR,
            message="Signature missing signedAt timestamp",
            path="signature.signedAt",
        ))
    else:
        from datetime import datetime

        try:
            datetime.fromisoformat(signed_at.replace("Z", "+00:00"))
            result.checks_passed += 1
        except ValueError:
            result.findings.append(Finding(
                rule_id="SIG-005",
                layer=ValidationLayer.CRYPTOGRAPHIC,
                severity=Severity.ERROR,
                message=f"signedAt '{signed_at}' is not a valid ISO 8601 datetime",
                path="signature.signedAt",
            ))

    # Check certificate chain
    cert_chain = sig.get("certificateChain", [])
    if cert_chain:
        if not isinstance(cert_chain, list) or len(cert_chain) == 0:
            result.findings.append(Finding(
                rule_id="SIG-006",
                layer=ValidationLayer.CRYPTOGRAPHIC,
                severity=Severity.WARNING,
                message="certificateChain is present but empty",
                path="signature.certificateChain",
            ))
        else:
            # Validate each cert in chain is non-empty string (basic structural check)
            for i, cert_pem in enumerate(cert_chain):
                if not isinstance(cert_pem, str) or len(cert_pem.strip()) == 0:
                    result.findings.append(Finding(
                        rule_id="SIG-006",
                        layer=ValidationLayer.CRYPTOGRAPHIC,
                        severity=Severity.ERROR,
                        message=f"certificateChain[{i}] is empty or not a string",
                        path=f"signature.certificateChain[{i}]",
                    ))
                    break
            else:
                result.checks_passed += 1  # Chain structurally OK
    else:
        result.findings.append(Finding(
            rule_id="SIG-006",
            layer=ValidationLayer.CRYPTOGRAPHIC,
            severity=Severity.WARNING,
            message="No certificateChain provided; signature cannot be fully verified",
            path="signature.certificateChain",
            fix="Add X.509 certificate chain for the signing key.",
        ))

    # Cryptographic verification (requires cryptography package and a public key)
    if public_key_path:
        _verify_with_key(certificate, sig, public_key_path, result)
    else:
        result.findings.append(Finding(
            rule_id="SIG-007",
            layer=ValidationLayer.CRYPTOGRAPHIC,
            severity=Severity.WARNING,
            message="Signature not cryptographically verified (no public key provided)",
            path="signature",
            fix="Use --verify-signature with a PEM public key to verify.",
        ))

    return result


def _verify_with_key(
    certificate: dict,
    sig: dict,
    public_key_path: str,
    result: LayerResult,
) -> None:
    """Perform actual cryptographic signature verification."""
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, padding, utils
    except ImportError:
        result.findings.append(Finding(
            rule_id="SIG-008",
            layer=ValidationLayer.CRYPTOGRAPHIC,
            severity=Severity.WARNING,
            message="cryptography package not installed; cannot verify signature. Install with: pip install mcc-validate[crypto]",
            path="signature",
        ))
        return

    import base64
    import json
    from pathlib import Path

    # Load public key
    key_path = Path(public_key_path)
    if not key_path.exists():
        result.findings.append(Finding(
            rule_id="SIG-008",
            layer=ValidationLayer.CRYPTOGRAPHIC,
            severity=Severity.ERROR,
            message=f"Public key file not found: {public_key_path}",
            path="signature",
        ))
        return

    try:
        key_data = key_path.read_bytes()
        public_key = serialization.load_pem_public_key(key_data)
    except Exception as e:
        result.findings.append(Finding(
            rule_id="SIG-008",
            layer=ValidationLayer.CRYPTOGRAPHIC,
            severity=Severity.ERROR,
            message=f"Failed to load public key: {e}",
            path="signature",
        ))
        return

    result.checks_passed += 1  # Key loaded successfully

    algo = sig.get("algorithm", "")
    sig_value_b64 = sig.get("signatureValue", "")

    # Decode signature value (base64url)
    try:
        # Pad base64url if necessary
        padded = sig_value_b64 + "=" * (4 - len(sig_value_b64) % 4)
        signature_bytes = base64.urlsafe_b64decode(padded)
    except Exception as e:
        result.findings.append(Finding(
            rule_id="SIG-009",
            layer=ValidationLayer.CRYPTOGRAPHIC,
            severity=Severity.ERROR,
            message=f"Failed to decode signatureValue: {e}",
            path="signature.signatureValue",
        ))
        return

    # Construct the signed payload (certificate without the signature block)
    cert_for_signing = {k: v for k, v in certificate.items() if k != "signature"}
    payload = json.dumps(cert_for_signing, sort_keys=True, separators=(",", ":")).encode("utf-8")

    # Select hash algorithm
    hash_algos = {
        "SHA-256": hashes.SHA256(),
        "SHA-384": hashes.SHA384(),
        "SHA-512": hashes.SHA512(),
    }
    hash_name = _ALGO_HASH_NAMES.get(algo, "SHA-256")
    hash_algo = hash_algos.get(hash_name, hashes.SHA256())

    # Verify based on key type
    try:
        key_type = _ALGO_KEY_TYPES.get(algo, "")
        if key_type == "EC" and isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature_bytes, payload, ec.ECDSA(hash_algo))
        elif key_type == "RSA":
            from cryptography.hazmat.primitives.asymmetric import rsa as rsa_mod

            if hasattr(public_key, "verify"):
                public_key.verify(signature_bytes, payload, padding.PKCS1v15(), hash_algo)
            else:
                result.findings.append(Finding(
                    rule_id="SIG-010",
                    layer=ValidationLayer.CRYPTOGRAPHIC,
                    severity=Severity.ERROR,
                    message=f"Key type mismatch: algorithm is {algo} but key is not RSA",
                    path="signature",
                ))
                return
        else:
            result.findings.append(Finding(
                rule_id="SIG-010",
                layer=ValidationLayer.CRYPTOGRAPHIC,
                severity=Severity.ERROR,
                message=f"Key type mismatch: algorithm is {algo} ({key_type}) but key type is {type(public_key).__name__}",
                path="signature",
            ))
            return

        result.checks_passed += 1  # Signature verified!

    except Exception as e:
        result.findings.append(Finding(
            rule_id="SIG-010",
            layer=ValidationLayer.CRYPTOGRAPHIC,
            severity=Severity.ERROR,
            message=f"Signature verification FAILED: {e}",
            path="signature.signatureValue",
            reference="MCC-STD-001",
            fix="The signature does not match the certificate content. The certificate may have been tampered with.",
        ))
