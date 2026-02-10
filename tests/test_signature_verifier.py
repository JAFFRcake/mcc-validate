"""Tests for Layer 3b: Signature verification."""

from __future__ import annotations

from mcc_validate.core.signature_verifier import verify_signature
from mcc_validate.models import Severity, ValidationLayer


def _make_cert_with_sig(**overrides: object) -> dict:
    """Create a minimal certificate with a signature block."""
    sig = {
        "algorithm": "ES256",
        "keyId": "test-key-001",
        "signatureValue": "MEUCIQC7fakesignaturevalue",
        "signedAt": "2026-01-01T00:00:00Z",
        "certificateChain": ["MIIBxTCCAWug...base64cert..."],
    }
    sig.update(overrides)
    return {"signature": sig}


class TestSignatureVerifier:
    """Test structural signature validation."""

    def test_valid_signature_structure(self) -> None:
        cert = _make_cert_with_sig()
        result = verify_signature(cert)
        assert result.layer == ValidationLayer.CRYPTOGRAPHIC
        # Should pass all structural checks, only warning about no key
        assert not result.has_errors
        assert result.checks_passed >= 4  # algo + keyId + sigValue + signedAt + chain

    def test_missing_signature_block(self) -> None:
        result = verify_signature({})
        assert result.has_errors
        rule_ids = [f.rule_id for f in result.findings]
        assert "SIG-001" in rule_ids

    def test_invalid_algorithm(self) -> None:
        cert = _make_cert_with_sig(algorithm="HS256")
        result = verify_signature(cert)
        rule_ids = [f.rule_id for f in result.findings]
        assert "SIG-002" in rule_ids

    def test_missing_key_id(self) -> None:
        cert = _make_cert_with_sig(keyId="")
        result = verify_signature(cert)
        rule_ids = [f.rule_id for f in result.findings]
        assert "SIG-003" in rule_ids

    def test_missing_signature_value(self) -> None:
        cert = _make_cert_with_sig(signatureValue="")
        result = verify_signature(cert)
        rule_ids = [f.rule_id for f in result.findings]
        assert "SIG-004" in rule_ids

    def test_missing_signed_at(self) -> None:
        cert = _make_cert_with_sig(signedAt="")
        result = verify_signature(cert)
        rule_ids = [f.rule_id for f in result.findings]
        assert "SIG-005" in rule_ids

    def test_invalid_signed_at_format(self) -> None:
        cert = _make_cert_with_sig(signedAt="not-a-date")
        result = verify_signature(cert)
        rule_ids = [f.rule_id for f in result.findings]
        assert "SIG-005" in rule_ids

    def test_missing_certificate_chain_warning(self) -> None:
        cert = _make_cert_with_sig()
        del cert["signature"]["certificateChain"]
        result = verify_signature(cert)
        # Should warn, not error
        assert not result.has_errors
        warnings = [f for f in result.findings if f.severity == Severity.WARNING]
        sig_warnings = [f for f in warnings if f.rule_id == "SIG-006"]
        assert len(sig_warnings) == 1

    def test_no_public_key_warning(self) -> None:
        cert = _make_cert_with_sig()
        result = verify_signature(cert, public_key_path=None)
        warnings = [f for f in result.findings if f.severity == Severity.WARNING]
        sig_warnings = [f for f in warnings if f.rule_id == "SIG-007"]
        assert len(sig_warnings) == 1

    def test_all_approved_algorithms(self) -> None:
        for algo in ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]:
            cert = _make_cert_with_sig(algorithm=algo)
            result = verify_signature(cert)
            algo_errors = [f for f in result.findings if f.rule_id == "SIG-002"]
            assert len(algo_errors) == 0, f"{algo} should be approved"

    def test_nonexistent_public_key_file(self) -> None:
        cert = _make_cert_with_sig()
        result = verify_signature(cert, public_key_path="/nonexistent/key.pem")
        rule_ids = [f.rule_id for f in result.findings]
        assert "SIG-008" in rule_ids
