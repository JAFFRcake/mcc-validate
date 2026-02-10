"""Tests for Layer 3a: Hash verification."""

from __future__ import annotations

import hashlib
from pathlib import Path

from mcc_validate.core.hash_verifier import verify_weight_hash
from mcc_validate.models import Severity, ValidationLayer


class TestHashVerifier:
    """Test weight file hash verification."""

    def test_matching_hash(self, tmp_path: Path) -> None:
        """Hash of a known file should match the declared value."""
        weight_file = tmp_path / "model.bin"
        content = b"fake model weights for testing"
        weight_file.write_bytes(content)

        expected_hash = hashlib.sha256(content).hexdigest()

        cert = {
            "identity": {
                "weightHash": {
                    "algorithm": "SHA-256",
                    "value": expected_hash,
                    "serialisationMethod": "generic",
                }
            }
        }

        result = verify_weight_hash(cert, weight_file)
        assert result.layer == ValidationLayer.CRYPTOGRAPHIC
        assert not result.has_errors
        assert result.checks_passed >= 3  # file exists + hash computed + hash matches

    def test_mismatched_hash(self, tmp_path: Path) -> None:
        """Wrong hash should produce an error."""
        weight_file = tmp_path / "model.bin"
        weight_file.write_bytes(b"actual content")

        cert = {
            "identity": {
                "weightHash": {
                    "algorithm": "SHA-256",
                    "value": "0000000000000000000000000000000000000000000000000000000000000000",
                    "serialisationMethod": "generic",
                }
            }
        }

        result = verify_weight_hash(cert, weight_file)
        assert result.has_errors
        rule_ids = [f.rule_id for f in result.findings]
        assert "HASH-005" in rule_ids

    def test_missing_file(self, tmp_path: Path) -> None:
        """Non-existent weight file should produce an error."""
        cert = {
            "identity": {
                "weightHash": {
                    "algorithm": "SHA-256",
                    "value": "abc123",
                    "serialisationMethod": "generic",
                }
            }
        }

        result = verify_weight_hash(cert, tmp_path / "nonexistent.bin")
        assert result.has_errors
        rule_ids = [f.rule_id for f in result.findings]
        assert "HASH-003" in rule_ids

    def test_unsupported_algorithm(self, tmp_path: Path) -> None:
        """Unsupported algorithm should produce an error."""
        weight_file = tmp_path / "model.bin"
        weight_file.write_bytes(b"content")

        cert = {
            "identity": {
                "weightHash": {
                    "algorithm": "MD5",
                    "value": "abc",
                    "serialisationMethod": "generic",
                }
            }
        }

        result = verify_weight_hash(cert, weight_file)
        assert result.has_errors
        rule_ids = [f.rule_id for f in result.findings]
        assert "HASH-001" in rule_ids

    def test_sha512_algorithm(self, tmp_path: Path) -> None:
        """SHA-512 should work."""
        weight_file = tmp_path / "model.bin"
        content = b"test content"
        weight_file.write_bytes(content)

        expected_hash = hashlib.sha512(content).hexdigest()

        cert = {
            "identity": {
                "weightHash": {
                    "algorithm": "SHA-512",
                    "value": expected_hash,
                    "serialisationMethod": "generic",
                }
            }
        }

        result = verify_weight_hash(cert, weight_file)
        assert not result.has_errors

    def test_safetensors_header_check(self, tmp_path: Path) -> None:
        """Files declared as safetensors get a header validation."""
        weight_file = tmp_path / "model.safetensors"
        # Write a valid-looking safetensors file (8-byte LE header size + some content)
        header_size = (42).to_bytes(8, byteorder="little")
        content = header_size + b"{}" + b"\x00" * 40 + b"weights"
        weight_file.write_bytes(content)

        expected_hash = hashlib.sha256(content).hexdigest()

        cert = {
            "identity": {
                "weightHash": {
                    "algorithm": "SHA-256",
                    "value": expected_hash,
                    "serialisationMethod": "safetensors-canonical",
                }
            }
        }

        result = verify_weight_hash(cert, weight_file)
        assert not result.has_errors

    def test_case_insensitive_hash_comparison(self, tmp_path: Path) -> None:
        """Hash comparison should be case-insensitive."""
        weight_file = tmp_path / "model.bin"
        content = b"test"
        weight_file.write_bytes(content)

        expected_hash = hashlib.sha256(content).hexdigest().upper()

        cert = {
            "identity": {
                "weightHash": {
                    "algorithm": "SHA-256",
                    "value": expected_hash,
                    "serialisationMethod": "generic",
                }
            }
        }

        result = verify_weight_hash(cert, weight_file)
        assert not result.has_errors
