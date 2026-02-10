"""Tests for the configuration system."""

from __future__ import annotations

import json
from pathlib import Path

from mcc_validate.config import Config, RuleOverride, apply_overrides, load_config
from mcc_validate.models import Finding, Severity, ValidationLayer


class TestConfigLoading:
    """Test config file loading and parsing."""

    def test_default_config_when_no_file(self) -> None:
        cfg = load_config(None)
        assert cfg.schema_version == "v1"
        assert cfg.default_format == "console"
        assert cfg.strict is False
        assert len(cfg.rule_overrides) == 0

    def test_load_from_explicit_path(self, tmp_path: Path) -> None:
        config_file = tmp_path / ".mcc-validate.yaml"
        config_file.write_text(
            "schema_version: v1\n"
            "default_format: json\n"
            "strict: true\n"
            "rules:\n"
            "  T2-EVAL-002:\n"
            "    severity: warning\n"
            '    justification: "Deferred to Phase 2"\n',
            encoding="utf-8",
        )
        cfg = load_config(str(config_file))
        assert cfg.default_format == "json"
        assert cfg.strict is True
        assert "T2-EVAL-002" in cfg.rule_overrides
        assert cfg.rule_overrides["T2-EVAL-002"].severity == "warning"
        assert "Deferred" in cfg.rule_overrides["T2-EVAL-002"].justification

    def test_nonexistent_path_returns_default(self) -> None:
        cfg = load_config("/nonexistent/path/config.yaml")
        assert cfg.schema_version == "v1"

    def test_malformed_yaml_returns_default(self, tmp_path: Path) -> None:
        config_file = tmp_path / ".mcc-validate.yaml"
        config_file.write_text("{{{{ invalid yaml", encoding="utf-8")
        cfg = load_config(str(config_file))
        assert cfg.schema_version == "v1"

    def test_crypto_settings(self, tmp_path: Path) -> None:
        config_file = tmp_path / ".mcc-validate.yaml"
        config_file.write_text(
            "crypto:\n"
            "  minimum_hash: SHA-384\n"
            "  minimum_signature: ES384\n",
            encoding="utf-8",
        )
        cfg = load_config(str(config_file))
        assert cfg.crypto_minimum_hash == "SHA-384"
        assert cfg.crypto_minimum_signature == "ES384"

    def test_ci_settings(self, tmp_path: Path) -> None:
        config_file = tmp_path / ".mcc-validate.yaml"
        config_file.write_text(
            "ci:\n"
            "  fail_on_warnings: true\n"
            "  sarif_output: reports/scan.sarif\n",
            encoding="utf-8",
        )
        cfg = load_config(str(config_file))
        assert cfg.ci_fail_on_warnings is True
        assert cfg.ci_sarif_output == "reports/scan.sarif"

    def test_multiple_rule_overrides(self, tmp_path: Path) -> None:
        config_file = tmp_path / ".mcc-validate.yaml"
        config_file.write_text(
            "rules:\n"
            "  T2-EVAL-002:\n"
            "    severity: warning\n"
            "  T3-DATA-001:\n"
            "    severity: ignore\n"
            '    justification: "Not applicable"\n',
            encoding="utf-8",
        )
        cfg = load_config(str(config_file))
        assert len(cfg.rule_overrides) == 2
        assert cfg.rule_overrides["T3-DATA-001"].severity == "ignore"


class TestApplyOverrides:
    """Test applying config overrides to findings."""

    def test_override_severity(self) -> None:
        cfg = Config(rule_overrides={
            "T2-EVAL-002": RuleOverride(
                rule_id="T2-EVAL-002",
                severity="warning",
            ),
        })
        findings = [
            Finding(
                rule_id="T2-EVAL-002",
                layer=ValidationLayer.TIER_COMPLIANCE,
                severity=Severity.ERROR,
                message="Test",
            ),
        ]
        result = apply_overrides(cfg, findings)
        assert len(result) == 1
        assert result[0].severity == Severity.WARNING

    def test_ignore_removes_finding(self) -> None:
        cfg = Config(rule_overrides={
            "T3-DATA-001": RuleOverride(
                rule_id="T3-DATA-001",
                severity="ignore",
            ),
        })
        findings = [
            Finding(
                rule_id="T3-DATA-001",
                layer=ValidationLayer.TIER_COMPLIANCE,
                severity=Severity.ERROR,
                message="Test",
            ),
            Finding(
                rule_id="T3-DATA-002",
                layer=ValidationLayer.TIER_COMPLIANCE,
                severity=Severity.ERROR,
                message="Other",
            ),
        ]
        result = apply_overrides(cfg, findings)
        assert len(result) == 1
        assert result[0].rule_id == "T3-DATA-002"

    def test_no_overrides_preserves_all(self) -> None:
        cfg = Config()
        findings = [
            Finding(
                rule_id="TEST",
                layer=ValidationLayer.SCHEMA,
                severity=Severity.ERROR,
                message="Test",
            ),
        ]
        result = apply_overrides(cfg, findings)
        assert len(result) == 1
        assert result[0].severity == Severity.ERROR

    def test_default_config(self) -> None:
        cfg = Config.default()
        assert cfg.strict is False
        assert cfg.default_format == "console"
