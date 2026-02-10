"""Configuration system — loads .mcc-validate.yaml for rule overrides and settings.

Searches for configuration in this order:
1. Explicit --config path
2. .mcc-validate.yaml in the current working directory
3. .mcc-validate.yml in the current working directory

Configuration is optional; the validator works without it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class RuleOverride:
    """Override for a specific rule's severity."""

    rule_id: str
    severity: str  # "error", "warning", "info", "ignore"
    justification: str = ""


@dataclass
class Config:
    """Parsed configuration."""

    schema_version: str = "v1"
    default_format: str = "console"
    strict: bool = False
    rule_overrides: dict[str, RuleOverride] = field(default_factory=dict)
    crypto_minimum_hash: str = "SHA-256"
    crypto_minimum_signature: str = "ES256"
    ci_fail_on_warnings: bool = False
    ci_sarif_output: str = ""

    @staticmethod
    def default() -> Config:
        """Return a default (empty) configuration."""
        return Config()


def load_config(config_path: str | Path | None = None) -> Config:
    """Load configuration from a YAML file.

    Parameters
    ----------
    config_path:
        Explicit path to a config file. If None, searches the current
        working directory for .mcc-validate.yaml / .yml.

    Returns
    -------
    Config instance. Returns default config if no file is found.
    """
    path = _resolve_path(config_path)
    if path is None:
        return Config.default()

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:
        return Config.default()

    if not isinstance(raw, dict):
        return Config.default()

    return _parse_config(raw)


def _resolve_path(config_path: str | Path | None) -> Path | None:
    """Resolve the config file path."""
    if config_path is not None:
        p = Path(config_path)
        return p if p.is_file() else None

    cwd = Path.cwd()
    for name in (".mcc-validate.yaml", ".mcc-validate.yml"):
        candidate = cwd / name
        if candidate.is_file():
            return candidate

    return None


def _parse_config(raw: dict[str, Any]) -> Config:
    """Parse a raw YAML dict into a Config object."""
    cfg = Config(
        schema_version=raw.get("schema_version", "v1"),
        default_format=raw.get("default_format", "console"),
        strict=bool(raw.get("strict", False)),
    )

    # Rule overrides
    rules = raw.get("rules", {})
    if isinstance(rules, dict):
        for rule_id, override in rules.items():
            if rule_id == "custom":
                continue  # Custom rules handled separately
            if isinstance(override, dict):
                cfg.rule_overrides[rule_id] = RuleOverride(
                    rule_id=rule_id,
                    severity=override.get("severity", "error"),
                    justification=override.get("justification", ""),
                )

    # Crypto settings
    crypto = raw.get("crypto", {})
    if isinstance(crypto, dict):
        cfg.crypto_minimum_hash = crypto.get("minimum_hash", "SHA-256")
        cfg.crypto_minimum_signature = crypto.get("minimum_signature", "ES256")

    # CI settings
    ci = raw.get("ci", {})
    if isinstance(ci, dict):
        cfg.ci_fail_on_warnings = bool(ci.get("fail_on_warnings", False))
        cfg.ci_sarif_output = ci.get("sarif_output", "")

    return cfg


def apply_overrides(config: Config, findings: list) -> list:
    """Apply rule severity overrides from config to a list of findings.

    Parameters
    ----------
    config:
        The loaded configuration.
    findings:
        List of Finding objects to filter/modify.

    Returns
    -------
    Modified list of findings with overridden severities.
    Findings with severity="ignore" are removed entirely.
    """
    from mcc_validate.models import Severity

    severity_map = {
        "error": Severity.ERROR,
        "warning": Severity.WARNING,
        "info": Severity.INFO,
    }

    result = []
    for finding in findings:
        override = config.rule_overrides.get(finding.rule_id)
        if override is not None:
            if override.severity == "ignore":
                continue
            new_sev = severity_map.get(override.severity)
            if new_sev is not None:
                finding.severity = new_sev
        result.append(finding)

    return result
