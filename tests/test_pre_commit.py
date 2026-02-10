"""Tests for the pre-commit hook configuration."""

from __future__ import annotations

from pathlib import Path

import yaml


HOOKS_PATH = Path(__file__).parent.parent / ".pre-commit-hooks.yaml"


class TestPreCommitConfig:
    """Validate .pre-commit-hooks.yaml structure."""

    def test_hooks_yaml_is_valid(self) -> None:
        hooks = yaml.safe_load(HOOKS_PATH.read_text(encoding="utf-8"))
        assert isinstance(hooks, list)
        assert len(hooks) >= 1

    def test_hook_has_required_fields(self) -> None:
        hooks = yaml.safe_load(HOOKS_PATH.read_text(encoding="utf-8"))
        hook = hooks[0]
        assert hook["id"] == "mcc-validate"
        assert hook["language"] == "python"
        assert "entry" in hook
        assert "json" in hook["types"]

    def test_hook_entry_points_to_check(self) -> None:
        hooks = yaml.safe_load(HOOKS_PATH.read_text(encoding="utf-8"))
        hook = hooks[0]
        assert "mcc-validate" in hook["entry"]
        assert "check" in hook["entry"]
