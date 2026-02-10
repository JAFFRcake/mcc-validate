"""Tests for the GitHub Action configuration."""

from __future__ import annotations

from pathlib import Path

import yaml


ACTION_PATH = Path(__file__).parent.parent / "github-action" / "action.yml"


class TestGitHubAction:
    """Validate github-action/action.yml structure."""

    def test_action_yaml_is_valid(self) -> None:
        action = yaml.safe_load(ACTION_PATH.read_text(encoding="utf-8"))
        assert isinstance(action, dict)
        assert action["name"] == "MCC Validate"

    def test_has_required_inputs(self) -> None:
        action = yaml.safe_load(ACTION_PATH.read_text(encoding="utf-8"))
        assert "inputs" in action
        assert "certificate" in action["inputs"]
        assert action["inputs"]["certificate"]["required"] is True

    def test_has_outputs(self) -> None:
        action = yaml.safe_load(ACTION_PATH.read_text(encoding="utf-8"))
        assert "outputs" in action
        assert "exit-code" in action["outputs"]
        assert "report-path" in action["outputs"]
        assert "valid" in action["outputs"]

    def test_uses_composite_runner(self) -> None:
        action = yaml.safe_load(ACTION_PATH.read_text(encoding="utf-8"))
        assert action["runs"]["using"] == "composite"

    def test_has_sarif_upload_step(self) -> None:
        action = yaml.safe_load(ACTION_PATH.read_text(encoding="utf-8"))
        steps = action["runs"]["steps"]
        sarif_steps = [s for s in steps if "upload-sarif" in s.get("uses", "")]
        assert len(sarif_steps) == 1
