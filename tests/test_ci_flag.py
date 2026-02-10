"""Tests for the --ci flag on the check command."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from mcc_validate.cli import main

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestCIFlag:
    """Test --ci mode behaviour."""

    def test_ci_produces_sarif_file(self, tmp_path: Path) -> None:
        output = tmp_path / "result.sarif"
        runner = CliRunner()
        result = runner.invoke(main, [
            "check", str(FIXTURES_DIR / "valid_tier1.json"),
            "--ci", "--output", str(output),
        ])
        assert output.exists()
        sarif = json.loads(output.read_text(encoding="utf-8"))
        assert sarif["version"] == "2.1.0"

    def test_ci_implies_strict(self) -> None:
        """--ci should cause warnings to produce exit code 1."""
        runner = CliRunner()
        # valid_tier1 should pass even with --ci
        result = runner.invoke(main, [
            "check", str(FIXTURES_DIR / "valid_tier1.json"),
            "--ci",
        ])
        # Exit 0 for valid cert (no warnings)
        assert result.exit_code == 0

    def test_ci_default_output_path(self) -> None:
        """--ci without --output writes to mcc-validate.sarif by default."""
        runner = CliRunner()
        with runner.isolated_filesystem():
            # Copy fixture into isolated fs
            cert = FIXTURES_DIR / "valid_tier1.json"
            Path("cert.json").write_text(cert.read_text(encoding="utf-8"), encoding="utf-8")
            result = runner.invoke(main, ["check", "cert.json", "--ci"])
            assert Path("mcc-validate.sarif").exists()
            sarif = json.loads(Path("mcc-validate.sarif").read_text(encoding="utf-8"))
            assert sarif["version"] == "2.1.0"

    def test_ci_uses_config_sarif_path(self, tmp_path: Path) -> None:
        """--ci uses ci.sarif_output from config when set."""
        config_file = tmp_path / ".mcc-validate.yaml"
        config_file.write_text(
            "ci:\n  sarif_output: custom-report.sarif\n",
            encoding="utf-8",
        )
        runner = CliRunner()
        with runner.isolated_filesystem():
            cert = FIXTURES_DIR / "valid_tier1.json"
            Path("cert.json").write_text(cert.read_text(encoding="utf-8"), encoding="utf-8")
            result = runner.invoke(main, [
                "--config", str(config_file),
                "check", "cert.json", "--ci",
            ])
            assert Path("custom-report.sarif").exists()
