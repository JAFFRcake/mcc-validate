"""Tests for the CLI entry point."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from mcc_validate.cli import main


FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestCLICheck:
    """Test the 'check' command."""

    def test_valid_tier1_exits_0(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["check", str(FIXTURES_DIR / "valid_tier1.json")])
        assert result.exit_code == 0
        assert "VALID" in result.output

    def test_valid_tier3_passes_validation(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["check", str(FIXTURES_DIR / "valid_tier3.json")])
        # Exit code 0 (clean) or 2 (warnings only, e.g. issued date in future)
        assert result.exit_code in (0, 2)
        assert "VALID" in result.output
        assert "INVALID" not in result.output

    def test_invalid_missing_fields_exits_1(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["check", str(FIXTURES_DIR / "invalid_missing_fields.json")])
        assert result.exit_code == 1
        assert "INVALID" in result.output

    def test_invalid_tier_mismatch_exits_1(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["check", str(FIXTURES_DIR / "invalid_tier_mismatch.json")])
        assert result.exit_code == 1

    def test_json_output_format(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, [
            "check", str(FIXTURES_DIR / "valid_tier1.json"),
            "--format", "json",
        ])
        assert result.exit_code == 0
        import json
        report = json.loads(result.output)
        assert report["result"]["valid"] is True
        assert report["result"]["exitCode"] == 0

    def test_nonexistent_file_exits_2(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["check", "nonexistent.json"])
        assert result.exit_code == 2  # Click's file-not-found

    def test_verbose_flag(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["-v", "check", str(FIXTURES_DIR / "valid_tier1.json")])
        assert result.exit_code == 0

    def test_version_flag(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert "0.1.0" in result.output


class TestCLIInit:
    """Test the 'init' scaffold command."""

    def test_init_tier1(self, tmp_path: Path) -> None:
        runner = CliRunner()
        output_file = tmp_path / "cert.json"
        result = runner.invoke(main, ["init", "--tier", "1", "--output", str(output_file)])
        assert result.exit_code == 0
        assert output_file.exists()

        import json
        cert = json.loads(output_file.read_text(encoding="utf-8"))
        assert cert["riskTier"] == 1
        assert cert["@type"] == "ModelContextCertificate"

    def test_init_tier3(self, tmp_path: Path) -> None:
        runner = CliRunner()
        output_file = tmp_path / "cert3.json"
        result = runner.invoke(main, ["init", "--tier", "3", "--output", str(output_file)])
        assert result.exit_code == 0

        import json
        cert = json.loads(output_file.read_text(encoding="utf-8"))
        assert cert["riskTier"] == 3
        assert "dataProcessingPipeline" in cert["trainingData"]
        assert "knownBiases" in cert["trainingData"]
        assert "independentEvaluation" in cert["evaluation"]
        assert "driftDetection" in cert["runtime"]

    def test_init_tier4(self, tmp_path: Path) -> None:
        runner = CliRunner()
        output_file = tmp_path / "cert4.json"
        result = runner.invoke(main, ["init", "--tier", "4", "--output", str(output_file)])
        assert result.exit_code == 0

        import json
        cert = json.loads(output_file.read_text(encoding="utf-8"))
        assert cert["riskTier"] == 4
        assert "clinicalEvidence" in cert["evaluation"]

    def test_init_stdout(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["init", "--tier", "2"])
        assert result.exit_code == 0
        import json
        cert = json.loads(result.output)
        assert cert["riskTier"] == 2


class TestCLIStatus:
    """Test the 'status' command."""

    def test_active_certificate(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["status", str(FIXTURES_DIR / "valid_tier3.json")])
        assert "ThoraxTriage-v3" in result.output
        assert "active" in result.output
