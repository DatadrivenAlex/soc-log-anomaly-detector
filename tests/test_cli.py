"""Typer commands."""

from typer.testing import CliRunner

from socdetect.cli import app

runner = CliRunner()


def test_help_and_version() -> None:
    help_result = runner.invoke(app, ["--help"])
    assert help_result.exit_code == 0
    assert "generate" in help_result.stdout
    assert "analyze" in help_result.stdout
    version = runner.invoke(app, ["version"])
    assert version.exit_code == 0
    assert version.stdout.strip()


def test_generate_then_analyze(tmp_path) -> None:
    logs = tmp_path / "logs"
    reports = tmp_path / "reports"
    generated = runner.invoke(app, ["generate", "--out", str(logs), "--seed", "42"])
    assert generated.exit_code == 0
    assert (logs / "auth.log").exists()
    analyzed = runner.invoke(
        app,
        ["analyze", str(logs), "--out", str(reports), "--seed", "42", "--no-anomaly"],
    )
    assert analyzed.exit_code == 0, analyzed.stdout + analyzed.stderr
    assert "Highest severity: critical" in analyzed.stdout
    assert (reports / "alerts.json").exists()
    assert (reports / "alerts.csv").exists()
    assert (reports / "incident-report.md").exists()


def test_missing_input_exits_with_code_2(tmp_path) -> None:
    result = runner.invoke(app, ["analyze", str(tmp_path / "missing")])
    assert result.exit_code == 2
