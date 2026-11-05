"""Command line for generating logs, analyzing them, and serving the API."""

from __future__ import annotations

from pathlib import Path

import typer
import uvicorn

from socdetect import __version__
from socdetect.api import create_app
from socdetect.engine import load_rules
from socdetect.generate import write_logs
from socdetect.pipeline import analyze_paths
from socdetect.reporting import write_outputs

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="SOC Tier-1 log triage for SSH, web, and Windows events.",
)


@app.callback()
def main() -> None:
    """SOC Tier-1 log triage for SSH, web, and Windows events."""


@app.command()
def version() -> None:
    """Print the package version."""
    typer.echo(__version__)


@app.command()
def generate(
    out: Path = typer.Option(Path("data/sample"), "--out", "-o", help="Directory to write."),
    seed: int = typer.Option(42, "--seed", help="Seed for benign noise."),
) -> None:
    """Write seeded auth.log, access.log, windows.jsonl, and manifest.json."""
    files = write_logs(out, seed=seed)
    typer.echo(f"Wrote {len(files)} files to {out} (seed {seed})")


@app.command()
def analyze(
    inputs: list[Path] = typer.Argument(..., help="Log files or a directory from generate."),
    rules: Path | None = typer.Option(None, "--rules", help="Directory of YAML rules."),
    out: Path = typer.Option(Path("reports"), "--out", "-o", help="Report directory."),
    year: int = typer.Option(2026, "--year", help="Year assumed for syslog dates."),
    anomaly: bool = typer.Option(True, "--anomaly/--no-anomaly"),
    seed: int = typer.Option(42, "--seed", help="IsolationForest random_state."),
) -> None:
    """Parse logs, run detections, and write JSON, CSV, and Markdown."""
    missing = [str(path) for path in inputs if not path.exists()]
    if missing:
        typer.echo(f"Path not found: {', '.join(missing)}", err=True)
        raise typer.Exit(code=2)
    analysis = analyze_paths(
        inputs,
        rules_dir=rules,
        year=year,
        enable_anomaly=anomaly,
        seed=seed,
    )
    written = write_outputs(analysis, load_rules(rules), out)
    summary = analysis.summary()
    typer.echo(
        f"Events: {summary['events']}  Alerts: {summary['alerts']}  "
        f"Parse errors: {summary['parse_errors']}"
    )
    typer.echo(f"Highest severity: {summary['highest_severity'] or 'none'}")
    typer.echo(
        "Reports: "
        + ", ".join(str(path) for path in (written["json"], written["csv"], written["markdown"]))
    )


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8000, "--port"),
    rules: Path | None = typer.Option(None, "--rules"),
) -> None:
    """Serve the unauthenticated lab API. Bind it to localhost."""
    typer.echo(f"Listening on http://{host}:{port}")
    uvicorn.run(create_app(rules), host=host, port=port, log_level="info")
