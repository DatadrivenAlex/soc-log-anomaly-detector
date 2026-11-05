"""Small FastAPI surface for submitting raw log lines and receiving alerts."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from fastapi import FastAPI
from pydantic import BaseModel, Field

from socdetect import __version__
from socdetect.engine import load_rules
from socdetect.models import Event
from socdetect.parsers.dispatch import parse_content
from socdetect.pipeline import Analysis, analyze_events


class LogRecord(BaseModel):
    source: Literal["linux_auth", "web_access", "windows_json", "auto"] = "auto"
    content: str = Field(min_length=1)


class AnalyzeRequest(BaseModel):
    records: list[LogRecord]
    enable_anomaly: bool = True
    year: int = 2026
    seed: int = 42


def _analysis_body(analysis: Analysis) -> dict[str, object]:
    return {"summary": analysis.summary(), "alerts": [alert.to_dict() for alert in analysis.alerts]}


def create_app(rules_dir: Path | None = None) -> FastAPI:
    rules = load_rules(rules_dir)
    app = FastAPI(
        title="socdetect",
        version=__version__,
        summary="SOC Tier-1 log triage API",
        description=(
            "Submit raw sshd, combined access-log, or Windows JSON lines. "
            "The service has no authentication and is meant for localhost lab use."
        ),
    )

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.get("/v1/rules")
    def list_rules() -> dict[str, object]:
        return {"rules": [rule.summary() for rule in rules]}

    @app.post("/v1/analyze")
    def analyze(body: AnalyzeRequest) -> dict[str, object]:
        events: list[Event] = []
        errors = 0
        skipped = 0
        for record in body.records:
            parsed = parse_content(record.content, record.source, year=body.year)
            events.extend(parsed.events)
            errors += parsed.errors
            skipped += parsed.skipped
        events.sort(key=lambda event: event.timestamp)
        analysis = analyze_events(
            events,
            rules,
            enable_anomaly=body.enable_anomaly,
            seed=body.seed,
        )
        analysis.parse_errors = errors
        analysis.skipped_lines = skipped
        return _analysis_body(analysis)

    return app


app = create_app()
