"""Load logs, enrich them, and run rules plus the anomaly detector."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from socdetect.anomaly import detect_anomalies
from socdetect.engine import Rule, evaluate, load_rules
from socdetect.geo import lookup
from socdetect.models import Alert, Event
from socdetect.parsers.dispatch import guess_source, parse_content
from socdetect.scoring import dedup, higher_severity, sort_alerts


@dataclass(slots=True)
class Analysis:
    events: list[Event]
    alerts: list[Alert]
    parse_errors: int = 0
    skipped_lines: int = 0
    anomaly_ran: bool = False
    notes: list[str] = field(default_factory=list)

    def summary(self) -> dict[str, object]:
        by_severity = Counter(alert.severity for alert in self.alerts)
        by_technique = Counter(alert.mitre_technique for alert in self.alerts)
        highest = None
        for alert in self.alerts:
            if highest is None or higher_severity(alert.severity, highest) == alert.severity:
                highest = alert.severity
        return {
            "events": len(self.events),
            "alerts": len(self.alerts),
            "parse_errors": self.parse_errors,
            "skipped_lines": self.skipped_lines,
            "anomaly_ran": self.anomaly_ran,
            "notes": list(self.notes),
            "by_severity": dict(by_severity),
            "by_technique": dict(by_technique),
            "highest_severity": highest,
        }


def enrich(event: Event) -> Event:
    point = lookup(event.src_ip)
    if point is not None:
        event.fields["city"] = point.city
        event.fields["country"] = point.country
        event.fields["lat"] = point.lat
        event.fields["lon"] = point.lon
    return event


def expand_inputs(paths: list[Path]) -> list[Path]:
    files: list[Path] = []
    for path in paths:
        if path.is_dir():
            for child in sorted(path.iterdir()):
                if child.is_file() and child.name != "manifest.json":
                    files.append(child)
        elif path.is_file():
            files.append(path)
    return files


def load_files(paths: list[Path], *, year: int = 2026) -> tuple[list[Event], int, int]:
    events: list[Event] = []
    errors = 0
    skipped = 0
    for path in expand_inputs(paths):
        text = path.read_text(encoding="utf-8", errors="replace")
        source = guess_source(path.name, text)
        if source == "skip":
            continue
        parsed = parse_content(text, source, year=year)
        events.extend(parsed.events)
        errors += parsed.errors
        skipped += parsed.skipped
    events.sort(key=lambda event: event.timestamp)
    return events, errors, skipped


def analyze_events(
    events: list[Event],
    rules: list[Rule],
    *,
    enable_anomaly: bool = True,
    seed: int = 42,
) -> Analysis:
    enriched = [enrich(event) for event in events]
    alerts = evaluate(rules, enriched)
    anomaly_ran = False
    notes: list[str] = []
    if enable_anomaly:
        anomaly_alerts, anomaly_ran, note = detect_anomalies(enriched, seed=seed)
        alerts.extend(anomaly_alerts)
        if note:
            notes.append(note)
    else:
        notes.append("Anomaly detector disabled.")
    alerts = sort_alerts(dedup(alerts))
    return Analysis(
        events=enriched,
        alerts=alerts,
        anomaly_ran=anomaly_ran,
        notes=notes,
    )


def analyze_paths(
    paths: list[Path],
    *,
    rules_dir: Path | None = None,
    year: int = 2026,
    enable_anomaly: bool = True,
    seed: int = 42,
) -> Analysis:
    rules = load_rules(rules_dir)
    events, errors, skipped = load_files(paths, year=year)
    analysis = analyze_events(events, rules, enable_anomaly=enable_anomaly, seed=seed)
    analysis.parse_errors = errors
    analysis.skipped_lines = skipped
    return analysis
