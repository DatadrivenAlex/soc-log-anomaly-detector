"""JSON, CSV, and Markdown writers for a completed analysis."""

from __future__ import annotations

import csv
import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from socdetect.engine import Rule
from socdetect.models import Alert, stamp
from socdetect.pipeline import Analysis
from socdetect.scoring import SEVERITY_RANK

_SEVERITY_ORDER = ["critical", "high", "medium", "low"]


def technique_url(technique: str) -> str:
    if "." in technique:
        parent, sub = technique.split(".", 1)
        return f"https://attack.mitre.org/techniques/{parent}/{sub}/"
    return f"https://attack.mitre.org/techniques/{technique}/"


def csv_safe(value: object) -> str:
    text = "" if value is None else str(value)
    if text[:1] in {"=", "+", "-", "@"}:
        return "'" + text
    return text


def alerts_payload(analysis: Analysis, generated_at: datetime) -> dict[str, object]:
    return {
        "generated_at": stamp(generated_at),
        "summary": analysis.summary(),
        "alerts": [alert.to_dict() for alert in analysis.alerts],
    }


def write_json(analysis: Analysis, path: Path, generated_at: datetime) -> None:
    path.write_text(
        json.dumps(alerts_payload(analysis, generated_at), indent=2) + "\n",
        encoding="utf-8",
    )


def write_csv(analysis: Analysis, path: Path) -> None:
    columns = [
        "alert_id",
        "severity",
        "score",
        "rule_id",
        "title",
        "mitre_technique",
        "mitre_tactic",
        "entity",
        "event_count",
        "first_seen",
        "last_seen",
        "detector",
        "confirmed_access",
        "evidence_sample",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for alert in analysis.alerts:
            data = alert.to_dict()
            evidence = alert.evidence[0] if alert.evidence else ""
            writer.writerow(
                {
                    "alert_id": data["alert_id"],
                    "severity": data["severity"],
                    "score": data["score"],
                    "rule_id": data["rule_id"],
                    "title": csv_safe(data["title"]),
                    "mitre_technique": data["mitre_technique"],
                    "mitre_tactic": data["mitre_tactic"],
                    "entity": csv_safe(data["entity"]),
                    "event_count": data["event_count"],
                    "first_seen": data["first_seen"],
                    "last_seen": data["last_seen"],
                    "detector": data["detector"],
                    "confirmed_access": data["confirmed_access"],
                    "evidence_sample": csv_safe(evidence),
                }
            )


def _falsepositives(alert: Alert, rules: dict[str, Rule]) -> list[str]:
    rule = rules.get(alert.rule_id)
    if rule is not None:
        return rule.falsepositives
    return [
        "A busy but legitimate host that is rare inside this particular batch",
        "A population that is mostly attack traffic, which makes outliers unstable",
    ]


def render_markdown(analysis: Analysis, rules: list[Rule], generated_at: datetime) -> str:
    summary = analysis.summary()
    rules_by_id = {rule.id: rule for rule in rules}
    by_severity = summary["by_severity"]
    assert isinstance(by_severity, dict)
    lines: list[str] = [
        "# SOC incident report",
        "",
        f"- Generated: {stamp(generated_at)}",
        f"- Events analyzed: {summary['events']}",
        f"- Parse errors: {summary['parse_errors']}",
        f"- Lines skipped by the auth parser: {summary['skipped_lines']}",
        f"- Alerts: {summary['alerts']}",
        f"- Highest severity: {summary['highest_severity'] or 'none'}",
        f"- Anomaly model ran: {'yes' if summary['anomaly_ran'] else 'no'}",
        "",
        "## Executive summary",
        "",
    ]
    if not analysis.alerts:
        lines.append("No detections fired for this batch.")
    else:
        lines.append(
            "Rule matches and IsolationForest outliers are listed below, highest severity first. "
            "Confirmed access means a successful authentication followed credential failures, "
            "or a web payload received a status below 400."
        )
    if analysis.notes:
        lines.extend(["", "Notes:"])
        lines.extend(f"- {note}" for note in analysis.notes)
    lines.extend(["", "## Severity", "", "| Severity | Alerts |", "| --- | ---: |"])
    for name in _SEVERITY_ORDER:
        lines.append(f"| {name} | {by_severity.get(name, 0)} |")

    technique_counts = Counter(alert.mitre_technique for alert in analysis.alerts)
    lines.extend(
        ["", "## MITRE ATT&CK", "", "| Technique | Name | Alerts |", "| --- | --- | ---: |"]
    )
    named: dict[str, str] = {}
    for alert in analysis.alerts:
        named.setdefault(alert.mitre_technique, alert.mitre_technique_name)
    for technique, count in sorted(technique_counts.items()):
        url = technique_url(technique)
        lines.append(f"| [{technique}]({url}) | {named[technique]} | {count} |")
    if not technique_counts:
        lines.append("| — | — | 0 |")

    lines.extend(["", "## Alerts", ""])
    if not analysis.alerts:
        lines.append("_None._")
    for alert in sorted(
        analysis.alerts,
        key=lambda item: (-SEVERITY_RANK[item.severity], -item.score, item.alert_id),
    ):
        data = alert.to_dict()
        url = technique_url(alert.mitre_technique)
        lines.extend(
            [
                f"### {alert.alert_id} — {alert.severity.upper()} ({alert.score}) — {alert.title}",
                "",
                f"- Rule: `{alert.rule_id}` ({alert.detector})",
                f"- Entity: {data['entity']}",
                f"- Events: {alert.event_count}",
                f"- Window: {data['first_seen']} → {data['last_seen']}",
                (
                    f"- ATT&CK: [{alert.mitre_technique} {alert.mitre_technique_name}]({url}) "
                    f"/ {alert.mitre_tactic}"
                ),
                f"- Confirmed access: {'yes' if alert.confirmed_access else 'no'}",
                "",
                alert.description,
                "",
                "**Evidence**",
                "",
                "```text",
                *(alert.evidence or ["(no raw line retained)"]),
                "```",
                "",
                f"**Tier-1 action.** {alert.recommendation}",
                "",
            ]
        )
        falsepositives = _falsepositives(alert, rules_by_id)
        if falsepositives:
            lines.append("**False-positive checks.**")
            lines.append("")
            lines.extend(f"- {item}" for item in falsepositives)
            lines.append("")

    lines.extend(
        [
            "## Scope",
            "",
            "This report is a batch triage aid. It does not retain a case, block an address, "
            "or replace a SIEM. Thresholds and the lab IP-to-city map are documented in the "
            "project README.",
            "",
        ]
    )
    return "\n".join(lines)


def write_outputs(
    analysis: Analysis,
    rules: list[Rule],
    directory: Path,
    *,
    generated_at: datetime | None = None,
) -> dict[str, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    moment = generated_at or datetime.now(UTC)
    json_path = directory / "alerts.json"
    csv_path = directory / "alerts.csv"
    md_path = directory / "incident-report.md"
    write_json(analysis, json_path, moment)
    write_csv(analysis, csv_path)
    md_path.write_text(render_markdown(analysis, rules, moment), encoding="utf-8")
    return {"json": json_path, "csv": csv_path, "markdown": md_path}
