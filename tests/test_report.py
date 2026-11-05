"""Markdown incident report content."""

from datetime import UTC, datetime
from pathlib import Path

from socdetect.engine import load_rules
from socdetect.generate import render_logs, write_logs
from socdetect.parsers.dispatch import parse_content
from socdetect.pipeline import analyze_events, analyze_paths
from socdetect.reporting import render_markdown, technique_url


def test_technique_url_splits_subtechniques() -> None:
    assert technique_url("T1110.001") == "https://attack.mitre.org/techniques/T1110/001/"
    assert technique_url("T1078") == "https://attack.mitre.org/techniques/T1078/"


def test_report_names_actions_and_false_positive_checks() -> None:
    files = render_logs(42)
    events = []
    for name, source in (
        ("auth.log", "linux_auth"),
        ("access.log", "web_access"),
        ("windows.jsonl", "windows_json"),
    ):
        events.extend(parse_content(files[name], source).events)
    rules = load_rules()
    analysis = analyze_events(events, rules, enable_anomaly=True, seed=42)
    text = render_markdown(analysis, rules, datetime(2026, 11, 3, 18, 0, tzinfo=UTC))
    assert "Password Guessing" in text
    assert "False-positive checks" in text
    assert "reset that credential" in text.lower() or "Reset that credential" in text
    assert "not a SIEM" in text or "does not retain a case" in text
    assert "T1190" in text


def test_checked_in_sample_matches_seed_42(tmp_path) -> None:
    write_logs(tmp_path, seed=42)
    analysis = analyze_paths([tmp_path], seed=42)
    rendered = render_markdown(analysis, load_rules(), datetime(2026, 11, 3, 18, 0, tzinfo=UTC))
    root = Path(__file__).resolve().parents[1]
    checked = (root / "examples" / "incident-report.md").read_text(encoding="utf-8")
    assert rendered == checked
    assert "Lines skipped by the auth parser: 2" in checked
