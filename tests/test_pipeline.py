"""End-to-end analysis of the seeded lab day."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from socdetect.engine import load_rules
from socdetect.generate import BRUTE_IP, write_logs
from socdetect.pipeline import analyze_paths
from socdetect.reporting import write_outputs

EXPECTED_RULES = {
    "ssh-brute-force",
    "password-spray",
    "impossible-travel",
    "web-scanning",
    "path-traversal",
    "sql-injection",
    "off-hours-admin",
    "isolation-forest",
}


def test_seed_42_detects_every_injected_scenario(tmp_path) -> None:
    write_logs(tmp_path, seed=42)
    analysis = analyze_paths([tmp_path], seed=42)
    found = {alert.rule_id for alert in analysis.alerts}
    assert EXPECTED_RULES <= found
    assert analysis.parse_errors == 0
    assert analysis.summary()["highest_severity"] == "critical"
    brute = next(alert for alert in analysis.alerts if alert.rule_id == "ssh-brute-force")
    assert brute.severity == "critical"
    assert brute.confirmed_access is True
    assert BRUTE_IP in brute.entity_value
    assert any("Accepted password" in line for line in brute.evidence)
    travel = next(alert for alert in analysis.alerts if alert.rule_id == "impossible-travel")
    assert any("198.51.100.30" in line for line in travel.evidence)
    assert any("203.0.113.80" in line for line in travel.evidence)
    assert analysis.skipped_lines >= 2


def test_a_different_seed_still_detects_the_fixed_attacks(tmp_path) -> None:
    write_logs(tmp_path, seed=7)
    analysis = analyze_paths([tmp_path], seed=7)
    found = {alert.rule_id for alert in analysis.alerts}
    assert EXPECTED_RULES <= found


def test_off_hours_alert_is_the_administrator_rdp(tmp_path) -> None:
    write_logs(tmp_path, seed=42)
    analysis = analyze_paths([tmp_path], enable_anomaly=False)
    off = [alert for alert in analysis.alerts if alert.rule_id == "off-hours-admin"]
    assert len(off) == 1
    assert off[0].entity_value == "Administrator"
    assert off[0].first_seen.hour == 2
    assert all(
        alert.entity_value != "jsmith" for alert in analysis.alerts if alert.detector == "rule"
    )


def test_outputs_json_csv_and_markdown(tmp_path) -> None:
    logs = tmp_path / "logs"
    reports = tmp_path / "reports"
    write_logs(logs, seed=42)
    analysis = analyze_paths([logs], seed=42)
    moment = datetime(2026, 11, 3, 18, 0, tzinfo=UTC)
    paths = write_outputs(analysis, load_rules(), reports, generated_at=moment)
    payload = json.loads(paths["json"].read_text(encoding="utf-8"))
    assert payload["generated_at"] == "2026-11-03T18:00:00Z"
    assert payload["summary"]["alerts"] == len(analysis.alerts)
    csv_text = paths["csv"].read_text(encoding="utf-8")
    assert "alert_id,severity,score" in csv_text
    assert "T1110.001" in csv_text
    report = paths["markdown"].read_text(encoding="utf-8")
    assert "# SOC incident report" in report
    assert "T1110.003" in report
    assert "Tier-1 action" in report


def test_disabling_anomaly_omits_that_detector(tmp_path) -> None:
    write_logs(tmp_path, seed=42)
    analysis = analyze_paths([tmp_path], enable_anomaly=False)
    assert analysis.anomaly_ran is False
    assert all(alert.detector == "rule" for alert in analysis.alerts)
    assert any("disabled" in note for note in analysis.notes)
