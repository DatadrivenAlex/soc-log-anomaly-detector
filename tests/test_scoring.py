"""Severity math and alert deduplication."""

from datetime import UTC, datetime

from socdetect.models import Alert
from socdetect.reporting import csv_safe
from socdetect.scoring import alert_id, band, compute_score, dedup


def _alert(
    score: int, severity: str, *, rule: str = "ssh-brute-force", entity: str = "1.1.1.1"
) -> Alert:
    moment = datetime(2026, 11, 3, 11, 0, tzinfo=UTC)
    return Alert(
        alert_id=alert_id(rule, "src_ip", entity, moment),
        rule_id=rule,
        title="SSH brute force",
        description="d",
        severity=severity,
        score=score,
        detector="rule",
        mitre_technique="T1110.001",
        mitre_technique_name="Password Guessing",
        mitre_tactic="Credential Access",
        entity_type="src_ip",
        entity_value=entity,
        event_count=8,
        first_seen=moment,
        last_seen=moment,
        evidence=[f"line-{score}"],
        recommendation="reset",
    )


def test_score_bands() -> None:
    assert band(44) == "low"
    assert band(45) == "medium"
    assert band(69) == "medium"
    assert band(70) == "high"
    assert band(89) == "high"
    assert band(90) == "critical"


def test_level_floor_lifts_a_short_high_rule() -> None:
    score, severity = compute_score(40, 1, confirmed_access=False, level="high")
    assert severity == "high"
    assert score >= 70


def test_confirmed_access_can_reach_critical() -> None:
    score, severity = compute_score(72, 16, confirmed_access=True, level="high")
    assert severity == "critical"
    assert score >= 90


def test_dedup_keeps_the_higher_score_and_merges_evidence() -> None:
    merged = dedup([_alert(70, "high"), _alert(91, "critical")])
    assert len(merged) == 1
    assert merged[0].score == 91
    assert merged[0].severity == "critical"
    assert "line-70" in merged[0].evidence
    assert "line-91" in merged[0].evidence


def test_dedup_leaves_different_entities_alone() -> None:
    assert (
        len(dedup([_alert(70, "high", entity="1.1.1.1"), _alert(70, "high", entity="2.2.2.2")]))
        == 2
    )


def test_alert_id_is_stable() -> None:
    moment = datetime(2026, 11, 3, 11, 0, tzinfo=UTC)
    assert alert_id("ssh-brute-force", "src_ip", "203.0.113.50", moment) == alert_id(
        "ssh-brute-force", "src_ip", "203.0.113.50", moment
    )


def test_csv_formula_is_neutralized() -> None:
    assert csv_safe("=cmd|'/c calc'!A0") == "'=cmd|'/c calc'!A0"
    assert csv_safe("203.0.113.50") == "203.0.113.50"
    assert csv_safe("-n") == "'-n"
