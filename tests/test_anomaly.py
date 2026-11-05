"""IsolationForest scores on per-IP and per-user features."""

from __future__ import annotations

import math

from socdetect.anomaly import (
    MIN_ENTITIES,
    detect_anomalies,
    ip_profiles,
    score_entities,
)
from socdetect.generate import BRUTE_IP, SCAN_IP, SPRAY_IP, render_logs
from socdetect.parsers.dispatch import parse_content
from socdetect.pipeline import enrich


def _generated(seed: int = 42):
    files = render_logs(seed)
    events = []
    for name, source in (
        ("auth.log", "linux_auth"),
        ("access.log", "web_access"),
        ("windows.jsonl", "windows_json"),
    ):
        events.extend(parse_content(files[name], source).events)
    return [enrich(event) for event in events]


def test_brute_ip_profile_is_failure_heavy() -> None:
    profiles = ip_profiles(_generated())
    brute = profiles[BRUTE_IP]
    assert brute["fail_ratio"] > 0.8
    assert brute["log_fail"] > math.log1p(10)
    assert brute["unique_users"] == 1


def test_attack_ips_score_below_the_benign_median() -> None:
    scores = [score for score in score_entities(_generated(), seed=42) if score.kind == "src_ip"]
    benign = [score.decision for score in scores if score.entity.startswith("198.51.100.")]
    assert len(benign) >= MIN_ENTITIES
    median = sorted(benign)[len(benign) // 2]
    for score in scores:
        if score.entity in {BRUTE_IP, SPRAY_IP, SCAN_IP}:
            assert score.decision < median


def test_scores_are_deterministic() -> None:
    events = _generated()
    first = [(item.kind, item.entity, round(item.decision, 6)) for item in score_entities(events)]
    second = [(item.kind, item.entity, round(item.decision, 6)) for item in score_entities(events)]
    assert first == second


def test_tiny_batch_skips_the_model() -> None:
    alerts, ran, note = detect_anomalies(_generated()[:5], seed=42)
    assert alerts == []
    assert ran is False
    assert note is not None
    assert "skipped" in note


def test_anomaly_alert_carries_a_technique() -> None:
    alerts, ran, note = detect_anomalies(_generated(), seed=42)
    assert ran is True
    assert note is None
    assert alerts
    for alert in alerts:
        assert alert.detector == "anomaly"
        assert alert.rule_id == "isolation-forest"
        assert alert.mitre_technique.startswith("T")
        assert alert.severity in {"medium", "high", "critical"}
        assert alert.recommendation
