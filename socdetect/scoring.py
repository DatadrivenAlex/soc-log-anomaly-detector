"""Alert severity scoring and exact-entity deduplication."""

from __future__ import annotations

import hashlib
from datetime import datetime

from socdetect.models import Alert, as_utc

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
SEVERITY_FLOOR_SCORE = {"low": 25, "medium": 45, "high": 70, "critical": 90}


def band(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 45:
        return "medium"
    return "low"


def higher_severity(left: str, right: str) -> str:
    return left if SEVERITY_RANK[left] >= SEVERITY_RANK[right] else right


def compute_score(
    base: int,
    event_count: int,
    *,
    confirmed_access: bool,
    level: str,
) -> tuple[int, str]:
    """Turn a rule base score into a 0-100 score and a severity label.

    Volume adds a little weight. A later successful authentication, or an HTTP
    payload that drew a 2xx/3xx, adds more. ``level`` is a floor so a rule
    authored as high cannot be reported as low just because the count is small.
    """
    score = base + min(10, max(0, event_count - 8) // 2)
    if confirmed_access:
        score += 15
    score = max(0, min(100, score))
    severity = band(score)
    if SEVERITY_RANK[severity] < SEVERITY_RANK[level]:
        severity = level
        score = max(score, SEVERITY_FLOOR_SCORE[level])
    return score, severity


def alert_id(rule_id: str, entity_type: str, entity_value: str, first_seen: datetime) -> str:
    seen = as_utc(first_seen).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload = f"{rule_id}|{entity_type}|{entity_value}|{seen}"
    digest = hashlib.sha256(payload.encode()).hexdigest()[:8].upper()
    return f"ALT-{digest}"


def dedup(alerts: list[Alert]) -> list[Alert]:
    """Collapse alerts that share a rule and entity. Keep the stronger score."""
    merged: dict[tuple[str, str, str], Alert] = {}
    for alert in alerts:
        key = (alert.rule_id, alert.entity_type, alert.entity_value)
        current = merged.get(key)
        if current is None:
            merged[key] = alert
            continue
        evidence: list[str] = []
        for line in current.evidence + alert.evidence:
            if line not in evidence:
                evidence.append(line)
        first = min(current.first_seen, alert.first_seen)
        last = max(current.last_seen, alert.last_seen)
        score = max(current.score, alert.score)
        severity = higher_severity(current.severity, alert.severity)
        confirmed = current.confirmed_access or alert.confirmed_access
        merged[key] = Alert(
            alert_id=alert_id(alert.rule_id, alert.entity_type, alert.entity_value, first),
            rule_id=alert.rule_id,
            title=current.title,
            description=current.description,
            severity=severity,
            score=score,
            detector=current.detector,
            mitre_technique=current.mitre_technique,
            mitre_technique_name=current.mitre_technique_name,
            mitre_tactic=current.mitre_tactic,
            entity_type=current.entity_type,
            entity_value=current.entity_value,
            event_count=max(current.event_count, alert.event_count),
            first_seen=first,
            last_seen=last,
            evidence=evidence[:5],
            recommendation=current.recommendation,
            confirmed_access=confirmed,
        )
    return list(merged.values())


def sort_alerts(alerts: list[Alert]) -> list[Alert]:
    return sorted(
        alerts,
        key=lambda alert: (-SEVERITY_RANK[alert.severity], -alert.score, as_utc(alert.first_seen)),
    )
