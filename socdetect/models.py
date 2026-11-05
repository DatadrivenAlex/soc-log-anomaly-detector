"""Normalized events and detection alerts."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


def as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def stamp(value: datetime) -> str:
    return as_utc(value).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(slots=True)
class Event:
    timestamp: datetime
    source: str
    host: str
    event_type: str
    outcome: str
    user: str | None
    src_ip: str | None
    raw: str
    fields: dict[str, Any] = field(default_factory=dict)

    def get(self, name: str) -> Any:
        if hasattr(self, name) and name != "fields":
            return getattr(self, name)
        return self.fields.get(name)


@dataclass(slots=True)
class ParseResult:
    events: list[Event]
    errors: int = 0
    skipped: int = 0


@dataclass(slots=True)
class Alert:
    alert_id: str
    rule_id: str
    title: str
    description: str
    severity: str
    score: int
    detector: str
    mitre_technique: str
    mitre_technique_name: str
    mitre_tactic: str
    entity_type: str
    entity_value: str
    event_count: int
    first_seen: datetime
    last_seen: datetime
    evidence: list[str]
    recommendation: str
    confirmed_access: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "score": self.score,
            "detector": self.detector,
            "mitre_technique": self.mitre_technique,
            "mitre_technique_name": self.mitre_technique_name,
            "mitre_tactic": self.mitre_tactic,
            "entity_type": self.entity_type,
            "entity_value": self.entity_value,
            "entity": format_entity(self),
            "event_count": self.event_count,
            "first_seen": stamp(self.first_seen),
            "last_seen": stamp(self.last_seen),
            "evidence": list(self.evidence),
            "recommendation": self.recommendation,
            "confirmed_access": self.confirmed_access,
        }


def format_entity(alert: Alert) -> str:
    keys = alert.entity_type.split("+")
    values = alert.entity_value.split("|")
    if len(keys) == len(values):
        return ", ".join(f"{key}={value}" for key, value in zip(keys, values, strict=True))
    return f"{alert.entity_type}={alert.entity_value}"
