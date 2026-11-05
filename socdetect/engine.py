"""Sigma-inspired rule engine.

This is a deliberate subset: equality selections, keyword and regex matchers,
count / distinct / unique thresholds over a sliding window, an off-hours
filter, and one correlation (impossible travel). It is not a Sigma compiler.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from socdetect.geo import haversine_km
from socdetect.models import Alert, Event, as_utc
from socdetect.scoring import SEVERITY_RANK, alert_id, compute_score

_WINDOW = {"s": 1, "m": 60, "h": 3600}


@dataclass(slots=True)
class Rule:
    id: str
    title: str
    description: str
    level: str
    base_score: int
    technique: str
    technique_name: str
    tactic: str
    recommendation: str
    selection: dict[str, Any]
    falsepositives: list[str]
    tags: list[str]
    match: dict[str, Any] | None = None
    threshold: dict[str, Any] | None = None
    correlation: dict[str, Any] | None = None
    time_filter: dict[str, Any] | None = None
    aggregate: dict[str, Any] | None = None
    author: str = ""
    status: str = "experimental"

    def summary(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description.strip(),
            "level": self.level,
            "base_score": self.base_score,
            "status": self.status,
            "author": self.author,
            "mitre_technique": self.technique,
            "mitre_technique_name": self.technique_name,
            "mitre_tactic": self.tactic,
            "tags": list(self.tags),
            "falsepositives": list(self.falsepositives),
            "recommendation": self.recommendation.strip(),
        }


class RuleError(ValueError):
    pass


def default_rules_dir() -> Path:
    return Path(__file__).resolve().parent / "rules"


def load_rules(directory: Path | None = None) -> list[Rule]:
    folder = directory or default_rules_dir()
    paths = sorted(folder.glob("*.yml"))
    if not paths:
        raise RuleError(f"No YAML rules found in {folder}")
    rules = [_load_rule(path) for path in paths]
    ids = [rule.id for rule in rules]
    if len(ids) != len(set(ids)):
        raise RuleError("Rule ids must be unique")
    return rules


def _require(data: dict[str, Any], key: str, path: Path) -> Any:
    if key not in data:
        raise RuleError(f"{path.name} is missing {key}")
    return data[key]


def _load_rule(path: Path) -> Rule:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise RuleError(f"{path.name} must be a mapping")
    detection = _require(loaded, "detection", path)
    mitre = _require(loaded, "mitre", path)
    level = str(loaded.get("level", "medium"))
    if level not in SEVERITY_RANK:
        raise RuleError(f"{path.name} has unknown level {level}")
    if not isinstance(detection, dict) or "selection" not in detection:
        raise RuleError(f"{path.name} detection.selection is required")
    return Rule(
        id=str(_require(loaded, "id", path)),
        title=str(_require(loaded, "title", path)),
        description=str(loaded.get("description", "")).strip(),
        level=level,
        base_score=int(loaded.get("base_score", 50)),
        technique=str(mitre["technique"]),
        technique_name=str(mitre["technique_name"]),
        tactic=str(mitre["tactic"]),
        recommendation=str(loaded.get("recommendation", "")).strip(),
        selection=dict(detection["selection"]),
        falsepositives=[str(item) for item in loaded.get("falsepositives", [])],
        tags=[str(item) for item in loaded.get("tags", [])],
        match=detection.get("match"),
        threshold=detection.get("threshold"),
        correlation=detection.get("correlation"),
        time_filter=detection.get("time_filter"),
        aggregate=detection.get("aggregate"),
        author=str(loaded.get("author", "")),
        status=str(loaded.get("status", "experimental")),
    )


def _matches_selection(event: Event, selection: dict[str, Any]) -> bool:
    for field, expected in selection.items():
        actual = event.get(field)
        if isinstance(expected, list):
            if actual not in expected:
                return False
        elif isinstance(expected, bool):
            if bool(actual) is not expected:
                return False
        elif actual != expected:
            return False
    return True


def _matches_pattern(event: Event, spec: dict[str, Any]) -> bool:
    value = str(event.get(spec["field"]) or "")
    lowered = value.lower()
    contains = [str(item) for item in spec.get("any_contains", [])]
    patterns = [str(item) for item in spec.get("any_regex", [])]
    if any(token.lower() in lowered for token in contains):
        return True
    return any(re.search(pattern, value) for pattern in patterns)


def _outside_business_hours(moment: datetime, spec: dict[str, Any]) -> bool:
    moment = as_utc(moment)
    if moment.weekday() >= 5:
        return True
    start = str(spec.get("start", "08:00"))
    end = str(spec.get("end", "18:00"))
    start_h, start_m = (int(part) for part in start.split(":"))
    end_h, end_m = (int(part) for part in end.split(":"))
    minutes = moment.hour * 60 + moment.minute
    return not (start_h * 60 + start_m <= minutes < end_h * 60 + end_m)


def _window_seconds(value: str) -> int:
    unit = value[-1]
    if unit not in _WINDOW:
        raise RuleError(f"Unsupported window {value}")
    return int(value[:-1]) * _WINDOW[unit]


def _entity_key(event: Event, fields: list[str]) -> tuple[Any, ...] | None:
    key = tuple(event.get(field) for field in fields)
    if any(part in (None, "", "-") for part in key):
        return None
    return key


def _chunk_matches(chunk: list[Event], spec: dict[str, Any]) -> bool:
    min_count = spec.get("min_count")
    if min_count is not None and len(chunk) < int(min_count):
        return False
    unique_field = spec.get("unique_field")
    if unique_field:
        values = {str(event.get(unique_field)) for event in chunk}
        if len(values) < int(spec["min_unique"]):
            return False
    distinct_field = spec.get("distinct_field")
    if distinct_field:
        counts = Counter(str(event.get(distinct_field)) for event in chunk)
        if len(counts) < int(spec["distinct_min"]):
            return False
        max_per = spec.get("max_per_distinct")
        if max_per is not None and max(counts.values()) > int(max_per):
            return False
    return min_count is not None or unique_field or distinct_field


def _select_evidence(events: list[Event], limit: int = 5) -> list[str]:
    ordered = sorted(events, key=lambda event: event.timestamp)
    if len(ordered) <= limit:
        return [event.raw[:300] for event in ordered]
    successes = [event for event in ordered if event.outcome == "success"]
    others = [event for event in ordered if event.outcome != "success"]
    chosen: list[Event] = list(others[: limit - (1 if successes else 0)])
    if successes and successes[-1] not in chosen:
        chosen.append(successes[-1])
    for event in others:
        if len(chosen) >= limit:
            break
        if event not in chosen:
            chosen.append(event)
    chosen.sort(key=lambda event: event.timestamp)
    return [event.raw[:300] for event in chosen[:limit]]


def _payload_accepted(events: list[Event]) -> bool:
    for event in events:
        status = event.get("status_code")
        if event.source == "web_access" and isinstance(status, int) and status < 400:
            return True
    return False


def _later_successes(
    events: list[Event],
    group_by: list[str],
    key: tuple[Any, ...],
    first: datetime,
    last: datetime,
) -> list[Event]:
    end = last + timedelta(minutes=30)
    found: list[Event] = []
    for event in events:
        if event.outcome != "success":
            continue
        if _entity_key(event, group_by) != key:
            continue
        if first <= event.timestamp <= end:
            found.append(event)
    return found


def _build_alert(
    rule: Rule,
    events: list[Event],
    entity_type: str,
    entity_value: str,
    *,
    confirmed_access: bool,
) -> Alert:
    ordered = sorted(events, key=lambda event: event.timestamp)
    confirmed = confirmed_access or _payload_accepted(ordered)
    score, severity = compute_score(
        rule.base_score,
        len(ordered),
        confirmed_access=confirmed,
        level=rule.level,
    )
    description = rule.description
    if confirmed and rule.id in {"ssh-brute-force", "password-spray"}:
        description = f"{description} A successful authentication followed the failures."
    if confirmed and rule.id in {"sql-injection", "path-traversal"}:
        description = f"{description} At least one matching request returned a status below 400."
    return Alert(
        alert_id=alert_id(rule.id, entity_type, entity_value, ordered[0].timestamp),
        rule_id=rule.id,
        title=rule.title,
        description=description,
        severity=severity,
        score=score,
        detector="rule",
        mitre_technique=rule.technique,
        mitre_technique_name=rule.technique_name,
        mitre_tactic=rule.tactic,
        entity_type=entity_type,
        entity_value=entity_value,
        event_count=len(ordered),
        first_seen=ordered[0].timestamp,
        last_seen=ordered[-1].timestamp,
        evidence=_select_evidence(ordered),
        recommendation=rule.recommendation,
        confirmed_access=confirmed,
    )


def _threshold_alerts(rule: Rule, selected: list[Event], all_events: list[Event]) -> list[Alert]:
    spec = rule.threshold or {}
    window = _window_seconds(str(spec["window"]))
    group_by = [str(field) for field in spec["group_by"]]
    status_gte = spec.get("status_gte")
    buckets: dict[tuple[Any, ...], list[Event]] = defaultdict(list)
    for event in selected:
        if status_gte is not None:
            status = event.get("status_code")
            if not isinstance(status, int) or status < int(status_gte):
                continue
        key = _entity_key(event, group_by)
        if key is None:
            continue
        buckets[key].append(event)

    alerts: list[Alert] = []
    for key, grouped in buckets.items():
        grouped.sort(key=lambda event: event.timestamp)
        hit: set[int] = set()
        left = 0
        for right in range(len(grouped)):
            while (grouped[right].timestamp - grouped[left].timestamp).total_seconds() > window:
                left += 1
            chunk = grouped[left : right + 1]
            if _chunk_matches(chunk, spec):
                hit.update(range(left, right + 1))
        if not hit:
            continue
        matched = [grouped[index] for index in sorted(hit)]
        confirmed = False
        if spec.get("include_later_success"):
            extras = _later_successes(
                all_events, group_by, key, matched[0].timestamp, matched[-1].timestamp
            )
            if extras:
                confirmed = True
                known = {id(event) for event in matched}
                matched.extend(event for event in extras if id(event) not in known)
        entity_type = "+".join(group_by)
        entity_value = "|".join(str(part) for part in key)
        alerts.append(
            _build_alert(
                rule,
                matched,
                entity_type,
                entity_value,
                confirmed_access=confirmed,
            )
        )
    return alerts


def _aggregate_alerts(rule: Rule, selected: list[Event]) -> list[Alert]:
    spec = rule.aggregate or {"group_by": ["src_ip"]}
    group_by = [str(field) for field in spec.get("group_by", ["src_ip"])]
    buckets: dict[tuple[Any, ...], list[Event]] = defaultdict(list)
    for event in selected:
        key = _entity_key(event, group_by)
        if key is None:
            continue
        buckets[key].append(event)
    alerts: list[Alert] = []
    for key, grouped in buckets.items():
        alerts.append(
            _build_alert(
                rule,
                grouped,
                "+".join(group_by),
                "|".join(str(part) for part in key),
                confirmed_access=False,
            )
        )
    return alerts


def _impossible_travel(rule: Rule, selected: list[Event]) -> list[Alert]:
    spec = rule.correlation or {}
    max_speed = float(spec.get("max_speed_kmh", 900))
    min_distance = float(spec.get("min_distance_km", 500))
    group_by = [str(field) for field in spec.get("group_by", ["user"])]
    buckets: dict[tuple[Any, ...], list[Event]] = defaultdict(list)
    for event in selected:
        if event.get("lat") is None or event.get("lon") is None:
            continue
        key = _entity_key(event, group_by)
        if key is None:
            continue
        buckets[key].append(event)

    alerts: list[Alert] = []
    for key, grouped in buckets.items():
        grouped.sort(key=lambda event: event.timestamp)
        chosen: list[Event] = []
        seen: set[int] = set()
        for prev, nxt in zip(grouped, grouped[1:], strict=False):
            hours = (nxt.timestamp - prev.timestamp).total_seconds() / 3600
            if hours <= 0:
                continue
            distance = haversine_km(
                float(prev.get("lat")),
                float(prev.get("lon")),
                float(nxt.get("lat")),
                float(nxt.get("lon")),
            )
            if distance >= min_distance and distance / hours > max_speed:
                for event in (prev, nxt):
                    if id(event) not in seen:
                        seen.add(id(event))
                        chosen.append(event)
        if not chosen:
            continue
        alerts.append(
            _build_alert(
                rule,
                chosen,
                "+".join(group_by),
                "|".join(str(part) for part in key),
                confirmed_access=False,
            )
        )
    return alerts


def evaluate_rule(rule: Rule, events: list[Event]) -> list[Alert]:
    selected = [event for event in events if _matches_selection(event, rule.selection)]
    if rule.match:
        selected = [event for event in selected if _matches_pattern(event, rule.match)]
    if rule.time_filter:
        selected = [
            event
            for event in selected
            if _outside_business_hours(event.timestamp, rule.time_filter)
        ]
    if not selected and not rule.correlation:
        return []
    if rule.correlation and rule.correlation.get("type") == "impossible_travel":
        return _impossible_travel(rule, selected)
    if rule.threshold:
        return _threshold_alerts(rule, selected, events)
    return _aggregate_alerts(rule, selected)


def evaluate(rules: list[Rule], events: list[Event]) -> list[Alert]:
    alerts: list[Alert] = []
    for rule in rules:
        alerts.extend(evaluate_rule(rule, events))
    return alerts
