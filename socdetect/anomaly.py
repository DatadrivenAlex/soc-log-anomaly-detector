"""Per-IP and per-user IsolationForest over behavioral ratios.

The model is fit on the batch itself. It needs a mixed population and will
not run when too few entities have enough events. Scores are comparable only
inside that batch.
"""

from __future__ import annotations

import math
import os
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime

from sklearn.ensemble import IsolationForest

from socdetect.models import Alert, Event, as_utc
from socdetect.scoring import alert_id, band

os.environ.setdefault("OMP_NUM_THREADS", "1")

MIN_ENTITY_EVENTS = 4
MIN_ENTITIES = 8

IP_FEATURES = [
    "fail_ratio",
    "unique_users",
    "unique_paths",
    "http_4xx_ratio",
    "off_hours_ratio",
    "unique_countries",
    "log_fail",
]
USER_FEATURES = [
    "fail_ratio",
    "unique_ips",
    "unique_countries",
    "off_hours_ratio",
    "privileged_ratio",
    "log_fail",
]

_FEATURE_MITRE = {
    "unique_users": ("T1110.003", "Password Spraying", "Credential Access"),
    "fail_ratio": ("T1110.001", "Password Guessing", "Credential Access"),
    "log_fail": ("T1110.001", "Password Guessing", "Credential Access"),
    "unique_paths": ("T1595.002", "Vulnerability Scanning", "Reconnaissance"),
    "http_4xx_ratio": ("T1595.002", "Vulnerability Scanning", "Reconnaissance"),
    "unique_ips": ("T1078", "Valid Accounts", "Defense Evasion"),
    "unique_countries": ("T1078", "Valid Accounts", "Defense Evasion"),
    "off_hours_ratio": ("T1078", "Valid Accounts", "Defense Evasion"),
    "privileged_ratio": ("T1078", "Valid Accounts", "Defense Evasion"),
}


@dataclass(slots=True)
class EntityScore:
    kind: str
    entity: str
    decision: float
    outlier: bool
    features: dict[str, float]
    first_seen: datetime
    last_seen: datetime
    evidence: list[str]
    event_count: int


def _off_hours(moment: datetime) -> bool:
    moment = as_utc(moment)
    if moment.weekday() >= 5:
        return True
    minutes = moment.hour * 60 + moment.minute
    return not (8 * 60 <= minutes < 18 * 60)


def _ratio(part: int, whole: int) -> float:
    if whole <= 0:
        return 0.0
    return part / whole


def ip_profiles(events: list[Event]) -> dict[str, dict[str, float]]:
    grouped: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        if event.src_ip:
            grouped[event.src_ip].append(event)
    profiles: dict[str, dict[str, float]] = {}
    for ip, rows in grouped.items():
        if len(rows) < MIN_ENTITY_EVENTS:
            continue
        users = {event.user for event in rows if event.user}
        paths = {str(event.get("path")) for event in rows if event.get("path")}
        countries = {str(event.get("country")) for event in rows if event.get("country")}
        http = [event for event in rows if event.source == "web_access"]
        http_4xx = [
            event
            for event in http
            if isinstance(event.get("status_code"), int)
            and 400 <= int(event.get("status_code")) < 500
        ]
        fails = [event for event in rows if event.outcome == "failure"]
        off = [event for event in rows if _off_hours(event.timestamp)]
        profiles[ip] = {
            "fail_ratio": _ratio(len(fails), len(rows)),
            "unique_users": float(len(users)),
            "unique_paths": float(len(paths)),
            "http_4xx_ratio": _ratio(len(http_4xx), len(http)),
            "off_hours_ratio": _ratio(len(off), len(rows)),
            "unique_countries": float(len(countries)),
            "log_fail": math.log1p(len(fails)),
        }
    return profiles


def user_profiles(events: list[Event]) -> dict[str, dict[str, float]]:
    grouped: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        if event.user:
            grouped[event.user].append(event)
    profiles: dict[str, dict[str, float]] = {}
    for user, rows in grouped.items():
        if len(rows) < MIN_ENTITY_EVENTS:
            continue
        ips = {event.src_ip for event in rows if event.src_ip}
        countries = {str(event.get("country")) for event in rows if event.get("country")}
        fails = [event for event in rows if event.outcome == "failure"]
        off = [event for event in rows if _off_hours(event.timestamp)]
        privileged = [event for event in rows if event.get("privileged") is True]
        profiles[user] = {
            "fail_ratio": _ratio(len(fails), len(rows)),
            "unique_ips": float(len(ips)),
            "unique_countries": float(len(countries)),
            "off_hours_ratio": _ratio(len(off), len(rows)),
            "privileged_ratio": _ratio(len(privileged), len(rows)),
            "log_fail": math.log1p(len(fails)),
        }
    return profiles


def _fit_scores(
    kind: str,
    profiles: dict[str, dict[str, float]],
    names: list[str],
    events: list[Event],
    *,
    seed: int,
) -> list[EntityScore]:
    if len(profiles) < MIN_ENTITIES:
        return []
    labels = list(profiles)
    matrix = [[profiles[label][name] for name in names] for label in labels]
    model = IsolationForest(
        n_estimators=200,
        contamination=0.12,
        random_state=seed,
        n_jobs=1,
        bootstrap=False,
    )
    model.fit(matrix)
    decisions = model.decision_function(matrix)
    predictions = model.predict(matrix)
    grouped: dict[str, list[Event]] = defaultdict(list)
    attribute = "src_ip" if kind == "src_ip" else "user"
    for event in events:
        value = event.get(attribute)
        if value in profiles:
            grouped[str(value)].append(event)
    scores: list[EntityScore] = []
    for label, decision, prediction in zip(labels, decisions, predictions, strict=True):
        rows = sorted(grouped[label], key=lambda event: event.timestamp)
        scores.append(
            EntityScore(
                kind=kind,
                entity=label,
                decision=float(decision),
                outlier=bool(prediction == -1),
                features=dict(profiles[label]),
                first_seen=rows[0].timestamp,
                last_seen=rows[-1].timestamp,
                evidence=[row.raw[:300] for row in rows[:3]],
                event_count=len(rows),
            )
        )
    return scores


def score_entities(events: list[Event], *, seed: int = 42) -> list[EntityScore]:
    ip_scores = _fit_scores("src_ip", ip_profiles(events), IP_FEATURES, events, seed=seed)
    user_scores = _fit_scores("user", user_profiles(events), USER_FEATURES, events, seed=seed + 1)
    return ip_scores + user_scores


def _dominant_feature(features: dict[str, float], population: list[dict[str, float]]) -> str:
    best_name = "fail_ratio"
    best_z = -1.0
    for name, value in features.items():
        column = sorted(row[name] for row in population)
        median = column[len(column) // 2]
        deviations = sorted(abs(item - median) for item in column)
        mad = deviations[len(deviations) // 2] or 1.0
        z_score = (value - median) / mad
        if z_score > best_z:
            best_z = z_score
            best_name = name
    return best_name


def alerts_from_scores(scores: list[EntityScore]) -> list[Alert]:
    alerts: list[Alert] = []
    by_kind: dict[str, list[EntityScore]] = defaultdict(list)
    for score in scores:
        by_kind[score.kind].append(score)
    for score in scores:
        if not score.outlier:
            continue
        peers = [peer.features for peer in by_kind[score.kind]]
        feature = _dominant_feature(score.features, peers)
        technique, technique_name, tactic = _FEATURE_MITRE[feature]
        # Map the negative decision_function into the medium/high band.
        # Typical in-batch outliers land near 0 to -0.15.
        lifted = int(round(58 + min(24.0, max(0.0, -score.decision) * 120)))
        severity = band(lifted)
        if severity == "low":
            severity = "medium"
            lifted = max(lifted, 45)
        description = (
            "IsolationForest fit on this batch marked the entity as an outlier. "
            f"Dominant feature {feature}={score.features[feature]:.2f}. "
            f"decision_function={score.decision:.3f}. "
            "Review it next to any rule alerts for the same entity. "
            "Do not contain on this signal alone."
        )
        alerts.append(
            Alert(
                alert_id=alert_id("isolation-forest", score.kind, score.entity, score.first_seen),
                rule_id="isolation-forest",
                title=f"Anomalous {score.kind} behavior",
                description=description,
                severity=severity,
                score=lifted,
                detector="anomaly",
                mitre_technique=technique,
                mitre_technique_name=technique_name,
                mitre_tactic=tactic,
                entity_type=score.kind,
                entity_value=score.entity,
                event_count=score.event_count,
                first_seen=score.first_seen,
                last_seen=score.last_seen,
                evidence=score.evidence,
                recommendation=(
                    "Compare the entity with peer workstations or accounts from the same "
                    "batch. Escalate only if a rule-based alert, a successful login, or "
                    "an unusual geo corroborates the outlier."
                ),
                confirmed_access=False,
            )
        )
    return alerts


def detect_anomalies(
    events: list[Event], *, seed: int = 42
) -> tuple[list[Alert], bool, str | None]:
    ip_count = len(ip_profiles(events))
    user_count = len(user_profiles(events))
    if ip_count < MIN_ENTITIES and user_count < MIN_ENTITIES:
        return (
            [],
            False,
            (
                "Anomaly detector skipped: fewer than "
                f"{MIN_ENTITIES} IP profiles and {MIN_ENTITIES} user profiles "
                f"with at least {MIN_ENTITY_EVENTS} events."
            ),
        )
    scores = score_entities(events, seed=seed)
    return alerts_from_scores(scores), True, None
