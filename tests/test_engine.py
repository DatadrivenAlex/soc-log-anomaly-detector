"""Rule behavior against hand-built events."""

from __future__ import annotations

from tests.helpers import at, event_at

from socdetect.engine import Rule, evaluate, load_rules
from socdetect.models import Event


def _ids(events: list[Event], rules: list[Rule] | None = None) -> set[str]:
    return {alert.rule_id for alert in evaluate(rules or load_rules(), events)}


def _failures(
    count: int, *, user: str = "root", ip: str = "203.0.113.50", gap: int = 20
) -> list[Event]:
    return [
        event_at(
            at(11, 0, gap * index),
            user=user,
            src_ip=ip,
            raw=f"fail {user} {index}",
            privileged=user == "root",
        )
        for index in range(count)
    ]


def test_rules_catalog_loads_unique_sigma_style_ids() -> None:
    rules = load_rules()
    assert len(rules) == 7
    assert len({rule.id for rule in rules}) == 7
    brute = next(rule for rule in rules if rule.id == "ssh-brute-force")
    assert brute.technique == "T1110.001"
    assert "attack.t1110.001" in brute.tags
    assert brute.falsepositives
    assert brute.threshold is not None
    assert brute.threshold["window"] == "10m"


def test_brute_force_fires_at_eight_and_not_at_seven() -> None:
    rules = load_rules()
    assert "ssh-brute-force" not in _ids(_failures(7), rules)
    alerts = evaluate(rules, _failures(8))
    brute = [alert for alert in alerts if alert.rule_id == "ssh-brute-force"]
    assert len(brute) == 1
    assert brute[0].mitre_technique == "T1110.001"
    assert brute[0].mitre_tactic == "Credential Access"
    assert brute[0].entity_value == "203.0.113.50|root"
    assert brute[0].severity in {"high", "critical"}


def test_brute_force_does_not_merge_two_users() -> None:
    events = _failures(8, user="root") + _failures(4, user="alice", ip="203.0.113.50")
    alerts = [
        alert for alert in evaluate(load_rules(), events) if alert.rule_id == "ssh-brute-force"
    ]
    assert len(alerts) == 1
    assert alerts[0].entity_value.endswith("|root")


def test_brute_window_does_not_count_a_slow_trickle() -> None:
    events = _failures(8, gap=120)
    assert "ssh-brute-force" not in _ids(events)


def test_two_sources_are_not_one_brute_force() -> None:
    events = _failures(4, ip="203.0.113.50") + _failures(4, ip="203.0.113.51")
    assert "ssh-brute-force" not in _ids(events)


def test_success_after_brute_force_is_critical() -> None:
    events = _failures(15)
    events.append(
        event_at(
            at(11, 6),
            outcome="success",
            user="root",
            src_ip="203.0.113.50",
            raw="Accepted password for root from 203.0.113.50 port 40016 ssh2",
            privileged=True,
        )
    )
    alert = next(
        item for item in evaluate(load_rules(), events) if item.rule_id == "ssh-brute-force"
    )
    assert alert.confirmed_access is True
    assert alert.severity == "critical"
    assert alert.score >= 90
    assert any("Accepted password" in line for line in alert.evidence)


def test_password_spray_fires_and_single_user_does_not() -> None:
    spray = [
        event_at(at(12, 0, 30 * index), user=f"svc{index:02d}", src_ip="203.0.113.60")
        for index in range(6)
    ]
    assert "password-spray" in _ids(spray)
    assert "password-spray" not in _ids(_failures(20, user="root", ip="203.0.113.60"))


def test_spray_rejects_one_account_hammered_inside_the_set() -> None:
    events = [
        event_at(at(12, index), user=f"svc{index:02d}", src_ip="203.0.113.60") for index in range(6)
    ]
    events.extend(
        event_at(at(12, index, 30), user="root", src_ip="203.0.113.60", privileged=True)
        for index in range(4)
    )
    assert "password-spray" not in _ids(events)


def test_five_accounts_is_not_a_spray() -> None:
    events = [
        event_at(at(12, 0, index), user=f"svc{index:02d}", src_ip="203.0.113.61")
        for index in range(5)
    ]
    assert "password-spray" not in _ids(events)


def test_impossible_travel_fast_pair_only() -> None:
    fast = [
        event_at(
            at(14, 0),
            outcome="success",
            user="alice",
            src_ip="198.51.100.30",
            lat=51.5074,
            lon=-0.1278,
            city="London",
            country="GB",
        ),
        event_at(
            at(14, 20),
            outcome="success",
            user="alice",
            src_ip="203.0.113.80",
            lat=1.3521,
            lon=103.8198,
            city="Singapore",
            country="SG",
        ),
    ]
    alerts = evaluate(load_rules(), fast)
    travel = [alert for alert in alerts if alert.rule_id == "impossible-travel"]
    assert len(travel) == 1
    assert travel[0].mitre_technique == "T1078"
    assert travel[0].entity_value == "alice"

    same_city = [
        event_at(at(14, 0), outcome="success", user="bob", lat=51.5, lon=-0.12, country="GB"),
        event_at(at(14, 20), outcome="success", user="bob", lat=51.52, lon=-0.10, country="GB"),
    ]
    assert "impossible-travel" not in _ids(same_city)

    slow = [
        event_at(
            at(14, 0),
            outcome="success",
            user="cara",
            lat=51.5074,
            lon=-0.1278,
        ),
        event_at(
            at(14, 0, day=4),
            outcome="success",
            user="cara",
            lat=1.3521,
            lon=103.8198,
        ),
    ]
    assert "impossible-travel" not in _ids(slow)


def test_travel_without_coordinates_is_silent() -> None:
    events = [
        event_at(at(14, 0), outcome="success", user="alice", src_ip="198.51.100.30"),
        event_at(at(14, 20), outcome="success", user="alice", src_ip="203.0.113.80"),
    ]
    assert "impossible-travel" not in _ids(events)


def test_path_traversal_and_benign_url() -> None:
    hit = event_at(
        at(15, 3),
        source="web_access",
        event_type="http_request",
        outcome="failure",
        user=None,
        src_ip="203.0.113.70",
        url="/static/../../etc/shadow",
        path="/static/../../etc/shadow",
        status_code=400,
    )
    miss = event_at(
        at(15, 4),
        source="web_access",
        event_type="http_request",
        outcome="success",
        user=None,
        src_ip="198.51.100.11",
        url="/reports",
        path="/reports",
        status_code=200,
    )
    assert "path-traversal" in _ids([hit])
    assert "path-traversal" not in _ids([miss])


def test_traversal_that_returns_200_is_critical() -> None:
    event = event_at(
        at(15, 3, 12),
        source="web_access",
        event_type="http_request",
        outcome="success",
        user=None,
        src_ip="203.0.113.70",
        url="/download?file=../../etc/passwd",
        path="/download",
        status_code=200,
        raw="GET /download?file=../../etc/passwd 200",
    )
    alert = next(
        item for item in evaluate(load_rules(), [event]) if item.rule_id == "path-traversal"
    )
    assert alert.confirmed_access is True
    assert alert.severity == "critical"


def test_blocked_traversal_stays_high() -> None:
    event = event_at(
        at(15, 3),
        source="web_access",
        event_type="http_request",
        outcome="failure",
        user=None,
        src_ip="203.0.113.70",
        url="/static/../../etc/shadow",
        path="/static/../../etc/shadow",
        status_code=400,
    )
    alert = next(
        item for item in evaluate(load_rules(), [event]) if item.rule_id == "path-traversal"
    )
    assert alert.severity == "high"
    assert alert.score < 90


def test_sql_injection_patterns_and_a_normal_query() -> None:
    injected = event_at(
        at(15, 3, 48),
        source="web_access",
        event_type="http_request",
        outcome="success",
        user=None,
        src_ip="203.0.113.70",
        url="/index.php?id=1 UNION SELECT username,password FROM users",
        path="/index.php",
        status_code=200,
    )
    normal = event_at(
        at(15, 1),
        source="web_access",
        event_type="http_request",
        outcome="success",
        user="jsmith",
        src_ip="198.51.100.11",
        url="/search?q=quarterly-report",
        path="/search",
        status_code=200,
    )
    assert "sql-injection" in _ids([injected])
    assert "sql-injection" not in _ids([normal])


def test_web_scan_threshold() -> None:
    scanned = [
        event_at(
            at(15, 0, 5 * index),
            source="web_access",
            event_type="http_request",
            outcome="failure",
            user=None,
            src_ip="203.0.113.70",
            path=f"/probe/{index}",
            url=f"/probe/{index}",
            status_code=404,
        )
        for index in range(12)
    ]
    assert "web-scanning" in _ids(scanned)
    short = scanned[:8]
    assert "web-scanning" not in _ids(short)


def test_off_hours_admin_boundaries() -> None:
    night = event_at(
        at(2, 17),
        source="windows_json",
        host="DC01",
        event_type="windows_logon",
        outcome="success",
        user="Administrator",
        src_ip="192.0.2.40",
        privileged=True,
        logon_type=10,
        raw="4624 Administrator 02:17",
    )
    day = event_at(
        at(10, 30),
        source="windows_json",
        host="DC01",
        event_type="windows_logon",
        outcome="success",
        user="Administrator",
        src_ip="198.51.100.31",
        privileged=True,
        logon_type=2,
    )
    user_night = event_at(
        at(3, 10),
        outcome="success",
        user="jsmith",
        src_ip="198.51.100.11",
        privileged=False,
    )
    weekend = event_at(
        at(10, 0, day=7),
        source="windows_json",
        event_type="windows_logon",
        outcome="success",
        user="Administrator",
        src_ip="192.0.2.40",
        privileged=True,
    )
    assert "off-hours-admin" in _ids([night])
    assert "off-hours-admin" not in _ids([day])
    assert "off-hours-admin" not in _ids([user_night])
    assert "off-hours-admin" in _ids([weekend])
    opened = evaluate(load_rules(), [night, day])
    off = next(alert for alert in opened if alert.rule_id == "off-hours-admin")
    assert off.first_seen.hour == 2
    assert off.event_count == 1
    assert off.mitre_technique == "T1078.002"


def test_exact_hour_boundaries() -> None:
    opening = event_at(
        at(8, 0),
        outcome="success",
        user="root",
        privileged=True,
    )
    closing = event_at(
        at(18, 0),
        outcome="success",
        user="root",
        privileged=True,
    )
    assert "off-hours-admin" not in _ids([opening])
    assert "off-hours-admin" in _ids([closing])
