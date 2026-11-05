"""FastAPI lab endpoint."""

from fastapi.testclient import TestClient

from socdetect.api import create_app

FAILED = (
    "Nov  3 11:00:{second:02d} lab-ssh sshd[2100]: Failed password for root "
    "from 203.0.113.50 port 400{second:02d} ssh2"
)
SUCCESS = (
    "Nov  3 11:06:00 lab-ssh sshd[2102]: Accepted password for root "
    "from 203.0.113.50 port 40016 ssh2"
)

client = TestClient(create_app())


def test_health_and_rule_catalog() -> None:
    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"
    catalog = client.get("/v1/rules")
    assert catalog.status_code == 200
    ids = {rule["id"] for rule in catalog.json()["rules"]}
    assert "ssh-brute-force" in ids
    assert "sql-injection" in ids
    assert len(ids) == 7


def test_post_brute_force_returns_an_alert() -> None:
    records = [
        {"source": "linux_auth", "content": FAILED.format(second=index)} for index in range(8)
    ]
    records.append({"source": "auto", "content": SUCCESS})
    response = client.post("/v1/analyze", json={"records": records, "enable_anomaly": False})
    assert response.status_code == 200
    body = response.json()
    assert body["summary"]["parse_errors"] == 0
    assert body["summary"]["anomaly_ran"] is False
    brute = [alert for alert in body["alerts"] if alert["rule_id"] == "ssh-brute-force"]
    assert len(brute) == 1
    assert brute[0]["confirmed_access"] is True
    assert brute[0]["mitre_technique"] == "T1110.001"


def test_empty_batch_has_no_alerts() -> None:
    response = client.post("/v1/analyze", json={"records": [], "enable_anomaly": False})
    assert response.status_code == 200
    assert response.json()["alerts"] == []


def test_invalid_payload_is_rejected() -> None:
    response = client.post("/v1/analyze", json={"records": [{"source": "linux_auth"}]})
    assert response.status_code == 422


def test_auto_source_accepts_an_access_log_line() -> None:
    line = (
        "203.0.113.70 - - [03/Nov/2026:15:03:12 +0000] "
        '"GET /download?file=../../etc/passwd HTTP/1.1" 200 100 "-" "curl/8.5.0"'
    )
    response = client.post(
        "/v1/analyze",
        json={"records": [{"source": "auto", "content": line}], "enable_anomaly": False},
    )
    assert response.status_code == 200
    rules = {alert["rule_id"] for alert in response.json()["alerts"]}
    assert "path-traversal" in rules
