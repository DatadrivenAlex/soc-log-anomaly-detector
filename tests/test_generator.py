"""Seeded generator: stable attacks, deterministic files."""

import json

from socdetect.generate import (
    ALICE_IP,
    BRUTE_IP,
    OFFHOURS_IP,
    SCAN_IP,
    SPRAY_IP,
    TRAVEL_IP,
    render_logs,
    write_logs,
)


def test_same_seed_is_byte_stable() -> None:
    assert render_logs(42) == render_logs(42)


def test_seed_changes_benign_noise_but_keeps_attacks() -> None:
    first = render_logs(42)
    second = render_logs(7)
    assert first["auth.log"] != second["auth.log"]
    for logs in (first, second):
        assert logs["auth.log"].count(f"from {BRUTE_IP} ") >= 16
        assert logs["auth.log"].count(f"from {SPRAY_IP} ") == 12
        assert f"from {ALICE_IP} " in logs["auth.log"]
        assert f"from {TRAVEL_IP} " in logs["auth.log"]
        assert "UNION%20SELECT" in logs["access.log"]
        assert "/etc/shadow" in logs["access.log"] or "%2e%2e" in logs["access.log"]
        assert OFFHOURS_IP in logs["windows.jsonl"]
        assert "nikto" in logs["access.log"]


def test_manifest_lists_every_scenario() -> None:
    manifest = json.loads(render_logs(42)["manifest.json"])
    assert manifest["seed"] == 42
    assert {item["id"] for item in manifest["scenarios"]} == {
        "ssh-brute-force",
        "password-spray",
        "impossible-travel",
        "web-scanning",
        "path-traversal",
        "sql-injection",
        "off-hours-admin",
    }


def test_write_logs_creates_the_four_files(tmp_path) -> None:
    write_logs(tmp_path, seed=3)
    names = sorted(path.name for path in tmp_path.iterdir())
    assert names == ["access.log", "auth.log", "manifest.json", "windows.jsonl"]
    assert SCAN_IP in (tmp_path / "access.log").read_text(encoding="utf-8")
