"""Seeded synthetic logs with a fixed set of injected attacks.

Benign noise changes with the seed (ports, minute jitter, which safe paths a
user hits). The attack timelines do not, so every seed still contains the same
scenarios: SSH brute force, password spraying, impossible travel, web
scanning with traversal and SQL injection, and an off-hours administrator logon.
"""

from __future__ import annotations

import json
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path

ANCHOR = datetime(2026, 11, 3, 0, 0, tzinfo=UTC)

BENIGN_USERS = [
    "jsmith",
    "mlee",
    "rpatel",
    "dkim",
    "cbrown",
    "lgarcia",
    "nwang",
    "sivanov",
    "hnguyen",
    "ebrown",
    "kchen",
    "tdavis",
]
SAFE_PATHS = [
    "/",
    "/login",
    "/dashboard",
    "/assets/app.js",
    "/api/health",
    "/reports",
    "/static/style.css",
    "/favicon.ico",
]
SAFE_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15",
]
SCAN_PATHS = [
    "/.env",
    "/.git/config",
    "/admin",
    "/wp-login.php",
    "/phpmyadmin",
    "/server-status",
    "/actuator/health",
    "/backup.zip",
    "/config.php",
    "/console",
    "/debug/vars",
    "/manager/html",
    "/owa/auth.owa",
    "/remote/login",
    "/boaform/admin/formLogin",
    "/dns-query",
    "/cgi-bin/luci",
    "/solr/admin/info/system",
]

BRUTE_IP = "203.0.113.50"
SPRAY_IP = "203.0.113.60"
SCAN_IP = "203.0.113.70"
TRAVEL_IP = "203.0.113.80"
ALICE_IP = "198.51.100.30"
OFFHOURS_IP = "192.0.2.40"
ADMIN_IP = "198.51.100.31"


def _syslog(moment: datetime, host: str, pid: int, message: str) -> str:
    stamp = f"{moment.strftime('%b')} {moment.day:2d} {moment.strftime('%H:%M:%S')}"
    return f"{stamp} {host} sshd[{pid}]: {message}"


def _failed(moment: datetime, user: str, ip: str, port: int, *, invalid: bool = False) -> str:
    account = f"invalid user {user}" if invalid else user
    return _syslog(
        moment,
        "lab-ssh",
        2000 + (port % 7000),
        f"Failed password for {account} from {ip} port {port} ssh2",
    )


def _accepted(moment: datetime, user: str, ip: str, port: int, method: str = "password") -> str:
    return _syslog(
        moment,
        "lab-ssh",
        3000 + (port % 5000),
        f"Accepted {method} for {user} from {ip} port {port} ssh2",
    )


def _access(
    moment: datetime,
    ip: str,
    method: str,
    target: str,
    status: int,
    user_agent: str,
    user: str = "-",
    size: int = 420,
) -> str:
    when = moment.strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - {user} [{when}] "{method} {target} HTTP/1.1" {status} {size} "-" "{user_agent}"'


def _windows(
    moment: datetime,
    event_id: int,
    user: str,
    ip: str,
    *,
    logon_type: int,
    elevated: bool,
    computer: str = "DC01",
) -> str:
    payload = {
        "TimeCreated": moment.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "EventID": event_id,
        "Computer": computer,
        "TargetUserName": user,
        "IpAddress": ip,
        "LogonType": logon_type,
        "ElevatedToken": elevated,
    }
    return json.dumps(payload, separators=(", ", ": "))


def render_logs(seed: int = 42) -> dict[str, str]:
    rng = random.Random(seed)
    auth: list[str] = [
        "Nov  3 08:05:00 lab-ssh CRON[99]: pam_unix(cron:session): session opened for user root",
        "Nov  3 08:05:01 lab-ssh sshd[140]: Server listening on 0.0.0.0 port 22.",
    ]
    access: list[str] = []
    windows: list[str] = []

    for index, user in enumerate(BENIGN_USERS):
        ip = f"198.51.100.{11 + index}"
        fail_at = ANCHOR.replace(hour=9, minute=index % 20) + timedelta(minutes=rng.randint(0, 4))
        auth.append(_failed(fail_at, user, ip, rng.randint(22000, 42000)))
        for slot in range(4):
            success_at = ANCHOR.replace(hour=9, minute=30) + timedelta(
                hours=slot * 2, minutes=index + rng.randint(0, 3)
            )
            method = "publickey" if slot % 2 == 0 else "password"
            auth.append(_accepted(success_at, user, ip, rng.randint(22000, 42000), method))
        paths = rng.sample(SAFE_PATHS, 4)
        agent = rng.choice(SAFE_AGENTS)
        for slot, path in enumerate(paths):
            when = ANCHOR.replace(hour=10, minute=0) + timedelta(
                hours=slot, minutes=index * 2 + rng.randint(0, 2)
            )
            access.append(_access(when, ip, "GET", path, 200, agent, user=user, size=1800 + slot))
        windows.append(
            _windows(
                ANCHOR.replace(hour=9, minute=15) + timedelta(minutes=index),
                4624,
                user,
                ip,
                logon_type=2,
                elevated=False,
                computer=f"WS{index + 1:02d}",
            )
        )

    # One ordinary account signs in before the office opens. Not privileged.
    auth.append(_accepted(ANCHOR.replace(hour=3, minute=10), "jsmith", "198.51.100.11", 41001))

    # SSH brute force against root, then one accepted password.
    for attempt in range(15):
        when = ANCHOR.replace(hour=11, minute=0, second=0) + timedelta(seconds=20 * attempt)
        auth.append(_failed(when, "root", BRUTE_IP, 40000 + attempt))
    auth.append(_accepted(ANCHOR.replace(hour=11, minute=6, second=0), "root", BRUTE_IP, 40016))

    # Password spray: one failure per account, many accounts, one source.
    for attempt in range(12):
        when = ANCHOR.replace(hour=12, minute=0) + timedelta(seconds=30 * attempt)
        auth.append(_failed(when, f"svc{attempt + 1:02d}", SPRAY_IP, 41000 + attempt, invalid=True))

    # Alice works from London, then authenticates from Singapore 22 minutes later.
    auth.append(_accepted(ANCHOR.replace(hour=14, minute=0), "alice", ALICE_IP, 43001, "publickey"))
    auth.append(_accepted(ANCHOR.replace(hour=14, minute=8), "alice", ALICE_IP, 43002, "publickey"))
    auth.append(
        _accepted(ANCHOR.replace(hour=14, minute=22), "alice", TRAVEL_IP, 43003, "password")
    )
    access.append(
        _access(
            ANCHOR.replace(hour=14, minute=2),
            ALICE_IP,
            "GET",
            "/dashboard",
            200,
            SAFE_AGENTS[0],
            user="alice",
        )
    )
    access.append(
        _access(
            ANCHOR.replace(hour=14, minute=4),
            ALICE_IP,
            "GET",
            "/reports",
            200,
            SAFE_AGENTS[0],
            user="alice",
        )
    )

    # Web scan, plus path traversal and SQL injection payloads.
    for slot, path in enumerate(SCAN_PATHS):
        when = ANCHOR.replace(hour=15, minute=0, second=0) + timedelta(seconds=8 * slot)
        access.append(_access(when, SCAN_IP, "GET", path, 404, "nikto/2.5.0", size=180))
    access.append(
        _access(
            ANCHOR.replace(hour=15, minute=3, second=0),
            SCAN_IP,
            "GET",
            "/static/%2e%2e/%2e%2e/etc/shadow",
            400,
            "curl/8.5.0",
            size=90,
        )
    )
    access.append(
        _access(
            ANCHOR.replace(hour=15, minute=3, second=12),
            SCAN_IP,
            "GET",
            "/download?file=../../etc/passwd",
            200,
            "curl/8.5.0",
            size=1400,
        )
    )
    access.append(
        _access(
            ANCHOR.replace(hour=15, minute=3, second=30),
            SCAN_IP,
            "GET",
            "/search?q=%27%20OR%201%3D1--",
            500,
            "sqlmap/1.8",
            size=220,
        )
    )
    access.append(
        _access(
            ANCHOR.replace(hour=15, minute=3, second=48),
            SCAN_IP,
            "GET",
            "/index.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users",
            200,
            "sqlmap/1.8",
            size=2600,
        )
    )

    # Daytime domain admin, then the same account over RDP before office hours.
    for slot in range(4):
        windows.append(
            _windows(
                ANCHOR.replace(hour=10, minute=30) + timedelta(minutes=15 * slot),
                4624,
                "Administrator",
                ADMIN_IP,
                logon_type=2,
                elevated=True,
            )
        )
    windows.append(
        _windows(
            ANCHOR.replace(hour=2, minute=17),
            4624,
            "Administrator",
            OFFHOURS_IP,
            logon_type=10,
            elevated=True,
        )
    )

    manifest = {
        "seed": seed,
        "anchor": ANCHOR.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "note": (
            "Attack rows are fixed. Benign rows vary with the seed but stay under rule thresholds."
        ),
        "scenarios": [
            {
                "id": "ssh-brute-force",
                "src_ip": BRUTE_IP,
                "user": "root",
                "failures": 15,
                "success": True,
            },
            {
                "id": "password-spray",
                "src_ip": SPRAY_IP,
                "users": [f"svc{i:02d}" for i in range(1, 13)],
            },
            {
                "id": "impossible-travel",
                "user": "alice",
                "from_ip": ALICE_IP,
                "to_ip": TRAVEL_IP,
                "from_city": "London",
                "to_city": "Singapore",
            },
            {
                "id": "web-scanning",
                "src_ip": SCAN_IP,
                "probes": len(SCAN_PATHS),
            },
            {"id": "path-traversal", "src_ip": SCAN_IP},
            {"id": "sql-injection", "src_ip": SCAN_IP},
            {
                "id": "off-hours-admin",
                "user": "Administrator",
                "src_ip": OFFHOURS_IP,
                "at": "2026-11-03T02:17:00Z",
                "logon_type": 10,
            },
        ],
    }
    return {
        "auth.log": "\n".join(auth) + "\n",
        "access.log": "\n".join(access) + "\n",
        "windows.jsonl": "\n".join(windows) + "\n",
        "manifest.json": json.dumps(manifest, indent=2) + "\n",
    }


def write_logs(directory: Path, seed: int = 42) -> dict[str, str]:
    directory.mkdir(parents=True, exist_ok=True)
    files = render_logs(seed)
    for name, content in files.items():
        (directory / name).write_text(content, encoding="utf-8")
    return files
