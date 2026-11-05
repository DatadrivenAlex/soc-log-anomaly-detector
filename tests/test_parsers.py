"""Parsers for sshd, combined access logs, and Windows JSON."""

from __future__ import annotations

from socdetect.parsers.access import parse_access
from socdetect.parsers.auth import parse_auth
from socdetect.parsers.dispatch import guess_source, parse_content
from socdetect.parsers.windows import parse_windows

FAILED = (
    "Nov  3 11:00:01 lab-ssh sshd[2100]: Failed password for root from 203.0.113.50 port 40001 ssh2"
)
INVALID = (
    "Nov  3 11:00:21 lab-ssh sshd[2101]: Failed password for invalid user admin "
    "from 203.0.113.50 port 40002 ssh2"
)
ACCEPTED = (
    "Nov  3 11:06:00 lab-ssh sshd[2102]: Accepted password for root "
    "from 203.0.113.50 port 40016 ssh2"
)
PUBLICKEY = (
    "Nov  3 14:00:00 lab-ssh sshd[2103]: Accepted publickey for alice "
    "from 198.51.100.30 port 43001 ssh2"
)
INVALID_ONLY = "Nov  3 11:01:00 lab-ssh sshd[2104]: Invalid user ghost from 203.0.113.9 port 22"
CRON = "Nov  3 08:05:00 lab-ssh CRON[99]: pam_unix(cron:session): session opened for user root"
LISTENING = "Nov  3 08:05:01 lab-ssh sshd[140]: Server listening on 0.0.0.0 port 22."

ACCESS = (
    "203.0.113.70 - - [03/Nov/2026:15:03:48 +0000] "
    '"GET /index.php?id=1%20UNION%20SELECT%20username%20FROM%20users HTTP/1.1" '
    '200 2600 "-" "sqlmap/1.8"'
)
TRAVERSAL = (
    "203.0.113.70 - alice [03/Nov/2026:15:03:12 +0000] "
    '"GET /static/%2e%2e/%2e%2e/etc/shadow HTTP/1.1" 400 90 "-" "curl/8.5.0"'
)


def test_failed_password_fields() -> None:
    event = parse_auth(FAILED).events[0]
    assert event.outcome == "failure"
    assert event.user == "root"
    assert event.src_ip == "203.0.113.50"
    assert event.fields["port"] == 40001
    assert event.fields["privileged"] is True
    assert event.fields["invalid_user"] is False
    assert event.timestamp.year == 2026
    assert event.timestamp.hour == 11


def test_invalid_user_failure() -> None:
    event = parse_auth(INVALID).events[0]
    assert event.user == "admin"
    assert event.fields["invalid_user"] is True
    assert event.outcome == "failure"


def test_accepted_password_and_publickey() -> None:
    password = parse_auth(ACCEPTED).events[0]
    key = parse_auth(PUBLICKEY).events[0]
    assert password.outcome == "success"
    assert password.fields["method"] == "password"
    assert key.fields["method"] == "publickey"
    assert key.user == "alice"
    assert key.fields["privileged"] is False


def test_invalid_user_line_without_failed_password() -> None:
    event = parse_auth(INVALID_ONLY).events[0]
    assert event.user == "ghost"
    assert event.fields["invalid_user"] is True
    assert event.fields["port"] == 22


def test_non_sshd_lines_are_skipped_not_errors() -> None:
    parsed = parse_auth(f"{CRON}\n{LISTENING}\n{FAILED}\n")
    assert len(parsed.events) == 1
    assert parsed.errors == 0
    assert parsed.skipped == 2


def test_auth_year_override() -> None:
    event = parse_auth(FAILED, year=2024).events[0]
    assert event.timestamp.year == 2024


def test_auth_preserves_order() -> None:
    parsed = parse_auth(f"{FAILED}\n{ACCEPTED}\n")
    assert [event.outcome for event in parsed.events] == ["failure", "success"]


def test_combined_log_splits_query_and_decodes() -> None:
    event = parse_access(ACCESS).events[0]
    assert event.src_ip == "203.0.113.70"
    assert event.user is None
    assert event.fields["method"] == "GET"
    assert event.fields["path"] == "/index.php"
    assert "UNION SELECT" in event.fields["url"]
    assert event.fields["status_code"] == 200
    assert event.outcome == "success"
    assert event.fields["user_agent"] == "sqlmap/1.8"


def test_traversal_is_decoded_twice() -> None:
    event = parse_access(TRAVERSAL).events[0]
    assert event.user == "alice"
    assert "../" in event.fields["url"]
    assert "/etc/shadow" in event.fields["url"]
    assert event.outcome == "failure"


def test_access_negative_offset_converts_to_utc() -> None:
    line = (
        "198.51.100.11 - - [03/Nov/2026:03:00:00 -0500] "
        '"GET /login HTTP/1.1" 200 10 "-" "Mozilla/5.0"'
    )
    event = parse_access(line).events[0]
    assert event.timestamp.hour == 8
    assert event.timestamp.tzinfo is not None


def test_malformed_access_line_is_an_error() -> None:
    parsed = parse_access("this is not a log\n" + ACCESS)
    assert parsed.errors == 1
    assert len(parsed.events) == 1


def test_windows_failure_and_elevated_success() -> None:
    text = "\n".join(
        [
            '{"TimeCreated":"2026-11-03T02:17:00Z","EventID":4625,"Computer":"DC01",'
            '"TargetUserName":"Administrator","IpAddress":"::ffff:192.0.2.40","LogonType":10}',
            '{"TimeCreated":"2026-11-03T10:30:00Z","EventID":4624,"Computer":"DC01",'
            '"TargetUserName":"Administrator","IpAddress":"198.51.100.31","LogonType":2,'
            '"ElevatedToken":true}',
        ]
    )
    events = parse_windows(text).events
    assert events[0].outcome == "failure"
    assert events[0].src_ip == "192.0.2.40"
    assert events[0].fields["logon_type"] == 10
    assert events[0].fields["privileged"] is True
    assert events[1].outcome == "success"
    assert events[1].fields["elevated"] is True
    assert events[1].event_type == "windows_logon"


def test_windows_json_array_and_privilege_event() -> None:
    text = (
        '[{"TimeCreated":"2026-11-03T10:00:00Z","EventID":4672,'
        '"Computer":"DC01","TargetUserName":"svc-backup","PrivilegeList":"SeDebugPrivilege"}]'
    )
    parsed = parse_windows(text)
    assert parsed.errors == 0
    assert parsed.events[0].event_type == "windows_privilege"
    assert parsed.events[0].fields["privileged"] is True
    assert parsed.events[0].src_ip is None


def test_windows_bad_line_and_missing_time() -> None:
    parsed = parse_windows('{"EventID":4624}\nnot-json\n')
    assert parsed.events == []
    assert parsed.errors == 2


def test_guess_source_from_name_and_body() -> None:
    assert guess_source("auth.log", "") == "linux_auth"
    assert guess_source("nginx-access.log", "") == "web_access"
    assert guess_source("windows.jsonl", "") == "windows_json"
    assert guess_source("manifest.json", "{") == "skip"
    assert guess_source("unknown.log", FAILED) == "linux_auth"
    assert guess_source("unknown.log", ACCESS) == "web_access"


def test_auto_dispatch_parses_each_family() -> None:
    assert parse_content(FAILED, "auto").events[0].source == "linux_auth"
    assert parse_content(ACCESS, "auto").events[0].source == "web_access"
    windows = '{"TimeCreated":"2026-11-03T10:00:00Z","EventID":4624,"TargetUserName":"a"}'
    assert parse_content(windows, "auto").events[0].source == "windows_json"
