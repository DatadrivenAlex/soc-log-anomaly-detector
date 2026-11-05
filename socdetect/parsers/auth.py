"""Parser for classic syslog sshd lines from Linux auth.log."""

from __future__ import annotations

import re
from datetime import UTC, datetime

from socdetect.models import Event, ParseResult

_MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}

_LINE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<hms>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+(?P<msg>.*)$"
)
_FAILED = re.compile(
    r"^Failed password for (?P<invalid>invalid user )?(?P<user>\S+) from "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port (?P<port>\d+)"
)
_ACCEPTED = re.compile(
    r"^Accepted (?P<method>\S+) for (?P<user>\S+) from "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port (?P<port>\d+)"
)
_INVALID = re.compile(
    r"^Invalid user (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
    r"(?: port (?P<port>\d+))?"
)

_ADMINS = {"root", "admin", "administrator"}


def _timestamp(mon: str, day: str, hms: str, year: int) -> datetime | None:
    month = _MONTHS.get(mon)
    if month is None:
        return None
    hour, minute, second = (int(part) for part in hms.split(":"))
    return datetime(year, month, int(day), hour, minute, second, tzinfo=UTC)


def _privileged(user: str) -> bool:
    return user.lower() in _ADMINS


def parse_auth(text: str, *, year: int = 2026) -> ParseResult:
    """Parse sshd authentication lines. Other syslog lines are skipped."""
    events: list[Event] = []
    skipped = 0
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        header = _LINE.match(line)
        if header is None:
            skipped += 1
            continue
        timestamp = _timestamp(header["mon"], header["day"], header["hms"], year)
        if timestamp is None:
            skipped += 1
            continue
        message = header["msg"]
        host = header["host"]
        failed = _FAILED.match(message)
        accepted = _ACCEPTED.match(message)
        invalid = _INVALID.match(message)
        if failed:
            user = failed["user"]
            events.append(
                Event(
                    timestamp=timestamp,
                    source="linux_auth",
                    host=host,
                    event_type="ssh_auth",
                    outcome="failure",
                    user=user,
                    src_ip=failed["ip"],
                    raw=line,
                    fields={
                        "port": int(failed["port"]),
                        "method": "password",
                        "invalid_user": bool(failed["invalid"]),
                        "privileged": _privileged(user),
                        "pid": int(header["pid"]),
                    },
                )
            )
        elif accepted:
            user = accepted["user"]
            events.append(
                Event(
                    timestamp=timestamp,
                    source="linux_auth",
                    host=host,
                    event_type="ssh_auth",
                    outcome="success",
                    user=user,
                    src_ip=accepted["ip"],
                    raw=line,
                    fields={
                        "port": int(accepted["port"]),
                        "method": accepted["method"],
                        "invalid_user": False,
                        "privileged": _privileged(user),
                        "pid": int(header["pid"]),
                    },
                )
            )
        elif invalid:
            user = invalid["user"]
            port = int(invalid["port"]) if invalid["port"] else None
            events.append(
                Event(
                    timestamp=timestamp,
                    source="linux_auth",
                    host=host,
                    event_type="ssh_auth",
                    outcome="failure",
                    user=user,
                    src_ip=invalid["ip"],
                    raw=line,
                    fields={
                        "port": port,
                        "method": "password",
                        "invalid_user": True,
                        "privileged": _privileged(user),
                        "pid": int(header["pid"]),
                    },
                )
            )
        else:
            skipped += 1
    return ParseResult(events=events, errors=0, skipped=skipped)
