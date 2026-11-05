"""Parser for nginx and Apache combined access logs."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta, timezone
from urllib.parse import unquote, urlsplit

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
    r"^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+"
    r'"(?P<method>[A-Z]+)\s+(?P<target>\S+)\s+(?P<proto>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)"\s*$'
)
_TIME = re.compile(
    r"(?P<day>\d{2})/(?P<mon>[A-Za-z]{3})/(?P<year>\d{4}):"
    r"(?P<hms>\d{2}:\d{2}:\d{2})\s+(?P<offset>[+-]\d{4})"
)

_ADMINS = {"root", "admin", "administrator"}


def _timestamp(value: str) -> datetime | None:
    match = _TIME.match(value)
    if match is None:
        return None
    month = _MONTHS.get(match["mon"].title())
    if month is None:
        return None
    hour, minute, second = (int(part) for part in match["hms"].split(":"))
    offset = match["offset"]
    sign = 1 if offset[0] == "+" else -1
    hours = int(offset[1:3])
    minutes = int(offset[3:5])
    tz = timezone(sign * timedelta(hours=hours, minutes=minutes))
    moment = datetime(
        int(match["year"]),
        month,
        int(match["day"]),
        hour,
        minute,
        second,
        tzinfo=tz,
    )
    return moment.astimezone(UTC)


def _decoded_target(target: str) -> tuple[str, str, str]:
    decoded = unquote(unquote(target))
    parts = urlsplit(decoded)
    path = parts.path or "/"
    query = parts.query
    url = f"{path}?{query}" if query else path
    return path, query, url


def parse_access(text: str, *, year: int = 2026) -> ParseResult:
    """Parse combined access-log lines. ``year`` is unused; the timestamp has one."""
    del year
    events: list[Event] = []
    errors = 0
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = _LINE.match(line)
        if match is None:
            errors += 1
            continue
        timestamp = _timestamp(match["ts"])
        if timestamp is None:
            errors += 1
            continue
        status = int(match["status"])
        user = None if match["user"] == "-" else match["user"]
        path, query, url = _decoded_target(match["target"])
        size_raw = match["size"]
        size = int(size_raw) if size_raw.isdigit() else None
        events.append(
            Event(
                timestamp=timestamp,
                source="web_access",
                host="web",
                event_type="http_request",
                outcome="success" if status < 400 else "failure",
                user=user,
                src_ip=match["ip"],
                raw=line,
                fields={
                    "method": match["method"],
                    "path": path,
                    "query": query,
                    "url": url,
                    "status_code": status,
                    "size": size,
                    "user_agent": match["ua"],
                    "referer": match["referer"],
                    "protocol": match["proto"],
                    "privileged": bool(user and user.lower() in _ADMINS),
                },
            )
        )
    return ParseResult(events=events, errors=errors, skipped=0)
