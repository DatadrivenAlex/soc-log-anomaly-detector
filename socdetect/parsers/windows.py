"""Parser for Windows-style JSON security events (one object per line, or an array)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from socdetect.models import Event, ParseResult

_ADMINS = {"root", "admin", "administrator"}
_LOGON_IDS = {4624, 4625, 4648}
_PRIV_MARKERS = ("SeDebugPrivilege", "SeTcbPrivilege", "SeSecurityPrivilege")


def _parse_time(value: str) -> datetime | None:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC)


def _first(obj: dict[str, Any], *names: str) -> Any:
    lowered = {str(key).lower(): value for key, value in obj.items()}
    for name in names:
        if name.lower() in lowered and lowered[name.lower()] not in (None, ""):
            return lowered[name.lower()]
    return None


def _clean_ip(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if text.lower() in {"", "-", "null", "::1", "local"}:
        return None
    if text.startswith("::ffff:"):
        text = text.split("::ffff:", 1)[1]
    return text


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"true", "yes", "1"}
    return bool(value)


def _event_from_object(obj: Any, raw: str) -> Event | None:
    if not isinstance(obj, dict):
        return None
    time_raw = _first(obj, "TimeCreated", "UtcTime", "timestamp", "@timestamp")
    if not isinstance(time_raw, str):
        return None
    timestamp = _parse_time(time_raw)
    if timestamp is None:
        return None
    event_id_raw = _first(obj, "EventID", "EventId", "event_id")
    try:
        event_id = int(event_id_raw)
    except (TypeError, ValueError):
        return None
    user_raw = _first(obj, "TargetUserName", "SubjectUserName", "user")
    user = str(user_raw) if user_raw else None
    src_ip = _clean_ip(_first(obj, "IpAddress", "SourceIp", "src_ip", "Ip"))
    host_raw = _first(obj, "Computer", "ComputerName", "host")
    host = str(host_raw) if host_raw else "windows"
    logon_type = _first(obj, "LogonType", "logon_type")
    try:
        logon_type_int = int(logon_type) if logon_type is not None else None
    except (TypeError, ValueError):
        logon_type_int = None
    elevated = _as_bool(_first(obj, "ElevatedToken", "elevated"))
    privilege_list = str(_first(obj, "PrivilegeList", "privilege_list") or "")
    privileged = bool(
        elevated
        or event_id == 4672
        or (user and user.lower() in _ADMINS)
        or any(marker in privilege_list for marker in _PRIV_MARKERS)
    )
    if event_id == 4625:
        outcome = "failure"
        event_type = "windows_logon"
    elif event_id in _LOGON_IDS:
        outcome = "success"
        event_type = "windows_logon" if event_id != 4648 else "windows_explicit"
    elif event_id == 4672:
        outcome = "success"
        event_type = "windows_privilege"
    else:
        outcome = "unknown"
        event_type = "windows_event"
    return Event(
        timestamp=timestamp,
        source="windows_json",
        host=host,
        event_type=event_type,
        outcome=outcome,
        user=user,
        src_ip=src_ip,
        raw=raw,
        fields={
            "event_id": event_id,
            "logon_type": logon_type_int,
            "elevated": elevated,
            "privileged": privileged,
            "privilege_list": privilege_list,
            "status": _first(obj, "Status", "SubStatus", "status"),
            "workstation": _first(obj, "WorkstationName", "workstation"),
        },
    )


def parse_windows(text: str, *, year: int = 2026) -> ParseResult:
    """Parse a JSON array or JSON Lines. ``year`` is unused; timestamps are absolute."""
    del year
    stripped = text.strip()
    if not stripped:
        return ParseResult(events=[])
    if stripped.startswith("["):
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            return ParseResult(events=[], errors=1)
        if not isinstance(payload, list):
            return ParseResult(events=[], errors=1)
        events: list[Event] = []
        errors = 0
        for obj in payload:
            raw = json.dumps(obj, separators=(",", ":"), sort_keys=True)
            event = _event_from_object(obj, raw)
            if event is None:
                errors += 1
            else:
                events.append(event)
        return ParseResult(events=events, errors=errors)
    events = []
    errors = 0
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            errors += 1
            continue
        event = _event_from_object(obj, line)
        if event is None:
            errors += 1
        else:
            events.append(event)
    return ParseResult(events=events, errors=errors)
