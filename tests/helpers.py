"""Event builders used by the detection tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from socdetect.models import Event


def event_at(
    moment: datetime,
    *,
    source: str = "linux_auth",
    host: str = "lab-ssh",
    event_type: str = "ssh_auth",
    outcome: str = "failure",
    user: str | None = "jsmith",
    src_ip: str | None = "198.51.100.11",
    raw: str | None = None,
    **fields: object,
) -> Event:
    payload: dict[str, object] = {"privileged": False}
    payload.update(fields)
    text = raw or f"{outcome} {user} {src_ip} {moment.isoformat()}"
    return Event(
        timestamp=moment,
        source=source,
        host=host,
        event_type=event_type,
        outcome=outcome,
        user=user,
        src_ip=src_ip,
        raw=text,
        fields=payload,
    )


def at(hour: int, minute: int = 0, second: int = 0, *, day: int = 3) -> datetime:
    base = datetime(2026, 11, day, tzinfo=UTC)
    return base + timedelta(hours=hour, minutes=minute, seconds=second)
