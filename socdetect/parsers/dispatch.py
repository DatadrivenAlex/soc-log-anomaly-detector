"""Pick a parser from a declared source or from the shape of the text."""

from __future__ import annotations

import re

from socdetect.models import ParseResult
from socdetect.parsers.access import parse_access
from socdetect.parsers.auth import parse_auth
from socdetect.parsers.windows import parse_windows

_ACCESS_START = re.compile(r"^\S+\s+\S+\s+\S+\s+\[")


def guess_source(name: str, sample: str) -> str:
    lowered = name.lower()
    if lowered == "manifest.json":
        return "skip"
    if "auth" in lowered:
        return "linux_auth"
    if any(token in lowered for token in ("access", "nginx", "apache")):
        return "web_access"
    if lowered.endswith(".jsonl") or "windows" in lowered:
        return "windows_json"
    line = next((item.strip() for item in sample.splitlines() if item.strip()), "")
    if line.startswith("{") or line.startswith("["):
        return "windows_json"
    if "sshd[" in line:
        return "linux_auth"
    if _ACCESS_START.match(line):
        return "web_access"
    return "auto"


def parse_content(content: str, source: str, *, year: int = 2026) -> ParseResult:
    chosen = source
    if chosen in {"auto", ""}:
        chosen = guess_source("", content)
    if chosen == "linux_auth":
        return parse_auth(content, year=year)
    if chosen == "web_access":
        return parse_access(content, year=year)
    if chosen == "windows_json":
        return parse_windows(content, year=year)
    if chosen == "skip":
        return ParseResult(events=[])
    auth = parse_auth(content, year=year)
    if auth.events:
        return auth
    access = parse_access(content, year=year)
    if access.events:
        return access
    windows = parse_windows(content, year=year)
    if windows.events:
        return windows
    return ParseResult(events=[], errors=1 if content.strip() else 0, skipped=auth.skipped)
