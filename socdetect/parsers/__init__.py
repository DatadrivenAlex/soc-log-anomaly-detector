"""Log parsers that emit a single normalized event shape."""

from socdetect.parsers.access import parse_access
from socdetect.parsers.auth import parse_auth
from socdetect.parsers.dispatch import guess_source, parse_content
from socdetect.parsers.windows import parse_windows

__all__ = [
    "guess_source",
    "parse_access",
    "parse_auth",
    "parse_content",
    "parse_windows",
]
