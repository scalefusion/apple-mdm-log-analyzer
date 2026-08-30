"""Parse `log show --style ndjson` output into raw dicts, and normalize the
unified-log timestamp format to ISO-8601 UTC.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Iterator

# Example log show timestamp: "2026-06-19 14:03:12.481920-0700"
_LOG_TS_FORMATS = (
    "%Y-%m-%d %H:%M:%S.%f%z",
    "%Y-%m-%d %H:%M:%S%z",
)


def parse_ndjson(text: str) -> Iterator[dict]:
    """Yield one dict per non-empty line. Bad lines are skipped (logged upstream)."""
    for line in text.splitlines():
        line = line.strip()
        if not line or line in ("[", "]"):  # tolerate stray array brackets
            continue
        if line.endswith(","):
            line = line[:-1]
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            yield obj


def to_iso_utc(raw_ts: str) -> str:
    """Convert a unified-log timestamp string to ISO-8601 UTC with ms precision."""
    if not raw_ts:
        return ""
    for fmt in _LOG_TS_FORMATS:
        try:
            dt = datetime.strptime(raw_ts, fmt)
            break
        except ValueError:
            dt = None
    else:
        dt = None
    if dt is None:
        # Last resort: try fromisoformat (handles already-ISO inputs).
        try:
            dt = datetime.fromisoformat(raw_ts)
        except ValueError:
            return raw_ts  # give back what we got rather than crash
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def epoch_ms(iso_utc: str) -> int | None:
    """Milliseconds since epoch for an ISO-8601 UTC string, or None."""
    try:
        dt = datetime.strptime(iso_utc, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        try:
            dt = datetime.fromisoformat(iso_utc.replace("Z", "+00:00"))
        except ValueError:
            return None
    return int(dt.timestamp() * 1000)
