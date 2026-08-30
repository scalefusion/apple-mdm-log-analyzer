"""Derive device context from mdmclient logs (spec §7.1).

Log-derived orientation for the model: MDM server host, installed-profile count,
enrollment state, and last check-in — extracted from mdmclient activity. (The
`profiles` CLI would give the authoritative profile list, but it is Mac-only and
needs live device state; the counts mdmclient logs are enough to orient.)

Heuristic, version-sensitive phrasing — keep the patterns here. Validated against
real macOS logs:
  Calling MDM_Connect (At login: no) <PushNotification> for: https://<host>/…
  No commands from server: https://<host>/apple/mdm
  [0:MDMDaemon:<…>] Number of <Device> profiles found: 13 (Filtered: 0)
"""
from __future__ import annotations

import re

from .redact import hash_id
from .schema import Event

# MDM server URL — only trust it from MDM check-in context, not any stray URL.
_RE_MDM_HOST = re.compile(r"https?://([A-Za-z0-9.\-]+)")
_MDM_CONTEXT = ("MDM_Connect", "from server", "Server URL")
# "Number of <Device> profiles found: 13" / "<User: 501> profiles found: 0"
_RE_PROFILE_COUNT = re.compile(r"Number of\s+<(?P<scope>[^>]+)>\s+profiles found:\s*(?P<n>\d+)")


def build(events: list[Event]) -> dict:
    """Extract {mdm_server_host, installed_profiles, user_profiles, last_checkin,
    enrollment} from mdmclient events. Server host is hashed (spec §7.1)."""
    host = None
    device_profiles = None
    user_profiles = None

    for e in events:
        msg = e.message or ""
        if host is None and any(k in msg for k in _MDM_CONTEXT):
            m = _RE_MDM_HOST.search(msg)
            if m:
                host = m.group(1)
        pm = _RE_PROFILE_COUNT.search(msg)
        if pm:
            n = int(pm.group("n"))
            scope = pm.group("scope")
            if scope.startswith("Device"):
                device_profiles = n
            elif scope.startswith("User"):
                user_profiles = n

    # Events arrive time-sorted; the last one is the most recent check-in signal.
    last_checkin = events[-1].timestamp if events else None

    return {
        "mdm_server_host": hash_id(host) if host else None,
        "installed_profiles": device_profiles,
        "user_profiles": user_profiles,
        "last_checkin": last_checkin,
        "enrollment": "managed" if host else "unknown",
    }
