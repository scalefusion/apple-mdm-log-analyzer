"""Reconstruct DDM declaration status from declarative-subsystem logs (spec §7.5).

There is no public CLI that dumps the device's tamper-proof declaration store, so
this is log-derived: it reads `remotemanagementd` / `com.apple.dmd` /
`SoftwareUpdateMacController` activity (the `declaration` predicate category) and
reconstructs which declarations the device processed, their lifecycle state, the
status-report cadence to the server, and any failures.

Like normalize.py / install_log.py, the message phrasing is heuristic and
version-sensitive — keep the patterns here. Message strings validated against
real macOS 15/26 captures and the derflounder/sudoade DDM-logging write-ups.

NOTE: an *invalid declaration* is typically Acknowledged at the MDM check-in and
reported back to the server in a StatusReport, not logged as a device-side error
— so a clean run here does not prove every declaration is valid (see ARCHITECTURE.md).
"""
from __future__ import annotations

import re

from .redact import hash_id, scrub_message
from .schema import Event

# Declaration identifiers, by context (the id is reverse-DNS, often with a UUID
# tail, e.g. com.acme.declaration.<uuid>).
_RE_DECL_UI = re.compile(r"configuration UI for:\s*([A-Za-z0-9][A-Za-z0-9._-]+)")
_RE_DECL_DELETE = re.compile(r"[Mm]arked for deletion:\s*id=['\"]?([A-Za-z0-9][A-Za-z0-9._-]+)")
_RE_DECL_GENERIC = re.compile(r"\b([a-z][A-Za-z0-9_-]*(?:\.[A-Za-z0-9_-]+)*\.declaration\.[A-Za-z0-9._-]+)")

# Status-report cadence to the MDM server (remotemanagementd statusEngine).
_STATUS_PATTERNS = (
    ("status_sent", re.compile(r"Successfully sent status")),
    ("no_status", re.compile(r"no status report to send")),
    ("mdm_response", re.compile(r"Got back from MDM:\s*(\d+)")),
    ("subscriptions_ack", re.compile(r"Acknowledged status subscriptions")),
    ("sync", re.compile(r"Syncing only if needed")),
    ("tokens_saved", re.compile(r"Successfully saved server tokens")),
)

# A declarative line that signals trouble. Conservative to avoid benign mentions:
# `Error Domain=` is a structured NSError (real failure); bare "error" / "could
# not lookup" are too noisy in remotemanagementd and are deliberately excluded.
# Validated against a real DDM-failure capture: catches "Failed to sync with
# conduit: Error Domain=InternalError Code=1", skips "Could not lookup
# ProductVersionExtra" and the benign XPC "invalidated because…" teardown lines.
_RE_FAIL = re.compile(
    r"\b(?:invalid|rejected|failed to|failure|not valid|unable to)\b|Error Domain=", re.I
)


def _decl_type(decl_id: str) -> str:
    """The stable, non-instance prefix of a declaration id (drops the UUID tail)."""
    if ".declaration." in decl_id:
        return decl_id.split(".declaration.", 1)[0] + ".declaration"
    head, _, tail = decl_id.rpartition(".")
    if head and re.fullmatch(r"[0-9A-Fa-f-]{8,}", tail):
        return head
    return decl_id


def _extract_decl_id(message: str) -> str | None:
    for rx in (_RE_DECL_UI, _RE_DECL_DELETE, _RE_DECL_GENERIC):
        m = rx.search(message)
        if m:
            return m.group(1).rstrip(".'\"")
    return None


def _decl_state(message: str) -> str | None:
    low = message.lower()
    if "marked for deletion" in low or "deletion" in low:
        return "removing"
    if "processing complete" in low:
        return "active"
    if any(k in low for k in ("configuration ui", "enqueuing", "fetching declaration", "processing")):
        return "processing"
    return None


def build(events: list[Event], declaration_id: str | None = None) -> dict:
    """Build {declarations, status_reports, failing} from declarative events.

    `declaration_id` (raw or hashed) optionally filters to one declaration.
    Declaration ids are hashed into `declaration_ref`; the non-sensitive type
    prefix is kept for readability.
    """
    target_ref = None
    if declaration_id:
        if declaration_id.startswith("h:"):
            target_ref = declaration_id
        else:
            # Declaration refs are hashed from the id as it appears in the
            # SCRUBBED message, where redact.py has already replaced the
            # instance UUID with its inline hash. Push a caller-supplied raw id
            # through the same scrub so the two hash to the same ref.
            target_ref = hash_id(scrub_message(declaration_id))

    declarations: dict[str, dict] = {}
    status_reports: list[dict] = []
    failing: list[dict] = []

    for e in events:
        msg = e.message or ""

        decl_id = _extract_decl_id(msg)
        ref = hash_id(decl_id) if decl_id else None
        if decl_id:
            d = declarations.get(ref)
            if d is None:
                d = {
                    "declaration_ref": ref,
                    "declaration_type": _decl_type(decl_id),
                    "state": "seen",
                    "first_seen": e.timestamp,
                    "last_seen": e.timestamp,
                }
                declarations[ref] = d
            d["last_seen"] = e.timestamp
            st = _decl_state(msg)
            if st:
                d["state"] = st

        matched_status = False
        for kind, pat in _STATUS_PATTERNS:
            m = pat.search(msg)
            if m:
                rec = {"kind": kind, "timestamp": e.timestamp}
                if kind == "mdm_response":
                    rec["http_status"] = int(m.group(1))
                status_reports.append(rec)
                matched_status = True
                break
        # A status-report line is never a failure — its subscription key-paths can
        # contain words like "failure" (e.g. an update-failure status item), which
        # would otherwise trip the text heuristic below.
        if matched_status:
            continue

        # Failure signal is the message TEXT, not the log level: macOS logs many
        # benign declaration lines (e.g. "Get configuration UI for: …") at error
        # level, so message_type=="error" massively over-reports. Only "fault"
        # (rare, meaningful) is trusted as a level signal.
        if e.message_type == "fault" or _RE_FAIL.search(msg):
            fail = e.to_dict()
            # Keep redaction consistent with `declarations`: the declaration id
            # (with its instance UUID) is an identifier — emit its hashed ref, not
            # the raw id, in the failing message.
            if decl_id and ref:
                fail["message"] = fail["message"].replace(decl_id, ref)
            failing.append(fail)

    decls = sorted(declarations.values(), key=lambda d: d["last_seen"])
    if target_ref is not None:
        decls = [d for d in decls if d["declaration_ref"] == target_ref]

    return {
        "declarations": decls,
        "status_reports": status_reports,
        "failing": failing,
    }
