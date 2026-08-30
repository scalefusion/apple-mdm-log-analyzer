"""Tier-0 deterministic triage (spec §4.1).

Pure, stdlib-only rules over an already-correlated timeline. This is the
strongest privacy tier: nothing is ever inferred off-device. The server still
does not *diagnose* in prose — it emits structured `Finding` signals (codes +
short templated summaries + raw_ref evidence) for the client/model to reason
over. No network, no raw log text.
"""
from __future__ import annotations

from typing import Optional

from .schema import Event, Finding, TERMINAL_STATUSES

# A command that takes longer than this to reach a terminal status is worth
# flagging (push/scheduling throttling, asset download, device contention).
HIGH_LATENCY_MS = 60_000


def _refs(events: list[Event]) -> list[str]:
    return [e.raw_ref for e in events if e.raw_ref]


# Lines that carry the authoritative abort reason. PackageKit reports the same
# failure twice with different wording — an App Store notification says
# "Authorisation is required to install the packages" while mdmclient's own
# abort says "Package signature cannot be verified". The mdmclient line is the
# one that names the actual cause, so it wins.
_ABORT_MARKERS = ("Aborting app install", "Result: <Abort>")


def _authoritative_reason(events: list[Event]) -> str:
    for e in events:
        if e.reason and any(m in (e.message or "") for m in _ABORT_MARKERS):
            return e.reason
    for e in events:
        if e.reason:
            return e.reason
    return "unspecified"


def _abort_finding(group: list[Event], apps: list[str]) -> Finding:
    reason = _authoritative_reason(group)
    codes = sorted({e.error_code for e in group if e.error_code is not None})
    who = f" for {', '.join(apps)}" if apps else ""
    code = f" (error_code {codes[0]})" if len(codes) == 1 else ""
    return Finding(
        code="app_install_abort",
        severity="error",
        summary=f"Managed app install aborted{who}: {reason}{code}.",
        evidence=_refs(group),
        confidence="high",
    )


def triage_app_installs(events: list[Event]) -> list[Finding]:
    """Findings for managed-app installs that aborted (spec §4.1).

    Separate from `triage_timeline` because these failures do not live in a
    correlated round-trip: the InstallApplication command is Acknowledged and the
    install fails afterwards inside PackageKit. Nothing in install.log records it
    either — installd never opens a session for a package it rejects up front —
    so without this rule an aborted app install is invisible to every tool here.
    """
    aborted = [
        e
        for e in events
        if e.status == "Error" and e.command_type == "InstallApplication"
    ]
    if not aborted:
        return []

    # One abort is logged across several phase lines, and only one of them names
    # the app, so the phases must stay grouped together rather than split by
    # reason or by which line happened to carry the bundle id.
    apps = sorted({e.app_id for e in aborted if e.app_id})
    if len(apps) <= 1:
        return [_abort_finding(aborted, apps)]

    # More than one app failed in the window: group per app, and report the
    # phase lines that name no app separately rather than guessing an owner.
    findings: list[Finding] = []
    for app in apps:
        findings.append(
            _abort_finding([e for e in aborted if e.app_id == app], [app])
        )
    unattributed = [e for e in aborted if not e.app_id]
    if unattributed:
        findings.append(_abort_finding(unattributed, []))
    return findings


def triage_timeline(
    events: list[Event],
    outcome: str,
    latency_ms: Optional[int],
) -> list[Finding]:
    """Return deterministic Tier-0 findings for one correlated round-trip."""
    findings: list[Finding] = []
    if not events:
        return findings

    errors = [e for e in events if e.status == "Error"]
    notnows = [e for e in events if e.status == "NotNow"]
    has_terminal = any(e.status in TERMINAL_STATUSES for e in events)
    has_push = any(e.category == "push" for e in events)
    has_mdm = any(e.category in ("mdm_command", "ddm") for e in events)
    downloads = [e for e in events if e.category == "asset_download"]
    masked = [e for e in events if "<private>" in (e.message or "")]

    # terminal_error — a failed command, with the reason when the log gives one.
    if errors:
        last = errors[-1]
        # The status bracket that marks the failure carries no error code; the
        # ErrorChain line a few milliseconds later carries both code and
        # description. Look across the timeline rather than only at the terminal
        # event, or the finding says "terminated with Error" and stops there —
        # which is the count, not the diagnosis.
        detail = next(
            (e for e in reversed(events) if e.error_code is not None and e.reason),
            None,
        )
        if detail is None:
            detail = next(
                (e for e in reversed(errors) if e.error_code is not None), last
            )
        code = (
            f" (error_code {detail.error_code})"
            if detail.error_code is not None
            else ""
        )
        why = f" {detail.reason}" if detail is not None and detail.reason else ""
        findings.append(
            Finding(
                code="terminal_error",
                severity="error",
                summary=f"Command terminated with Error{code}.{why}",
                evidence=_refs(errors),
                confidence="high",
            )
        )

    # notnow_loop — commands the device declined. Counted per COMMAND, not per
    # log line: mdmclient logs the NotNow bracket on both the outgoing PUT and
    # the response, so a single deferral produced two events and "returned
    # NotNow 2 times" for one declined command. And it no longer claims the
    # command resolved — the old wording said "before resolving" unconditionally,
    # which read as reassurance about commands that never came back at all.
    deferred_seqs = {e.command_seq for e in notnows if e.command_seq}
    deferred_count = len(deferred_seqs) or len(notnows)
    if deferred_count >= 2:
        tail = (
            " All reached a terminal status afterwards."
            if has_terminal
            else " None reached a terminal status in this window."
        )
        findings.append(
            Finding(
                code="notnow_loop",
                severity="warn",
                summary=f"{deferred_count} command(s) declined with NotNow.{tail}",
                evidence=_refs(notnows),
                confidence="high",
            )
        )

    # no_terminal — command seen but never acknowledged or errored (stuck/pending).
    if has_mdm and not has_terminal:
        findings.append(
            Finding(
                code="no_terminal",
                severity="warn",
                summary="Command was received but reached no terminal status "
                "(Acknowledged/Error) in the window — pending or stuck.",
                evidence=_refs([e for e in events if e.category in ("mdm_command", "ddm")]),
                confidence="medium",
            )
        )

    # missing_push — MDM activity with no APNs wake nearby; possible push gap.
    if has_mdm and not has_push:
        findings.append(
            Finding(
                code="missing_push",
                severity="info",
                summary="No APNs push (apsd) event correlated with this command — "
                "push delivery or capture gap.",
                evidence=[],
                confidence="low",
            )
        )

    # high_latency — slow round-trip.
    if latency_ms is not None and latency_ms > HIGH_LATENCY_MS:
        findings.append(
            Finding(
                code="high_latency",
                severity="warn",
                summary=f"Round-trip took {latency_ms} ms (> {HIGH_LATENCY_MS} ms).",
                evidence=[],
                confidence="high",
            )
        )

    # download_stall — an asset download was in flight but the command did not
    # reach Acknowledged; the install may have failed mid-download.
    if downloads and outcome != "Acknowledged":
        findings.append(
            Finding(
                code="download_stall",
                severity="info",
                summary="Asset download was in progress but the command did not "
                "complete successfully.",
                evidence=_refs(downloads),
                confidence="medium",
            )
        )

    # private_data_masked — analysis is degraded without the §4.5 logging profile.
    if masked:
        findings.append(
            Finding(
                code="private_data_masked",
                severity="warn",
                summary="Log messages contain <private> fields; deploy the MDM "
                "private-data logging profile (spec §4.5) for full detail.",
                evidence=_refs(masked),
                confidence="high",
            )
        )

    return findings
