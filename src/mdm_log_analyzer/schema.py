"""Normalized event + timeline schema (spec section 6)."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional


# Message types as reported by the unified log, normalized to lowercase.
MESSAGE_TYPES = {"default", "info", "debug", "error", "fault"}

# Terminal MDM command statuses.
TERMINAL_STATUSES = {"Acknowledged", "Error", "CommandFormatError"}
NONTERMINAL_STATUSES = {"NotNow", "Idle"}


@dataclass
class Event:
    """A single normalized log event."""

    timestamp: str  # ISO-8601 UTC, e.g. "2026-06-19T21:03:12.481Z"
    process: str
    subsystem: Optional[str]
    category: str  # one of the predicate categories (see predicates.py)
    message_type: str  # default | info | debug | error | fault
    message: str
    command_type: Optional[str] = None
    command_uuid: Optional[str] = None  # hashed unless allowlisted
    command_seq: Optional[str] = None  # per-check-in sequence number (receipt↔result key)
    status: Optional[str] = None  # Acknowledged | Error | NotNow | Idle | None
    error_code: Optional[int] = None
    reason: Optional[str] = None
    device_ref: Optional[str] = None  # hashed serial/UDID
    # App bundle id for managed-app install events (e.g. "com.example.app"). An
    # app identifier, not a device or user identifier, so it is reported as-is —
    # without it an aborted install says "something failed" but not what.
    app_id: Optional[str] = None
    # Managed-app install OPERATION id (hashed), set only on the ManagedApps
    # install-phase lines. Distinct from command_uuid on purpose: an install
    # operation is a consequence of an InstallApplication command, not a command
    # in its own right, and conflating them double-counted one app as two.
    install_uuid: Optional[str] = None
    raw_ref: Optional[str] = None  # pointer back into source, never the raw line

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v is not None}


# Severity levels for Tier-0 findings.
SEVERITIES = {"info", "warn", "error"}

# Evidence is a pointer list, not a data set: a finding over a busy window can
# match thousands of events, and carrying every raw_ref made tier0_findings
# 374 KB of one real bundle. Enough refs to look the finding up, plus the true
# total so nothing about the scale is hidden.
MAX_EVIDENCE = 20


@dataclass
class Finding:
    """A deterministic Tier-0 triage signal over a correlated timeline (spec §4.1).

    A finding is a *structured observation*, not prose diagnosis — the server
    never reasons. `evidence` holds raw_ref pointers, never raw log text.
    """

    code: str  # terminal_error | notnow_loop | no_terminal | missing_push | ...
    severity: str  # info | warn | error
    summary: str  # short, templated description
    evidence: list[str] = field(default_factory=list)  # raw_ref pointers
    confidence: str = "high"  # high | medium | low

    def to_dict(self) -> dict:
        out = {
            "code": self.code,
            "severity": self.severity,
            "summary": self.summary,
            "evidence": self.evidence[:MAX_EVIDENCE],
            "confidence": self.confidence,
        }
        if len(self.evidence) > MAX_EVIDENCE:
            out["evidence_total"] = len(self.evidence)
        return out


@dataclass
class Timeline:
    """A correlated command round-trip (output of correlate_command)."""

    command_uuid: Optional[str]
    command_type: Optional[str]
    outcome: str  # Acknowledged | Error | NotNow | Idle | Unknown
    latency_ms: Optional[int]
    confidence: str  # high | medium | low
    # The per-check-in sequence number. macOS logs no protocol UUID for ordinary
    # commands, so command_uuid is null on most real timelines and the sequence
    # is the only thing that names the round-trip.
    command_seq: Optional[str] = None
    events: list[Event] = field(default_factory=list)
    tier0_findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "command_uuid": self.command_uuid,
            "command_seq": self.command_seq,
            "command_type": self.command_type,
            "outcome": self.outcome,
            "latency_ms": self.latency_ms,
            "confidence": self.confidence,
            "events": [e.to_dict() for e in self.events],
            "tier0_findings": [f.to_dict() for f in self.tier0_findings],
        }
