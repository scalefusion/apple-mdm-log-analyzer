"""Parse `/var/log/install.log` lines into structured install records (spec §7.4).

install.log is a plain syslog-style text file written by installd/installer — NOT
unified-log NDJSON — so it has its own line grammar and lives behind the source
abstraction's `read_install_log()`, not `fetch()`.

Like `normalize.py`, the message classification here is heuristic and
version-sensitive (PackageKit phrasing drifts across macOS builds); keep all
such patterns in this one file. Every emitted message is scrubbed before it
leaves the server.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from typing import Optional

from .parser import epoch_ms, to_iso_utc
from .redact import scrub_message

# 2026-06-19 14:03:10-0700 host installd[321] <Notice>: PackageKit: ...
# Line grammar. Tuned against real macOS 26 (Tahoe) install.log:
#   2026-06-19 17:36:38+05:30 host system_installd[97055]: PackageKit: ...
# The timezone is ISO-colon (+05:30); older builds wrote +0530 — accept both.
# The legacy "<Notice>:" level tag is optional (gone on modern builds).
_RE_LINE = re.compile(
    # Offset seen in three shapes on real logs: -0400, +05:30, and bare -04.
    # The bare form silently dropped 5 of 142 install sessions before it was
    # allowed here.
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}[+-]\d{2}(?::?\d{2})?)\s+"
    r"\S+\s+"  # hostname (dropped)
    r"(?P<proc>[A-Za-z0-9_.-]+)\[(?P<pid>\d+)\]:?\s*"
    r"(?:<(?P<level>\w+)>:?\s*)?"
    r"(?P<msg>.*)$"
)

# Package attribution is deliberately conservative: on modern macOS the only
# reliable package signal in install.log is a reverse-DNS bundle id (>=3 dotted,
# lowercase-led components, e.g. com.apple.MobileDevices, au.csiro.dialog).
# Quoted strings are usually script names ("postinstall") or components, so the
# old `"Name" (bundle)` display-name heuristic over-matched and was dropped.
_RE_BUNDLE = re.compile(r"\b([a-z][a-z0-9]*(?:\.[A-Za-z0-9_-]+){2,})\b")
# exit/exited with code|status N
_RE_EXIT = re.compile(r"\bexit(?:ed)?\s+(?:with\s+)?(?:code|status)\s+(\d+)\b")

# Phase classification by message phrasing (first match wins). `failed` is
# checked first so a *script* line that reports a nonzero exit is classified as a
# failure rather than a plain script step. The failed pattern only matches
# explicit failure phrasing, so it won't capture a normal script/success line.
_PHASE_RULES = (
    # "aborted" included because a failing package script often reports only
    # that: PackageKit's own verdict says "an error occurred while running
    # scripts", while the script's line says what was actually wrong
    # ("serverinfo.plist is not found, hence installation was aborted!"). That
    # line matched the `script` rule and never reached `failures`, so the one
    # actionable message in the capture was absent from the failure list.
    ("failed", re.compile(
        r"Install Failed|installation failed|\baborted\b|\bAborting\b"
        r"|exit(?:ed)? with (?:status|code) [1-9]",
        re.I,
    )),
    ("success", re.compile(r"Install Succeeded|completed successfully|Install completed", re.I)),
    ("begin", re.compile(r"Beginning install|Starting install(?:ation)?|will install", re.I)),
    ("extract", re.compile(r"Extracting", re.I)),
    ("script", re.compile(r"Executing script|package script|pre(?:install|flight)|postinstall|Install Script", re.I)),
)


@dataclass
class InstallRecord:
    timestamp: str
    process: str
    phase: str  # begin | extract | script | success | failed | info
    level: str  # Notice | Error | ... (as logged), normalized to title-case
    package: Optional[str]  # bundle id (stable key)
    package_name: Optional[str]  # human display name, when present
    message: str  # scrubbed
    exit_code: Optional[int] = None

    @property
    def is_failure(self) -> bool:
        return (
            self.phase == "failed"
            or self.level.lower() in ("error", "fault")
            or (self.exit_code is not None and self.exit_code != 0)
        )

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v is not None}


def _classify(message: str) -> str:
    for phase, pattern in _PHASE_RULES:
        if pattern.search(message):
            return phase
    return "info"


# --- install sessions (spec §7.4, activity reporting) ------------------------
#
# A single install spans many lines and several processes. installd /
# system_installd bracket their work with PackageKit markers:
#
#   PackageKit: ----- Begin install -----
#   …
#   PackageKit: ----- End install -----
#
# The lines that announce an outcome carry no package identity at all
# ("Starting installation:", "Displaying 'Install Succeeded' UI."), so naming
# what was installed requires reading the id from elsewhere in the same
# bracket. Validated against a real 214k-line macOS 27 install.log: 142 Begin
# markers, 141 End, 189 id-bearing lines.
_RE_SESSION_BEGIN = re.compile(r"-{2,}\s*Begin install\s*-{2,}")
_RE_SESSION_END = re.compile(r"-{2,}\s*End install\s*-{2,}")
# Strongest signal: PKLeopardPackage/PKBundlePackage <id=…, version=…>
_RE_PKG_ID = re.compile(r"<id=([A-Za-z0-9][A-Za-z0-9._\-]+)")
_RE_PKG_VERSION = re.compile(r"\bversion=([A-Za-z0-9][A-Za-z0-9._\-]*)")
# Fallbacks, in descending confidence.
_RE_RECEIPT = re.compile(r"receipt for ([A-Za-z0-9][A-Za-z0-9._\-]+)")
_RE_PKG_FILE = re.compile(r"file://\S*/([^/\s]+\.pkg)")
# PackageKit names the failing package explicitly. Preferred over the generic
# reverse-DNS scan, which picked the FIRST such token in the line — and on a
# managed-app failure that is the App Store cache path
# (…/C/com.apple.appstore/<uuid>/…), so the finding named com.apple.appstore
# instead of the package that actually failed.
_RE_PK_PKG_IDENT = re.compile(
    r"PKInstallPackageIdentifier\s*=\s*\"?([A-Za-z0-9][A-Za-z0-9._\-]+)"
)
_RE_ELAPSED = re.compile(r"([0-9.]+)s elapsed install time")


@dataclass
class InstallSession:
    """One bracketed install, successful or not — the unit an activity report
    talks about ("Chrome installed at 14:03, took 24s")."""

    package: Optional[str]  # reverse-DNS id where derivable
    version: Optional[str]
    outcome: str  # success | failed | incomplete
    started: str
    ended: Optional[str]
    duration_ms: Optional[int]
    process: str
    exit_codes: list  # nonzero script exits seen in the bracket
    failure: Optional[str]  # scrubbed message of the first failing line
    record_count: int
    # Timestamp of the last line inside the bracket. An interrupted session has
    # no `ended`, so without this its extent was unknowable and any summary had
    # to fall back to `started` — which put the end of the span BEFORE the
    # failure that closed the install.
    last_record: Optional[str] = None

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v not in (None, [])}


def _session_package(blob: str) -> tuple[Optional[str], Optional[str]]:
    """Best available (package, version) for one session's text."""
    m = _RE_PKG_ID.search(blob)
    if m:
        vm = _RE_PKG_VERSION.search(blob[m.end() : m.end() + 200])
        return m.group(1), (vm.group(1) if vm else None)
    m = _RE_RECEIPT.search(blob)
    if m:
        return m.group(1), None
    m = _RE_PKG_FILE.search(blob)
    if m:
        return m.group(1), None
    return None, None


def parse_sessions(text: str) -> list[InstallSession]:
    """Group install.log into bracketed install sessions with an outcome.

    Sessions are keyed by (process, pid) so concurrent installers don't merge.
    A bracket left open at EOF (or interrupted) is reported as `incomplete`
    rather than silently dropped — an install that never finished is exactly
    the kind of thing a report should show.
    """
    open_sessions: dict = {}
    done: list[InstallSession] = []

    def close(key, session, end_ts, outcome):
        # An unclosed bracket that recorded a failure did not merely fail to
        # finish — it failed. installd tears down without an End marker when a
        # package script aborts, so reporting that as "incomplete" understated a
        # definite failure and kept it out of by_outcome["failed"].
        if outcome == "incomplete" and (session["failure"] or session["exits"]):
            outcome = "failed"
        pkg, ver = _session_package(session["blob"])
        start_ms = epoch_ms(session["started"])
        end_ms = epoch_ms(end_ts) if end_ts else None
        done.append(
            InstallSession(
                package=scrub_message(pkg) if pkg else None,
                version=ver,
                outcome=outcome,
                started=session["started"],
                ended=end_ts,
                duration_ms=(end_ms - start_ms) if (start_ms and end_ms) else None,
                process=key[0],
                exit_codes=session["exits"],
                failure=session["failure"],
                record_count=session["count"],
                last_record=session.get("last_ts") or session["started"],
            )
        )

    for m, message, continuation in _parse_lines(text):
        proc, pid = m.group("proc"), m.group("pid")
        ts = to_iso_utc(m.group("ts"))
        key = (proc, pid)
        blob = message + ("\n" + continuation if continuation else "")

        if _RE_SESSION_BEGIN.search(message):
            # A second Begin without an End means the previous one never closed.
            if key in open_sessions:
                close(key, open_sessions.pop(key), None, "incomplete")
            open_sessions[key] = {
                "started": ts, "blob": blob, "exits": [], "failure": None,
                "count": 1, "last_ts": ts,
            }
            continue

        session = open_sessions.get(key)
        if session is None:
            continue  # line outside any bracket

        session["blob"] += "\n" + blob
        session["count"] += 1
        session["last_ts"] = ts

        exit_m = _RE_EXIT.search(message)
        if exit_m and int(exit_m.group(1)) != 0:
            session["exits"].append(int(exit_m.group(1)))
        if session["failure"] is None and _classify(message) == "failed":
            session["failure"] = scrub_message(message)

        if _RE_SESSION_END.search(message):
            outcome = "failed" if (session["failure"] or session["exits"]) else "success"
            close(key, open_sessions.pop(key), ts, outcome)

    for key, session in list(open_sessions.items()):
        close(key, session, None, "incomplete")

    done.sort(key=lambda s: s.started)
    return done


def _parse_lines(text: str):
    """Yield (match, message, continuation) per timestamped install.log line.

    PackageKit wraps its package list across lines, and the continuation lines
    carry no timestamp:

        PackageKit: packages=(
            "PKLeopardPackage <id=com.apple.pkg.XProtect…, version=5354.…>"
        )

    A timestamp-anchored parser drops them, which is why every install session
    came out with package=None despite the id being right there. They are
    attached to the record they continue so session attribution can read them.
    """
    pending: list = []  # [match, message, continuation lines]
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        m = _RE_LINE.match(line)
        if m:
            if pending:
                yield pending[0], pending[1], "\n".join(pending[2])
            pending = [m, m.group("msg") or "", []]
        elif pending and (raw.startswith((" ", "\t")) or line.startswith(('"', ")"))):
            pending[2].append(line)
    if pending:
        yield pending[0], pending[1], "\n".join(pending[2])


def parse(text: str) -> list[InstallRecord]:
    """Parse install.log text into ordered InstallRecords. Unmatched lines skipped."""
    records: list[InstallRecord] = []
    for m, message, _continuation in _parse_lines(text):

        # PackageKit's own identifier wins over the generic reverse-DNS scan.
        ident_m = _RE_PK_PKG_IDENT.search(message)
        if ident_m:
            bundle = ident_m.group(1)
        else:
            bundle_m = _RE_BUNDLE.search(message)
            bundle = bundle_m.group(1) if bundle_m else None

        exit_m = _RE_EXIT.search(message)
        exit_code = int(exit_m.group(1)) if exit_m else None

        records.append(
            InstallRecord(
                timestamp=to_iso_utc(m.group("ts")),
                process=m.group("proc"),
                phase=_classify(message),
                level=(m.group("level") or "Notice").title(),
                # Scrub the bundle id too: it is an analytic key, but scrubbing is
                # idempotent for clean reverse-DNS ids and guards against an id
                # that happens to embed a serial/email-shaped token.
                package=scrub_message(bundle) if bundle else None,
                package_name=None,  # display-name heuristic dropped (see _RE_BUNDLE)
                message=scrub_message(message),
                exit_code=exit_code,
            )
        )
    return records
