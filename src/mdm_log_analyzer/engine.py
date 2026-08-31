"""Engine: ties source + predicate + parse + normalize + redact together, and
implements the two Phase-1 operations (spec sections 7.2 and 7.3).
"""
from __future__ import annotations

import re
from typing import Optional

from . import ddm_status, device_context, install_log, predicates
from .parser import epoch_ms, parse_ndjson
from .normalize import normalize
from .redact import hash_id
from .schema import Event, Finding, MAX_EVIDENCE, Timeline
from .triage import triage_app_installs, triage_timeline

# Categories pulled when correlating a single command round-trip.
_CORRELATION_CATEGORIES = ("mdm_command", "ddm", "push", "asset_download", "scheduling")
_CONTEXT_PAD_MS = 60_000  # include push/download context within 60s of the match
_MAX_PHASES = 500  # cap install.log per-line records in a response (see get_install_log)
# query_events capped the event COUNT but never the byte size, and it is the one
# response path with no byte discipline — every other list here is capped
# because of the 1 MB MCP limit. At the 5000-event ceiling with realistic ~3 KB
# payload-dump lines that is a 15 MB response the transport refuses outright.
# Two independent limits: clip an individual message, then drop events (oldest
# first, keeping the most recent) until the whole response fits.
_MAX_EVENT_MESSAGE = 2000
_MAX_RESPONSE_BYTES = 900_000


def _collect(
    source,
    category: str,
    last: str,
    level: Optional[str],
    cache: Optional[dict] = None,
) -> list[Event]:
    """Fetch + normalize one category. `cache` memoizes within ONE request.

    build_incident_bundle collects several categories and then correlates up to
    _MAX_TIMELINES round-trips, each of which re-reads every correlation
    category. Without the cache that is a fresh fetch + parse per correlation —
    on a real 205 MB bundle (215k events, 197k of them apsd) the call did not
    finish in two minutes. The cache is request-scoped and passed in explicitly,
    never module state: the server is stateless and must not hold a corpus
    between calls (spec §4.4).
    """
    spec = predicates.resolve(category, source.os_major)
    use_level = level or spec["level"]
    key = (category, last, use_level)
    if cache is not None and key in cache:
        return cache[key]
    raw_text = source.fetch(spec["predicate"], last, use_level)
    events = [
        normalize(raw, category, idx)
        for idx, raw in enumerate(parse_ndjson(raw_text))
    ]
    events.sort(key=lambda e: e.timestamp)
    if cache is not None:
        cache[key] = events
    return events


def query_events(
    source,
    category: str,
    last: str = "30m",
    level: Optional[str] = None,
    limit: int = 500,
) -> dict:
    spec = predicates.resolve(category, source.os_major)
    events = _collect(source, category, last, level)
    truncated = len(events) > limit
    # Keep the NEWEST `limit` events, not the oldest. Events are sorted
    # ascending, so `events[:limit]` returned the start of the window — on a
    # busy capture (17,018 mdmclient events in one hour) that meant the last
    # ~50 minutes, including every command result, was silently dropped while
    # `count` still reported the full total.
    kept = events[-limit:] if truncated else events
    dicts, clipped, dropped = _fit_events(kept)
    out = {
        "category": category,
        # Which source actually answered. A caller that omits `source` silently
        # falls back to the environment (archive > fixture > live), and a live
        # `log show` on a busy Mac can take minutes — which reads as the tool
        # hanging rather than as reading the wrong thing.
        "source": type(source).__name__,
        "count": len(events),
        "truncated": truncated,
        "predicate_version": spec["predicate_version"],
        "exact_version_match": spec["exact_version_match"],
        "note": spec.get("note"),
        "events": dicts,
    }
    if truncated or dropped:
        out["truncation"] = {
            "kept": len(dicts),
            "of": len(events),
            "keeps": "most_recent",
        }
        if dropped:
            out["truncation"]["dropped_for_size"] = dropped
    if clipped:
        out["truncation"] = out.get("truncation") or {
            "kept": len(dicts),
            "of": len(events),
            "keeps": "most_recent",
        }
        out["truncation"]["messages_clipped"] = clipped
    return out


def _fit_events(events: list[Event]) -> tuple[list[dict], int, int]:
    """Serialize events within `_MAX_RESPONSE_BYTES`.

    Returns (dicts, messages_clipped, events_dropped). Long messages are clipped
    first because a single payload dump can be tens of kilobytes; only if that is
    not enough are whole events dropped, oldest first, since recency is what
    matters for an incident.
    """
    clipped = 0
    dicts = []
    for e in events:
        d = e.to_dict()
        msg = d.get("message")
        if msg is not None and len(msg) > _MAX_EVENT_MESSAGE:
            d["message"] = msg[:_MAX_EVENT_MESSAGE] + "…[clipped]"
            clipped += 1
        dicts.append(d)

    dropped = 0
    # Cheap length proxy avoids re-serializing the whole list on every step.
    def size(ds: list[dict]) -> int:
        return sum(len(str(d)) for d in ds) + 2 * len(ds)

    while dicts and size(dicts) > _MAX_RESPONSE_BYTES:
        # Drop from the front: oldest first, keep the most recent.
        step = max(1, len(dicts) // 20)
        del dicts[:step]
        dropped += step
    return dicts, clipped, dropped


def get_install_log(
    source,
    package_name: Optional[str] = None,
    last: str = "1d",
) -> dict:
    """Parse install.log into ordered phases, exit codes, and failures (spec §7.4).

    `package_name` filters by bundle id or display-name substring (case-insensitive).
    Returns structured records only — never raw log text.
    """
    text = source.read_install_log(last)
    records = install_log.parse(text)

    if package_name:
        needle = package_name.lower()
        records = [
            r
            for r in records
            if (r.package and needle in r.package.lower())
            or (r.package_name and needle in r.package_name.lower())
        ]

    exit_codes = [
        {
            "package": r.package,
            "exit_code": r.exit_code,
            "timestamp": r.timestamp,
        }
        for r in records
        if r.exit_code is not None
    ]
    failures = [r.to_dict() for r in records if r.is_failure]

    # Sessions are the reportable unit: a bracketed install with a package name
    # and an outcome. The flat `phases` list can't answer "what installed?" —
    # the lines announcing an outcome carry no package identity.
    sessions = install_log.parse_sessions(text)
    if package_name:
        needle = package_name.lower()
        sessions = [s for s in sessions if s.package and needle in s.package.lower()]

    # `phases` is the raw per-line view and is by far the largest thing this
    # tool can return: an unwindowed macOS install.log produced 31,760 records
    # (8.7 MB), past the MCP 1 MB response limit. Cap it like every other list
    # the engine returns, keeping the most recent — and report the span the
    # records actually cover so a stale window can't pass for the asked-for one.
    phases = [r.to_dict() for r in records]
    phases_truncated = len(phases) > _MAX_PHASES
    kept_phases = phases[-_MAX_PHASES:] if phases_truncated else phases
    stamps = [r.timestamp for r in records if r.timestamp]

    out = {
        "count": len(records),
        "time_span": (
            {"start": min(stamps), "end": max(stamps)} if stamps else None
        ),
        "phases": kept_phases,
        "phases_truncated": phases_truncated,
        "exit_codes": exit_codes,
        "failures": failures,
        "sessions": [s.to_dict() for s in sessions],
        "session_summary": _session_summary(sessions),
    }
    if phases_truncated:
        out["truncation"] = {
            "kept": len(kept_phases),
            "of": len(phases),
            "keeps": "most_recent",
        }
    return out


def _session_summary(sessions) -> dict:
    """Counts by outcome plus the packages involved — the activity report.

    Carries `time_span` because the counts alone are dangerous out of context: a
    caller who asks for 10 minutes and is handed "31 installs, all success" will
    read it as describing those 10 minutes, whatever window it really covers.
    """
    # The END bound must be where the sessions actually got to, not where the
    # last one STARTED. Using `started` for both bounds put the span's end
    # before the failure that ended the install (10:21:15 for a failure at
    # 10:21:18), and made a single-session window a zero-width span.
    starts = [s.started for s in sessions if getattr(s, "started", None)]
    ends = [
        getattr(s, "ended", None) or getattr(s, "last_record", None) or s.started
        for s in sessions
        if getattr(s, "started", None)
    ]
    summary: dict = {
        "total": len(sessions),
        "time_span": {"start": min(starts), "end": max(ends)} if starts else None,
        "by_outcome": {},
        "packages": {},
    }
    for s in sessions:
        summary["by_outcome"][s.outcome] = summary["by_outcome"].get(s.outcome, 0) + 1
        if s.package:
            summary["packages"].setdefault(s.package, {"success": 0, "failed": 0, "incomplete": 0})
            summary["packages"][s.package][s.outcome] += 1
    return summary


def _os_label(source) -> Optional[str]:
    """A self-describing OS string, e.g. "macOS 26.5.1" or "macOS 26".

    Exists because a bare `os_major: 26` reads to a model like a number needing
    translation. Observed twice on real captures: a 7B model turned 26 into
    "macOS 14, or Ventura" and 27 into "macOS 13" — the server was right both
    times and the prose was wrong. Naming the platform leaves nothing to convert.

    Deliberately NOT the marketing name (Tahoe/Sequoia): that mapping needs
    updating every release and being confidently wrong about it is the exact
    failure this is fixing.
    """
    major = getattr(source, "os_major", None)
    if major is None:
        return None
    version = getattr(source, "os_version", None)
    # Only trust the full version when it agrees with the major we resolved
    # predicates against — a bundle can carry an os_major override.
    if version and version.split(".")[0] == str(major):
        return f"macOS {version}"
    return f"macOS {major}"


def get_device_context(source, last: str = "1d") -> dict:
    """Orient the model: OS, enrollment, MDM server host, profile + declaration
    counts, last check-in (spec §7.1). Log-derived and redacted (server host
    hashed). Profile/declaration counts come from mdmclient / declarative logs,
    not the live `profiles` store.
    """
    try:
        events = _collect(source, "mdm_command", last, level=None)
    except predicates.PredicateError:
        events = []
    ctx = device_context.build(events)

    try:
        active_declarations = len(get_ddm_status(source, last=last)["declarations"])
    except predicates.PredicateError:
        active_declarations = None

    try:
        spec = predicates.resolve("mdm_command", source.os_major)
        os_info = {
            "os_name": _os_label(source),
            "os_major": getattr(source, "os_major", None),
            "predicate_version": spec["predicate_version"],
            "exact_version_match": spec["exact_version_match"],
        }
    except (predicates.PredicateError, AttributeError):
        os_info = {
            "os_name": _os_label(source),
            "os_major": getattr(source, "os_major", None),
        }

    return {
        "os": os_info,
        "enrollment": ctx["enrollment"],
        "mdm_server_host": ctx["mdm_server_host"],
        "installed_profiles": ctx["installed_profiles"],
        "user_profiles": ctx["user_profiles"],
        "active_declarations": active_declarations,
        "last_checkin": ctx["last_checkin"],
    }


def get_ddm_status(
    source,
    declaration_id: Optional[str] = None,
    last: str = "1h",
) -> dict:
    """Reconstruct DDM declaration status from declarative-subsystem logs (spec §7.5).

    Log-derived (no CLI dumps the tamper-proof declaration store): reads the
    `declaration` predicate category (remotemanagementd / com.apple.dmd /
    SoftwareUpdateMacController) and returns {declarations, status_reports,
    failing}. `declaration_id` (raw or hashed) optionally filters to one.

    Caveat: an invalid declaration is usually Acknowledged and reported to the
    server in a StatusReport, not logged as a device error — so an empty
    `failing` does not prove every declaration is valid.
    """
    try:
        events = _collect(source, "declaration", last, level=None)
    except predicates.PredicateError:
        events = []
    result = ddm_status.build(events, declaration_id=declaration_id)
    result["count"] = len(events)
    return result


def _normalize_uuid_query(command_uuid: str) -> str:
    """Caller may pass a raw uuid or an already-hashed 'h:...' value."""
    return command_uuid if command_uuid.startswith("h:") else hash_id(command_uuid)


def correlate_command(
    source,
    command_uuid: Optional[str] = None,
    command_type: Optional[str] = None,
    time_anchor: Optional[str] = None,
    last: str = "1h",
    _cache: Optional[dict] = None,
) -> dict:
    if not command_uuid and not (command_type and time_anchor):
        raise ValueError(
            "provide command_uuid, or both command_type and time_anchor"
        )

    # Gather candidate events across all round-trip-relevant categories.
    # Categories overlap (e.g. ddm and mdm_command both match mdmclient), so
    # de-duplicate by raw_ref (the unique per-line trace id), keeping the first
    # category that produced each line.
    pool: list[Event] = []
    seen: set[str] = set()
    for cat in _CORRELATION_CATEGORIES:
        try:
            collected = _collect(source, cat, last, level=None, cache=_cache)
        except predicates.PredicateError:
            continue
        for e in collected:
            key = e.raw_ref or f"{e.timestamp}|{e.process}|{e.message}"
            if key in seen:
                continue
            seen.add(key)
            pool.append(e)
    pool.sort(key=lambda e: e.timestamp)
    pool = _dedupe(pool)

    # Anchor: events matching the query directly.
    if command_uuid:
        matched_by = "uuid"
        target = _normalize_uuid_query(command_uuid)
        anchors = [e for e in pool if e.command_uuid == target]
    else:
        matched_by = "time+type"
        anchor_ms = epoch_ms(time_anchor) or 0
        anchors = [
            e
            for e in pool
            if e.command_type == command_type
            and abs((epoch_ms(e.timestamp) or 0) - anchor_ms) <= _CONTEXT_PAD_MS
        ]
        # A busy window holds many commands of the same type — a real capture had
        # 18 InstallProfile check-ins inside one minute. Taking all of them as
        # anchors merged them into a single "round-trip" whose outcome was
        # whichever finished last: correlating a failure at 04:40:07 reported
        # Acknowledged. Narrow to the check-in nearest the anchor, then let the
        # sequence number pull in exactly that command's other lines.
        if anchors:
            nearest = min(
                anchors, key=lambda e: abs((epoch_ms(e.timestamp) or 0) - anchor_ms)
            )
            if nearest.command_seq:
                anchors = [e for e in anchors if e.command_seq == nearest.command_seq]
            else:
                anchors = [nearest]

    if not anchors:
        return Timeline(
            command_uuid=command_uuid,
            command_type=command_type,
            outcome="Unknown",
            latency_ms=None,
            confidence="low",
            events=[],
        ).to_dict()

    # Expand the anchor into the full round-trip using the deterministic keys
    # mdmclient does log: the per-check-in sequence number (receipt↔result) and
    # the operation UUID (InstallApplication sub-steps), bridged by thread id
    # within the context window. Exact where it applies — no time-window guessing.
    core = _expand_core(pool, anchors, _CONTEXT_PAD_MS)

    # Pull nearby context events (push wake, asset download) not already in core.
    core_refs = {e.raw_ref for e in core}
    lo = min(epoch_ms(e.timestamp) or 0 for e in core) - _CONTEXT_PAD_MS
    hi = max(epoch_ms(e.timestamp) or 0 for e in core) + _CONTEXT_PAD_MS
    context = [
        e
        for e in pool
        if e.raw_ref not in core_refs
        and e.command_uuid is None
        and e.category in ("push", "asset_download", "scheduling")
        and lo <= (epoch_ms(e.timestamp) or 0) <= hi
    ]
    # Context is meant to be a few corroborating signals (the APNs wake, the
    # asset download) — not everything the machine logged nearby. A real capture
    # holds 197k apsd lines, so an uncapped ±60s window pulled ~30k events into
    # one round-trip and returned 8.4 MB, over the MCP 1 MB response limit.
    # Keep the ones closest to the command itself.
    if len(context) > _MAX_CONTEXT_EVENTS:
        mid = (lo + hi) // 2
        context = sorted(
            sorted(context, key=lambda e: abs((epoch_ms(e.timestamp) or 0) - mid))[
                :_MAX_CONTEXT_EVENTS
            ],
            key=lambda e: e.timestamp,
        )

    timeline_events = sorted(core + context, key=lambda e: e.timestamp)

    resolved_type = command_type or next(
        (e.command_type for e in core if e.command_type), None
    )
    outcome, terminal = _derive_outcome(core)
    # Measured over the command's OWN events, not the timeline including
    # context. `context` reaches +/-60s around the command to pull in the APNs
    # wake and download lines, so measuring from the timeline's first event
    # billed unrelated nearby chatter to the command: a real managed-app install
    # reported 29,370 ms where the command's own receipt-to-terminal span was
    # 28.2s, and with a busy +/-60s window the error can be far larger.
    latency = _latency_ms(core, terminal)
    if latency is None and outcome == "NotNow":
        # A declined command has no terminal status, but "how fast did the device
        # decline it?" is a real, useful number and was simply discarded. Measured
        # to the LAST NotNow in the round-trip.
        responder = next(
            (e for e in reversed(core) if e.status == "NotNow"), None
        )
        latency = _latency_ms(core, responder)
    confidence = _confidence(matched_by, core, terminal, _linked_to_terminal(anchors, terminal))

    # Clipped here too, not only inside build_incident_bundle: correlate_command
    # is a tool in its own right and a caller hitting a busy window got a
    # multi-megabyte response that the transport simply refused.
    return _clip_timeline(
        Timeline(
            command_uuid=next(
                (e.command_uuid for e in core if e.command_uuid), command_uuid
            ),
            command_seq=next((e.command_seq for e in core if e.command_seq), None),
            command_type=resolved_type,
            outcome=outcome,
            latency_ms=latency,
            confidence=confidence,
            events=timeline_events,
            tier0_findings=triage_timeline(timeline_events, outcome, latency),
        ).to_dict()
    )


def _dedupe(events: list[Event]) -> list[Event]:
    """Drop duplicate log lines collected via overlapping category predicates.

    Keyed on raw_ref (`traceID:machTimestamp`, unique per line); falls back to
    timestamp+process+message when absent. NOT traceID alone — that identifies
    the emitting code site, so it collapses distinct events.
    """
    seen: set = set()
    out: list[Event] = []
    for e in events:
        key = e.raw_ref or (e.timestamp, e.process, e.message)
        if key in seen:
            continue
        seen.add(key)
        out.append(e)
    return out


# Thread id in mdmclient messages, e.g. "[0:MDMDaemon:ManagedApps:<0x2a764>]".
# Bridges a command's receipt to its operation sub-steps within a short window.
_RE_THREAD = re.compile(r"<(0x[0-9a-fA-F]+)>")


def _thread(e: Event) -> Optional[str]:
    m = _RE_THREAD.search(e.message or "")
    return m.group(1) if m else None


def _expand_core(pool: list[Event], anchors: list[Event], pad_ms: int) -> list[Event]:
    """Grow the anchor set into the full round-trip via deterministic keys.

    Only the operation `command_uuid` is a GLOBAL key — UUIDs are unique, so they
    link sub-steps anywhere. `command_seq` and the thread id are WINDOWED keys:
    they only link an event that is within `pad_ms` of an already-included event.
    This is deliberate — a per-check-in sequence number is small and recurring
    (e.g. `0`), so matching it globally would merge unrelated round-trips and
    overstate confidence. Seq is additionally guarded by `command_type`.
    """
    core = list(anchors)
    in_core = {id(e) for e in core}
    anchor_times = [epoch_ms(e.timestamp) or 0 for e in anchors]
    anchor_floor = min(anchor_times, default=0)
    uuids = {e.command_uuid for e in core if e.command_uuid}  # global strong key

    changed = True
    while changed:
        changed = False
        # Windowed anchors recomputed each pass so new members extend the bridge.
        windowed = []  # (kind, value, command_type, timestamp_ms)
        for e in core:
            t = epoch_ms(e.timestamp) or 0
            if e.command_seq:
                windowed.append(("seq", e.command_seq, e.command_type, t))
            th = _thread(e)
            if th:
                windowed.append(("thr", th, None, t))
        for e in pool:
            if id(e) in in_core:
                continue
            link = bool(e.command_uuid and e.command_uuid in uuids)
            if not link and e.command_seq:
                et = epoch_ms(e.timestamp) or 0
                link = any(
                    kind == "seq"
                    and val == e.command_seq
                    and abs(et - t) <= pad_ms
                    and (ct is None or e.command_type is None or ct == e.command_type)
                    for kind, val, ct, t in windowed
                )
            # Thread bridges only DETAIL lines (error chains, sub-steps) that have
            # no sequence of their own. A line that carries its own command_seq is
            # a distinct check-in — never pull it across a shared thread, or a
            # device that logs every command on one thread would merge them all.
            # Bridged lines must also be close in time AND not precede the
            # command: sub-steps follow the receipt, whereas everything the
            # daemon happened to do earlier on that thread does not belong here.
            if not link and e.command_seq is None and (th := _thread(e)):
                et = epoch_ms(e.timestamp) or 0
                # Measured from the ANCHOR, not from any already-included core
                # member. Comparing to core members let the bridge chain forward
                # in _THREAD_PAD_MS hops, walking arbitrarily far from the
                # command: an ActivationLockBypassCode round-trip grew to a 65s
                # core and absorbed a later command's Acknowledged, so a failed
                # command was reported as succeeding.
                near_anchor = any(
                    abs(et - at) <= _THREAD_PAD_MS for at in anchor_times
                )
                if near_anchor and et >= anchor_floor - _THREAD_LEAD_MS:
                    link = any(
                        kind == "thr" and val == th
                        for kind, val, ct, t in windowed
                    )
            if link:
                core.append(e)
                in_core.add(id(e))
                if e.command_uuid:
                    uuids.add(e.command_uuid)
                changed = True
    # Chronological. `core` is built anchors-first and then extended in pool
    # order, so it was NOT time-ordered — and _derive_outcome takes "the last
    # terminal", which therefore depended on discovery order rather than time.
    # On a real install that picked the operation's own completion line over the
    # command's later Acknowledged, losing the link to the anchor and reporting
    # high-confidence correlations as low.
    core.sort(key=lambda e: e.timestamp)
    return core


def _linked_to_terminal(anchors: list[Event], terminal: Optional[Event]) -> bool:
    """True if the terminal event is tied to the query anchor by a strong key."""
    if terminal is None:
        return False
    a_seqs = {e.command_seq for e in anchors if e.command_seq}
    a_uuids = {e.command_uuid for e in anchors if e.command_uuid}
    return (terminal.command_seq in a_seqs) or (terminal.command_uuid in a_uuids)


# Terminal statuses outrank deferrals, which outrank "seen but no status yet".
_STATUS_RANK = {None: 0, "Idle": 1, "NotNow": 2, "Acknowledged": 3, "Error": 3,
                "CommandFormatError": 3}


def _status_rank(status: Optional[str]) -> int:
    return _STATUS_RANK.get(status, 1)



def _counts_as_command(key: tuple, slot: dict, commands: dict) -> bool:
    """Is this group a COMMAND for tallying purposes, or install-operation detail?

    An InstallApplication command and the install operation it triggers are
    different things, logged separately. Counting both reported one app twice.
    """
    if slot["type"] != "InstallApplication":
        return True
    # A SUCCESSFUL install operation adds nothing the command's own Acknowledged
    # did not already say. A FAILED one is new information — the command
    # succeeded and the install did not — so it still counts.
    if key[0] == "install":
        return slot["status"] in ("Error", "CommandFormatError")
    # `app`/`app_phase` groups are the fragments of one abort that carry no
    # operation id: the App Store notification (bundle id only) and the abort
    # line (neither). The operation they belong to is already counted via its
    # install id, so counting them too reported three failures for one failed
    # install. Counted only when no install operation was seen at all, so a
    # failure can never vanish entirely.
    if key[0] in ("app", "app_phase"):
        return not any(k[0] == "install" for k in commands)
    return True


def _clip_timeline(tl: dict) -> dict:
    """Keep a timeline's head and tail, dropping the middle, with a count."""
    events = tl.get("events") or []
    if len(events) <= _MAX_TIMELINE_EVENTS:
        return tl
    half = _MAX_TIMELINE_EVENTS // 2
    clipped = dict(tl)
    clipped["events"] = events[:half] + events[-half:]
    clipped["events_omitted"] = len(events) - _MAX_TIMELINE_EVENTS
    clipped["events_total"] = len(events)
    return clipped


def _derive_outcome(core: list[Event]) -> tuple[str, Optional[Event]]:
    terminal = None
    for e in core:
        if e.status in ("Acknowledged", "Error", "CommandFormatError"):
            terminal = e  # last terminal wins
    if terminal:
        return terminal.status, terminal
    # No terminal status: report the latest non-terminal one, but NotNow beats
    # Idle regardless of order. A NotNow is the device actively deferring the
    # command — the thing the caller is asking about — while Idle just means no
    # command was pending on that check-in. Taking whichever came last reported
    # a deferred command as "Idle" and lost the deferral.
    for e in reversed(core):
        if e.status == "NotNow":
            return e.status, None
    for e in reversed(core):
        if e.status == "Idle":
            return e.status, None
    return "Unknown", None


def _latency_ms(events: list[Event], terminal: Optional[Event]) -> Optional[int]:
    """Milliseconds from the command's first event to its terminal status.

    Pass the CORE events (the command's own lines), never core+context: context
    is padded around the command and would be billed to it.
    """
    if not events or terminal is None:
        return None
    start = epoch_ms(min(e.timestamp for e in events))
    end = epoch_ms(terminal.timestamp)
    if start is None or end is None:
        return None
    return max(0, end - start)


def _confidence(
    matched_by: str,
    core: list[Event],
    terminal: Optional[Event],
    linked: bool,
) -> str:
    # A terminal tied to the query by a strong key (seq/uuid) — or a direct uuid
    # match — is a deterministic round-trip.
    if terminal is not None and (linked or matched_by == "uuid"):
        return "high"
    if matched_by == "uuid":
        return "medium"
    return "low"


# --- build_incident_bundle (spec §7.7) ------------------------------------

# Each symptom maps to the categories worth querying and whether to pull the
# install log. Free-text/unknown symptoms fall back to a broad default. This is
# the only place the "which signals matter for X" policy lives.
_SYMPTOM_PLANS = {
    "command_failure": (("mdm_command", "push", "scheduling"), False),
    "install_failure": (("mdm_command", "asset_download", "pkg_install"), True),
    "profile_failure": (("profile_payload", "mdm_command"), False),
    # `declaration` is the declarative-subsystem-only category; `ddm` also
    # matches ALL of mdmclient, so a ddm_failure bundle came back full of
    # managed-app-install noise labelled category "ddm" — the one section a
    # reader trusts for DDM problems was actively misleading. mdm_command comes
    # along for the DeclarativeManagement command's own status.
    "ddm_failure": (("declaration", "mdm_command"), False),
    "enrollment_failure": (("enrollment", "mdm_command", "push"), False),
    # Activity (not failure) symptoms. Same categories as their failure
    # counterparts — the difference is what the caller is asking about, and the
    # outcome tally below reports successes rather than only errors. The
    # vocabulary was failure-only, which made "what installed in the last hour?"
    # unaskable even though the data was already being collected.
    "app_activity": (("mdm_command", "asset_download", "pkg_install"), True),
    "profile_activity": (("profile_payload", "mdm_command"), False),
    "ddm_activity": (("declaration", "mdm_command"), False),
    "activity": (("mdm_command", "push", "pkg_install"), True),
}
_DEFAULT_PLAN = (("mdm_command", "push", "scheduling"), True)
# Keyword hints so free-text symptoms still route sensibly.
_SYMPTOM_KEYWORDS = (
    # Activity/report wording first — "report of app installs" must not route to
    # install_failure just because it contains "install".
    ("app activity", "app_activity"),
    ("app_activity", "app_activity"),
    ("profile activity", "profile_activity"),
    ("profile_activity", "profile_activity"),
    ("ddm activity", "ddm_activity"),
    ("ddm_activity", "ddm_activity"),
    ("report", "activity"),
    ("activity", "activity"),
    ("inventory", "activity"),
    ("what installed", "app_activity"),
    ("install", "install_failure"),
    ("pkg", "install_failure"),
    ("package", "install_failure"),
    ("profile", "profile_failure"),
    ("payload", "profile_failure"),
    ("ddm", "ddm_failure"),
    ("declarat", "ddm_failure"),
    ("enroll", "enrollment_failure"),
    ("command", "command_failure"),
)

_MAX_TIMELINES = 10  # cap correlations to keep the bundle compact (§7.7)
_MAX_NOTABLE = 25
_MAX_REASONS = 5  # error CLASSES quoted in the command_failures finding
# A single correlated round-trip on a busy capture can pull thousands of context
# events, so capping the NUMBER of timelines is not enough — 7 timelines over a
# real 1h capture rendered a 34 MB bundle. Keep the head and tail of each: the
# receipt and the result are the diagnosis; the middle is XPC chatter.
_MAX_TIMELINE_EVENTS = 40
_MAX_CONTEXT_EVENTS = 25  # corroborating push/download/scheduling lines per timeline
# Thread-id bridging gets a much tighter window than the seq/context pad. A
# thread id is reused heavily by mdmclient, so a 60s bridge absorbed a whole
# check-in's unrelated work — DEP-state queries and profile-store reads landed
# in an InstallApplication's core, padding the timeline and starting its latency
# clock 1.2s before the command was even dispatched. An operation's sub-steps
# are close in time and FOLLOW its receipt.
_THREAD_PAD_MS = 10_000
# Just enough lead to keep the HTTP response that DELIVERED the command, which
# precedes the "Processing server request" line by ~2ms on real captures. A
# second was too generous: it re-admitted work the daemon did on that thread
# before the command existed.
_THREAD_LEAD_MS = 250
_CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}
# Volatile bits of a log message — addresses, ids, counters — normalized away so
# hundreds of near-identical fault lines collapse to their distinct shapes.
_RE_VOLATILE = re.compile(r"0x[0-9a-fA-F]+|\b\d+\b|h[:-][0-9a-f]{6,}")


def _resolve_plan(symptom: Optional[str]) -> tuple[tuple[str, ...], bool]:
    if not symptom:
        return _DEFAULT_PLAN
    key = symptom.strip().lower()
    if key in _SYMPTOM_PLANS:
        return _SYMPTOM_PLANS[key]
    for needle, plan_key in _SYMPTOM_KEYWORDS:
        if needle in key:
            return _SYMPTOM_PLANS[plan_key]
    return _DEFAULT_PLAN


def build_incident_bundle(
    source,
    symptom: Optional[str] = None,
    last: str = "1h",
) -> dict:
    """Assemble one compact, redacted incident bundle (spec §7.7).

    Runs the relevant query_events + correlate_command calls for the symptom and
    folds them into {context, timelines, notable_errors, tier0_findings} (plus an
    additive install_log when relevant). Never returns raw log text.
    """
    categories, want_install = _resolve_plan(symptom)

    event_counts: dict[str, int] = {}
    notable_errors: list[dict] = []
    fault_errors: list[dict] = []
    seen_errors: set[str] = set()
    seen_shapes: set[str] = set()
    command_uuids: list[str] = []
    by_status: dict[str, int] = {}
    by_type: dict[str, dict] = {}
    all_events: list[Event] = []
    # Distinct commands, keyed by sequence number / operation uuid.
    commands: dict[tuple, dict] = {}
    # Failures with no sequence number / uuid to key them on (check-in transport
    # errors), counted by type so the findings and the tally agree.
    unkeyed_failures: dict[str, int] = {}
    # Protocol check-ins, kept apart from the command tally.
    checkins: dict[str, dict] = {}
    checkin_failures: list[dict] = []
    # Predicate categories overlap by design (profile_payload and mdm_command
    # both match mdmclient), so the same line arrives more than once. De-dupe by
    # raw_ref before tallying, or one Error is counted once per category that
    # matched it. `event_counts` stays per-category on purpose: it reports what
    # each predicate matched, which is the diagnostic for predicate drift.
    seen_refs: set[str] = set()
    # One fetch+parse per (category, window) for this request, shared with the
    # correlations below. Dropped when the call returns — nothing persists.
    cache: dict = {}

    for cat in categories:
        # Collect the FULL event list, not query_events' presentation slice.
        # This aggregation previously read `query_events(...)["events"]`, which
        # is capped at `limit` (default 500) — so on a busy capture the tally,
        # the notable errors and the correlation seeds were computed from a
        # fraction of the window while `event_counts` reported the true total.
        # A real 1-hour capture with 17,018 mdmclient events and 9 failed
        # commands reported `by_status: {}` and `notable_errors: []`.
        try:
            collected = _collect(source, cat, last, None, cache=cache)
        except predicates.PredicateError:
            continue
        event_counts[cat] = len(collected)
        deduped = []
        for ev in collected:
            if ev.raw_ref is not None:
                if ev.raw_ref in seen_refs:
                    continue
                seen_refs.add(ev.raw_ref)
            deduped.append(ev)
        all_events.extend(deduped)
        for e in (ev.to_dict() for ev in deduped):
            # An MDM command Error (from a [Error(Type):n] bracket) is a real
            # signal — always keep it. Otherwise, only trust `fault` level:
            # macOS logs many benign mdmclient lines at `error` level (SQLite
            # housekeeping, apsd XPC teardown, "cannot open file"), so treating
            # `messageType == "error"` as an incident signal drowns the bundle
            # in subsystem noise. Same lesson we applied to ddm_status.failing.
            # An ErrorChain line carries the failure REASON but no status (it
            # is detail about a command counted elsewhere, so giving it a status
            # would double-count the failure). Without this clause the codes and
            # descriptions that say *why* a command failed never surfaced.
            if (
                e.get("status") == "Error"
                or e.get("message_type") == "fault"
                or (e.get("error_code") is not None and e.get("reason"))
            ):
                key = e.get("raw_ref") or f"{e.get('timestamp')}|{e.get('message')}"
                if key not in seen_errors:
                    seen_errors.add(key)
                    if e.get("status") == "Error" or e.get("error_code") is not None:
                        notable_errors.append(e)
                    else:
                        # A bare `fault` is weaker evidence than a command that
                        # reported Error. apsd emits hundreds on a laptop cycling
                        # sleep states — 977 of 987 on a real capture — so kept
                        # separately, shape-deduped, and appended AFTER the real
                        # errors so the cap can never crowd them out.
                        shape = _RE_VOLATILE.sub("#", (e.get("message") or "")[:160])
                        if shape not in seen_shapes:
                            seen_shapes.add(shape)
                            fault_errors.append(e)
            # Outcome tally: what the device did, successes included. The
            # bundle previously surfaced only errors, which made routine
            # activity ("9 acknowledged, 2 errored") unreportable.
            #
            # Counted per COMMAND, not per line. mdmclient logs a result twice —
            # once on the outgoing HTTP request and once on the response — and
            # the receipt line carries the same sequence number again, so a
            # per-line tally reported 58 Acknowledged and 20 Error for a window
            # holding 29 and 9. The sequence number (or operation uuid) is the
            # command's identity; lines carrying neither are still counted
            # individually, since there is nothing better to key them on.
            status, ctype = e.get("status"), e.get("command_type")
            # Check-in transport (MDM_Authenticate / MDM_TokenUpdate /
            # MDM_RemoteManagement / MDM_CheckOut) is tallied SEPARATELY. These
            # are protocol check-ins, not MDM commands: folding them in turned a
            # verified "29 acknowledged / 9 errored" window into 11 errors and
            # would not reconcile against the server's command log. They matter
            # on their own — a 401 here is how a manual enrollment fails, and a
            # 503 is the server refusing the device outright.
            if ctype and ctype.startswith("MDM_"):
                checkins.setdefault(ctype, {})
                bucket = status or "seen"
                checkins[ctype][bucket] = checkins[ctype].get(bucket, 0) + 1
                if status in ("Error", "CommandFormatError"):
                    code = e.get("error_code")
                    checkin_failures.append(
                        {"type": ctype, "code": code, "reason": e.get("reason")}
                    )
                continue
            key = None
            # NOTE the command_type is part of the key ONLY for `seq`. A
            # sequence number is small and recurring, so it needs the type as a
            # guard. A uuid does not — and including it there SPLIT one command
            # into two groups whenever its lines did not all name the type: the
            # receipt line carries `RequestType=InstallApplication` and the
            # result line carries only the uuid, so a single failed command was
            # tallied as "InstallApplication seen 1" plus "unknown Error 1".
            if e.get("command_seq"):
                key = ("seq", ctype, e["command_seq"])
            elif e.get("install_uuid"):
                # An install OPERATION, not a command. Keyed apart from
                # command_uuid so the tally can treat it differently — and
                # before it, since these lines carry both.
                key = ("install", None, e["install_uuid"])
            elif e.get("command_uuid"):
                key = ("uuid", None, e["command_uuid"])
            elif e.get("app_id"):
                key = ("app", None, e["app_id"])
            elif ctype == "InstallApplication":
                # An install-phase fragment with no identity at all (the abort
                # line itself). Keyed as one bucket so it can be folded into the
                # install operation below instead of tallying as its own failure.
                key = ("app_phase", ctype, "unkeyed")
            if key is not None:
                slot = commands.setdefault(
                    key, {"type": ctype, "status": None, "ts": e.get("timestamp")}
                )
                if slot["type"] is None:
                    slot["type"] = ctype
                if slot.get("ts") is None:
                    slot["ts"] = e.get("timestamp")
                if _status_rank(status) > _status_rank(slot["status"]):
                    slot["status"] = status
            elif (status or ctype) and not (
                status is None
                and (e.get("error_code") is not None or e.get("reason"))
            ):
                # The excluded case is DETAIL about a command counted elsewhere:
                # an ErrorChain line (type + code, no status) or a deferral
                # reason line ("Responding 'NotNow' … reason: …"). Both name a
                # command type without being one, so counting them added a
                # phantom "seen" beside the real status, and a third NotNow for
                # two deferred commands.
                if status:
                    by_status[status] = by_status.get(status, 0) + 1
                    if status in ("Error", "CommandFormatError"):
                        # Recorded so command_failures counts it too. A check-in
                        # failure (HTTP 401 on MDM_Authenticate) has no sequence
                        # number, so it lands here rather than in `commands` —
                        # and the finding, which read only `commands`, disagreed
                        # with the tally that had already reported it.
                        t = ctype or "unknown"
                        unkeyed_failures[t] = unkeyed_failures.get(t, 0) + 1
                if ctype:
                    by_type.setdefault(ctype, {})
                    by_type[ctype][status or "seen"] = (
                        by_type[ctype].get(status or "seen", 0) + 1
                    )
            uuid = e.get("command_uuid")
            if uuid and uuid not in command_uuids:
                command_uuids.append(uuid)

    # Real errors first, then one example of each distinct fault shape.
    notable_total = len(notable_errors) + len(fault_errors)
    notable_errors = notable_errors + fault_errors

    all_events_dicts = [e.to_dict() for e in all_events]

    # Fold distinct commands into the tally. `counted` is derived once and used
    # for both the tally and the command_failures finding below — computing the
    # two independently let them disagree (a tally of 1 failure next to a
    # finding claiming 3).
    counted = {k: v for k, v in commands.items() if _counts_as_command(k, v, commands)}
    for slot in counted.values():
        status, ctype = slot["status"], slot["type"]
        if status:
            by_status[status] = by_status.get(status, 0) + 1
        if ctype:
            by_type.setdefault(ctype, {})
            by_type[ctype][status or "seen"] = by_type[ctype].get(status or "seen", 0) + 1

    # Correlate each distinct command into a timeline (capped).
    timelines: list[dict] = []
    # Distinct uuids can correlate to the same span of events (several
    # operation uuids logged inside one check-in), which rendered the same
    # 40-event round-trip several times in a report that bills itself as
    # compact. De-dupe on the event set, not the uuid.
    # Correlation seeds, failures and deferrals FIRST. Seeds used to be only
    # the events carrying a command_uuid — but macOS logs no protocol UUID for
    # ordinary commands, so on a real command_failure window with 3 Errors and 2
    # NotNows the only timeline produced was a *successful* InstallApplication
    # (the one thing that had an operation uuid), and every command the caller
    # was asking about got none. A seq-keyed command is anchored by type+time,
    # which correlate_command then narrows to that single check-in.
    seeds: list[tuple] = []
    for want_failed in (True, False):
        for key, slot in commands.items():
            failed = slot["status"] in ("Error", "CommandFormatError", "NotNow")
            if failed is not want_failed:
                continue
            if (
                key[0] in ("install", "uuid")
                and slot["type"] == "InstallApplication"
                and any(
                    k[0] == "seq" and commands[k]["type"] == "InstallApplication"
                    for k in commands
                )
            ):
                # The install operation belongs to a command that is itself
                # seeded, and that command's timeline reaches the operation's
                # sub-steps through the operation uuid (a global key in
                # _expand_core). Seeding both produced two timelines for one
                # round-trip, differing only in which end they terminated at —
                # so the same install rendered twice, once at low confidence.
                continue
            if key[0] in ("uuid", "install"):
                seeds.append(("uuid", key[2], None))
            elif slot.get("ts") and slot["type"]:
                seeds.append(("anchor", slot["type"], slot["ts"]))
    # No separate pass over `command_uuids`: every uuid-bearing event is already
    # a group in `commands`, so a second pass only re-adds the seeds the rules
    # above deliberately skipped.

    seen_spans: set = set()
    by_terminal: dict[str, int] = {}
    for kind, a, b in seeds:
        if len(timelines) >= _MAX_TIMELINES:
            break
        if kind == "uuid":
            tl = correlate_command(source, command_uuid=a, last=last, _cache=cache)
        else:
            tl = correlate_command(
                source, command_type=a, time_anchor=b, last=last, _cache=cache
            )
        if not tl["events"]:
            continue
        # A timeline with neither a command type nor a resolved outcome says
        # nothing. These come from `_RE_OP_UUID` matching "UUID:"/"ID:" in
        # unrelated text (keychain persistent refs, attestation certs), which
        # seeded one-event "Unknown" round-trips that padded the bundle.
        if tl.get("command_type") is None and tl.get("outcome") == "Unknown":
            continue
        span = (
            tl.get("command_type"),
            tl.get("outcome"),
            tuple(e.get("raw_ref") for e in tl["events"]),
        )
        if span in seen_spans:
            continue
        seen_spans.add(span)
        # Two seeds can reach the same round-trip — a command keyed by its
        # sequence and the operation it triggered keyed by uuid both resolve to
        # one terminal event — which rendered the same install twice, once at
        # low confidence and once at high. Keyed on the terminal event, keeping
        # whichever correlation is better evidenced.
        terminal_ref = next(
            (
                e.get("raw_ref")
                for e in reversed(tl["events"])
                if e.get("status") in ("Acknowledged", "Error", "CommandFormatError")
            ),
            None,
        )
        clipped = _clip_timeline(tl)
        if terminal_ref is not None and terminal_ref in by_terminal:
            prev = by_terminal[terminal_ref]
            if _CONFIDENCE_RANK.get(tl.get("confidence"), 0) > _CONFIDENCE_RANK.get(
                timelines[prev].get("confidence"), 0
            ):
                timelines[prev] = clipped
            continue
        if terminal_ref is not None:
            by_terminal[terminal_ref] = len(timelines)
        timelines.append(clipped)

    # Optional install-log report; archive sources may not supply it yet.
    install_report = None
    if want_install:
        try:
            install_report = get_install_log(source, last=last)
        except NotImplementedError:
            install_report = None

    # Aggregate Tier-0 findings: every timeline's findings (deduped), plus a
    # synthesized finding per install failure.
    findings: list[dict] = []
    seen_findings: dict = {}

    def _add_finding(f: dict) -> None:
        # Keyed on code+summary, NOT on evidence: the generic rules
        # (no_terminal, private_data_masked) fire on every timeline with
        # different refs each time, so an evidence-sensitive key emitted the
        # same finding six times over. Same finding, merged evidence.
        key = (f["code"], f["summary"])
        existing = seen_findings.get(key)
        if existing is None:
            seen_findings[key] = f
            findings.append(f)
            return
        merged = list(dict.fromkeys(existing.get("evidence", []) + f.get("evidence", [])))
        total = existing.get("evidence_total", len(existing.get("evidence", [])))
        total += f.get("evidence_total", len(f.get("evidence", [])))
        existing["evidence"] = merged[:MAX_EVIDENCE]
        if total > len(existing["evidence"]):
            existing["evidence_total"] = total

    for tl in timelines:
        for f in tl.get("tier0_findings", []):
            _add_finding(f)
    # Failed commands, straight from the tally. Without this a bundle over a
    # window with 9 failed commands produced no finding at all: the failures had
    # no CommandUUID (macOS logs none), so no timeline covered them, and
    # timelines were the only source of findings.
    counts: dict[str, int] = dict(unkeyed_failures)
    for slot in counted.values():
        if slot["status"] in ("Error", "CommandFormatError"):
            t = slot["type"] or "unknown"
            counts[t] = counts.get(t, 0) + 1
    failed = sorted(counts)
    if failed:
        detail = ", ".join(f"{t}×{counts[t]}" for t in failed)
        # Include the distinct ErrorChain reasons: "9 commands failed" is a
        # count, not a diagnosis, and the reasons are right there in the log.
        # Grouped by error CLASS (domain + code), not by exact wording. Listing
        # distinct reason strings looked reasonable until a real window produced
        # five "Profile with identifier '<different id>' not found" reasons: they
        # filled the cap, and two other error classes were dropped with nothing
        # saying so. One line per class, with a count, says more in less room.
        classes: dict[int, dict] = {}
        for e in notable_errors:
            r, code = e.get("reason"), e.get("error_code")
            if not r or code is None:
                continue
            # Keyed on the numeric code, not the label: the same failure is
            # logged twice, once as "[CPProfile:-102] …" from the inline chain
            # and once bare from the response payload, so keying on the label
            # split one error class into two.
            m = re.match(r"^\[([^\]]+)\]\s*(.*)$", r)
            slot = classes.setdefault(code, {"n": 0, "desc": "", "label": None})
            slot["n"] += 1
            if m and slot["label"] is None:
                slot["label"] = m.group(1)  # the domain-qualified form, when seen
            if not slot["desc"]:
                slot["desc"] = (m.group(2) if m else r).strip()
        shown = list(classes.items())[:_MAX_REASONS]
        # Units spelled out: this counts LOG LINES mentioning the class, which
        # need not equal the command count in the sentence above (one failure is
        # logged as an inline chain and again in the response payload).
        reasons = [
            f"[{v['label'] or k}] ({v['n']} log line(s)) {v['desc']}"
            for k, v in shown
        ]
        if len(classes) > len(shown):
            reasons.append(f"(+{len(classes) - len(shown)} more error class(es))")
        why = (" Reasons: " + " | ".join(reasons)) if reasons else ""
        _add_finding(
            Finding(
                code="command_failures",
                severity="error",
                summary=f"{sum(counts.values())} MDM command(s) returned Error: {detail}.{why}",
                evidence=[
                    e["raw_ref"]
                    for e in notable_errors[:_MAX_NOTABLE]
                    if e.get("raw_ref")
                ],
                confidence="high",
            ).to_dict()
        )

    # Check-in failures. A refused check-in is not a failed command but it is
    # how enrollment fails, and it had no finding at all: a manual enrollment
    # that died on HTTP 401 reported "enrollment: 0 events" and nothing else.
    if checkin_failures:
        groups: dict[str, int] = {}
        for cf in checkin_failures:
            label = f"{cf['type']}({cf['code']})" if cf["code"] else cf["type"]
            groups[label] = groups.get(label, 0) + 1
        detail = ", ".join(f"{k}×{v}" for k, v in sorted(groups.items()))
        # Only say it about enrollment when Authenticate is what failed — a
        # TokenUpdate or RemoteManagement 503 is a different problem.
        enrol = any(cf["type"] == "MDM_Authenticate" for cf in checkin_failures)
        note = (
            " MDM_Authenticate was refused, so enrollment did not complete."
            if enrol
            else ""
        )
        _add_finding(
            Finding(
                code="checkin_failure",
                severity="error",
                summary=(
                    f"{len(checkin_failures)} MDM check-in(s) rejected by the "
                    f"server: {detail}.{note}"
                ),
                evidence=[],
                confidence="high",
            ).to_dict()
        )

    # Declaration failures. get_ddm_status finds these in one call from the
    # declarative subsystems, but the bundle never consulted it — so a
    # deliberately invalid declaration produced a ddm_failure bundle with no
    # DDM finding at all, while the device had logged the offending key by name.
    if "declaration" in categories:
        try:
            ddm = get_ddm_status(source, last=last)
        except (predicates.PredicateError, RuntimeError):
            ddm = None
        if ddm:
            bundle_ddm = {
                "declarations": ddm["declarations"],
                "status_reports": ddm["status_reports"][:_MAX_NOTABLE],
                "failing": ddm["failing"][:_MAX_NOTABLE],
                "count": ddm.get("count"),
            }
            if ddm["failing"]:
                reasons = list(
                    dict.fromkeys(
                        (f.get("message") or "")[:180] for f in ddm["failing"]
                    )
                )[:_MAX_REASONS]
                _add_finding(
                    Finding(
                        code="declaration_failure",
                        severity="error",
                        summary=(
                            f"{len(ddm['failing'])} declarative-subsystem "
                            f"failure(s): " + " | ".join(reasons)
                        ),
                        evidence=[
                            f["raw_ref"] for f in ddm["failing"] if f.get("raw_ref")
                        ],
                        confidence="high",
                    ).to_dict()
                )
        else:
            bundle_ddm = None
    else:
        bundle_ddm = None

    # Deferred commands. A NotNow is the most common real-world MDM symptom and
    # was reportable only as a bare counter: the reason lives on a separate
    # unbracketed line, so a bundle could say "NotNow x2" and not why.
    deferred = [slot for slot in counted.values() if slot["status"] == "NotNow"]
    if deferred:
        types: dict[str, int] = {}
        for slot in deferred:
            t = slot["type"] or "unknown"
            types[t] = types.get(t, 0) + 1
        detail = ", ".join(f"{t}×{n}" for t, n in sorted(types.items()))
        # macOS logs the reason on a separate line that does NOT carry the
        # sequence number, so a reason cannot be attributed to a specific
        # deferral. Say how many reason lines were found against how many
        # deferrals, rather than presenting one reason as if it covered all of
        # them — a reader took an aggregated reason for a per-command fact.
        reason_lines = [
            e["reason"]
            for e in all_events_dicts
            if (e.get("reason") or "").startswith("NotNow:")
        ]
        why = list(dict.fromkeys(reason_lines))[:_MAX_REASONS]
        if why:
            scope = (
                f" Reasons ({len(reason_lines)} reason line(s) for "
                f"{len(deferred)} deferral(s), not attributable to a specific "
                f"command): "
            )
            reasons = scope + " | ".join(why)
        else:
            reasons = (
                " No reason line was logged; macOS logs it separately from the"
                " status bracket and it may fall outside the window."
            )
        _add_finding(
            Finding(
                code="command_deferred",
                severity="warn",
                summary=f"{len(deferred)} command(s) deferred with NotNow: {detail}.{reasons}",
                evidence=[],
                confidence="high",
            ).to_dict()
        )

    # Managed-app install aborts: not part of any round-trip (the command is
    # Acknowledged and the install fails later, in PackageKit) and absent from
    # install.log, so they are only reachable from the flat event list.
    for f in triage_app_installs(all_events):
        _add_finding(f.to_dict())
    if install_report and install_report["failures"]:
        pkgs = sorted({f.get("package") for f in install_report["failures"] if f.get("package")})
        _add_finding(
            Finding(
                code="pkg_install_failure",
                severity="error",
                summary=f"{len(install_report['failures'])} install.log failure(s)"
                + (f" for {', '.join(pkgs)}" if pkgs else ""),
                evidence=[f["timestamp"] for f in install_report["failures"]],
                confidence="high",
            ).to_dict()
        )

    command_activity = {"by_status": by_status, "by_type": by_type}
    if checkins:
        command_activity["checkins"] = checkins
    if install_report and install_report.get("session_summary"):
        command_activity["installs"] = install_report["session_summary"]

    context = {
        "source": type(source).__name__,
        "os_name": _os_label(source),
        "os_major": getattr(source, "os_major", None),
        "predicate_version": _predicate_version(source),
        "time_window": last,
        "symptom": symptom,
        "event_counts": event_counts,
    }
    # What the capture actually contains, so a 0 in `event_counts` is readable:
    # a file present with 0 records means the predicate matched nothing, a file
    # absent means that process was never captured. Without this the two are
    # indistinguishable and get guessed at.
    inventory = source.capture_inventory()
    if inventory is not None:
        context["capture"] = inventory
    # Enrich with device context (enrollment, MDM server host, profile/declaration
    # counts, last check-in) — spec §7.1. Degrade gracefully if the source can't
    # be read (e.g. live `log show` failure); let logic errors surface.
    try:
        context["device"] = get_device_context(source, last=last)
    except (RuntimeError, predicates.PredicateError):
        context["device"] = None

    # A capture with no push file cannot answer "was a push delivered?", and
    # `context.capture` already states that. Keeping missing_push here presented
    # a collection gap as a possible delivery problem.
    inv_files = (inventory or {}).get("files", {}) if inventory else {}
    if inventory is not None and not inv_files.get("push.ndjson"):
        findings = [f for f in findings if f["code"] != "missing_push"]

    bundle = {
        "context": context,
        "command_activity": command_activity,
        "timelines": timelines,
        "notable_errors": notable_errors[:_MAX_NOTABLE],
        "notable_errors_total": notable_total,
        "tier0_findings": findings,
    }
    if install_report is not None:
        bundle["install_log"] = install_report
    if bundle_ddm is not None:
        bundle["ddm_status"] = bundle_ddm
    return bundle


def _predicate_version(source) -> Optional[int]:
    try:
        return predicates.resolve("mdm_command", source.os_major)["predicate_version"]
    except (predicates.PredicateError, AttributeError):
        return None
