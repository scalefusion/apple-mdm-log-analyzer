"""`--report`: the engine as a plain command, for clients that can't run MCP.

The MCP server only reaches clients that launch a local process — Claude
Desktop, Claude Code, Cursor, mcphost. ChatGPT cannot (it connects only to
remote HTTPS servers with OAuth), and neither can a browser tab, a ticket, or
an email. This renders the same redacted incident bundle as text the admin
pastes wherever they like.

It is also readable without any model: an admin can diagnose straight from the
findings and round-trips.

Deliberately stdlib-only and free of any `mcp` import, so it stays covered by
the zero-dependency engine suite and works even where the SDK is unavailable.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from typing import Optional

from . import engine, sources

# Caps on what the human-readable rendering shows. The underlying bundle is
# already capped by the engine (_MAX_TIMELINES / _MAX_NOTABLE); these keep the
# paste small enough for any chat box. --format json is the uncapped view.
_MAX_TIMELINES = 5
_MAX_EVENTS_PER_TIMELINE = 10
_MAX_NOTABLE = 10
_MAX_MESSAGE = 140

SYMPTOMS = (
    # failures
    "command_failure",
    "install_failure",
    "profile_failure",
    "ddm_failure",
    "enrollment_failure",
    # activity / reporting
    "activity",
    "app_activity",
    "profile_activity",
    "ddm_activity",
)


def _clip(text: str, limit: int = _MAX_MESSAGE) -> str:
    text = (text or "").replace("\n", " ").strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _hhmmss(iso: Optional[str]) -> str:
    """Time-of-day from an ISO timestamp — the date is in the header already."""
    return iso[11:23] if iso and len(iso) >= 23 else (iso or "?")


def render_markdown(bundle: dict, *, symptom: Optional[str], last: str) -> str:
    ctx = bundle.get("context", {}) or {}
    dev = ctx.get("device") or {}
    out: list[str] = []

    out.append(f"# MDM incident report — {symptom or 'general'}")
    out.append(
        f"_window {last} · {ctx.get('os_name') or 'unknown OS'} · "
        f"predicates v{ctx.get('predicate_version')} · "
        f"generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC_"
    )
    out.append("")
    out.append(
        "_Identifiers are hashed (`h:`/`h-`) or scrubbed, with a per-session "
        "salt — the same value hashes differently in another run. No raw log "
        "text is included._"
    )

    out.append("\n## Device")
    if dev:
        out.append(
            f"- enrollment: **{dev.get('enrollment')}** · "
            f"MDM host `{dev.get('mdm_server_host')}`"
        )
        out.append(
            f"- profiles: {dev.get('installed_profiles')} device / "
            f"{dev.get('user_profiles')} user · "
            f"declarations: {dev.get('active_declarations')}"
        )
        out.append(f"- last check-in: {dev.get('last_checkin')}")
    else:
        out.append("- (device context unavailable for this source)")
    counts = ctx.get("event_counts") or {}
    if counts:
        out.append(
            "- events scanned: "
            + ", ".join(f"{k} {v}" for k, v in sorted(counts.items()))
        )

    # Activity — successes included. Without this the report only ever showed
    # what broke, so "what installed in the last hour?" had no answer.
    activity = bundle.get("command_activity") or {}
    by_status = activity.get("by_status") or {}
    by_type = activity.get("by_type") or {}
    installs = activity.get("installs") or {}
    if by_status or by_type or installs:
        out.append("\n## Activity")
        if by_status:
            out.append(
                "- command outcomes: "
                + ", ".join(f"{k} {v}" for k, v in sorted(by_status.items()))
            )
        if by_type:
            out.append(
                "- command types: "
                + ", ".join(
                    f"{t} ({', '.join(f'{s} {n}' for s, n in sorted(counts.items()))})"
                    for t, counts in sorted(by_type.items())[:_MAX_NOTABLE]
                )
            )
        if installs:
            out.append(
                f"- installs: {installs.get('total', 0)} — "
                + ", ".join(f"{k} {v}" for k, v in sorted((installs.get("by_outcome") or {}).items()))
            )
            pkgs = installs.get("packages") or {}
            shown = sorted(pkgs.items(), key=lambda kv: -sum(kv[1].values()))[:_MAX_NOTABLE]
            for pkg, counts in shown:
                detail = ", ".join(f"{k} {v}" for k, v in counts.items() if v)
                out.append(f"  - `{pkg}` — {detail}")
            if len(pkgs) > len(shown):
                out.append(f"  - _…{len(pkgs) - len(shown)} more packages_")

    findings = bundle.get("tier0_findings") or []
    out.append("\n## Findings")
    if findings:
        for f in findings:
            out.append(f"- **[{f.get('severity')}] {f.get('code')}** — {f.get('summary')}")
    else:
        out.append("- none — nothing in this window matched a Tier-0 rule")

    timelines = bundle.get("timelines") or []
    out.append("\n## Correlated round-trips")
    if not timelines:
        out.append("- none correlated in this window")
    for t in timelines[:_MAX_TIMELINES]:
        latency = t.get("latency_ms")
        latency_s = f"{latency} ms" if latency is not None else "latency unknown"
        out.append(
            f"\n### {t.get('command_type') or 'unknown command'} → "
            f"**{t.get('outcome')}** ({latency_s}, confidence {t.get('confidence')})"
        )
        events = t.get("events") or []
        for e in events[:_MAX_EVENTS_PER_TIMELINE]:
            out.append(
                f"- `{_hhmmss(e.get('timestamp'))}` {e.get('process')}: "
                f"{_clip(e.get('message', ''))}"
            )
        if len(events) > _MAX_EVENTS_PER_TIMELINE:
            out.append(f"- _…{len(events) - _MAX_EVENTS_PER_TIMELINE} more events_")
    if len(timelines) > _MAX_TIMELINES:
        out.append(f"\n_…{len(timelines) - _MAX_TIMELINES} more timelines omitted_")

    notable = bundle.get("notable_errors") or []
    out.append("\n## Notable errors")
    if notable:
        for e in notable[:_MAX_NOTABLE]:
            out.append(
                f"- `{_hhmmss(e.get('timestamp'))}` {e.get('process')}: "
                f"{_clip(e.get('message', ''))}"
            )
        if len(notable) > _MAX_NOTABLE:
            out.append(f"- _…{len(notable) - _MAX_NOTABLE} more_")
    else:
        out.append("- none")

    install = bundle.get("install_log")
    if install:
        out.append("\n## install.log")
        out.append(
            f"- {install.get('count', 0)} records · "
            f"{len(install.get('failures') or [])} failure(s)"
        )
        for f in (install.get("failures") or [])[:_MAX_NOTABLE]:
            out.append(
                f"- `{_hhmmss(f.get('timestamp'))}` {f.get('process')}: "
                f"{_clip(f.get('message', ''))}"
            )

    return "\n".join(out) + "\n"


def build_bundle(source, symptom: Optional[str], last: str) -> dict:
    return engine.build_incident_bundle(source, symptom=symptom, last=last)


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mcp-mdm-log-analyzer --report",
        description=(
            "Render a compact, redacted incident report from collected macOS "
            "MDM/DDM logs. Paste the output into any assistant, ticket, or "
            "email — no MCP client required."
        ),
        epilog=(
            "example: mcp-mdm-log-analyzer --report --symptom install_failure "
            "--last 1h --source ~/Downloads/mdm-logs-mac1.tar.gz"
        ),
    )
    p.add_argument("--report", action="store_true", help="render a report instead of running the MCP server")
    p.add_argument(
        "--source",
        metavar="PATH",
        help=".logarchive, collect-mdm-logs.sh .tar.gz/.zip, extracted bundle "
        "directory, or captured .ndjson. Defaults to MDM_LOG_ARCHIVE / "
        "MDM_LOG_FIXTURE, else the live log (macOS only).",
    )
    p.add_argument("--symptom", metavar="S", help=f"one of: {', '.join(SYMPTOMS)} (free text is keyword-matched)")
    p.add_argument("--last", default="1h", metavar="W", help="time window, e.g. 30m, 1h, 1d (default: 1h)")
    p.add_argument("--os-major", type=int, metavar="N", help="macOS major for predicate selection (bundles read it from os.txt)")
    p.add_argument("--format", choices=("md", "json"), default="md", help="md (default, pasteable) or json (uncapped)")
    p.add_argument("-o", "--output", metavar="FILE", help="write to FILE instead of stdout")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = _parser().parse_args(argv if argv is not None else sys.argv[1:])

    try:
        if args.source:
            source = sources.open_archive_source(args.source, os_major=args.os_major)
        else:
            source = sources.from_env(os_major=args.os_major)
    except (FileNotFoundError, ValueError, NotImplementedError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    try:
        bundle = build_bundle(source, args.symptom, args.last)
    except RuntimeError as e:  # e.g. `log show` failed on the live source
        print(f"error: {e}", file=sys.stderr)
        return 1

    text = (
        json.dumps(bundle, indent=2)
        if args.format == "json"
        else render_markdown(bundle, symptom=args.symptom, last=args.last)
    )

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"wrote {args.output} ({len(text)} bytes, ~{len(text) // 4} tokens)", file=sys.stderr)
    else:
        print(text)
    return 0
