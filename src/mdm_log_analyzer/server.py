"""MCP server exposing the Phase-1 tools (spec section 7).

Run on a Mac:
    mcp-mdm-log-analyzer            # live unified log (needs root for full access)
    MDM_LOG_ARCHIVE=/path.logarchive mcp-mdm-log-analyzer   # collected bundle

Or as a one-shot CLI, for clients that cannot run an MCP server (see report.py):
    mcp-mdm-log-analyzer --report --symptom install_failure --source bundle.tar.gz

The server is egress-free: it only reads local logs and returns structured,
redacted results over stdio. Whether anything crosses the network is decided
entirely by the MCP client's model choice (spec section 4).
"""
from __future__ import annotations

import hashlib
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _installed_version
from pathlib import Path
from typing import Optional

from mcp.server.mcpserver import MCPServer

from . import engine, sources
from .predicates import CATEGORIES


def _package_version() -> str:
    """Our own version, for the MCP handshake.

    FastMCP reported the SDK's version here rather than the server's, so clients
    saw "1.28.0" for a 0.1.x server. MCPServer takes it explicitly, so report the
    truth. Running from a source checkout without an install is normal (the smoke
    test does exactly that), hence the fallback.
    """
    try:
        return _installed_version("mdm-log-analyzer")
    except PackageNotFoundError:
        return "0+unknown"


mcp = MCPServer("mdm-log-analyzer", version=_package_version())

# Archives opened this session via open_archive: archive_id -> LogSource. Kept in
# memory only (stateless across runs); holds no unredacted corpus, just a handle.
_ARCHIVES: dict[str, "sources.LogSource"] = {}

# Hard ceiling on events returned by query_events, whatever the caller asks for.
MAX_EVENT_LIMIT = 5000


def _build_source(source: Optional[str] = None):
    """Select the source: a registered archive_id if given, else the
    environment (archive > fixture > live). Env selection lives in sources.py
    so the --report CLI shares it without importing the MCP SDK.
    """
    if source:
        if source in _ARCHIVES:
            return _ARCHIVES[source]
        raise ValueError(f"unknown source {source!r}; call open_archive first")
    return sources.from_env()


@mcp.tool()
def open_archive(path: str, os_major: Optional[int] = None) -> dict:
    """Register a collected .logarchive (or captured .ndjson) as a source.

    path:     path to a `.logarchive` bundle or a captured `.ndjson` export.
    os_major: optional macOS major for predicate selection (archive OS detection
              is a Mac follow-up; defaults to the latest known).

    Returns {archive_id, os_build, time_span}. Use archive_id as the `source`
    argument to the other tools. Sysdiagnose tarballs aren't supported yet —
    extract the .logarchive and pass that.
    """
    try:
        src = sources.open_archive_source(path, os_major=os_major)
    except (FileNotFoundError, ValueError, NotImplementedError) as e:
        return {"error": str(e)}
    info = src.probe()
    archive_id = "arch:" + hashlib.sha256(str(Path(path).resolve()).encode()).hexdigest()[:10]
    _ARCHIVES[archive_id] = src
    return {"archive_id": archive_id, "os_build": info["os_build"], "time_span": info["time_span"]}


@mcp.tool()
def query_events(
    category: str,
    last: str = "30m",
    level: Optional[str] = None,
    limit: int = 500,
    source: Optional[str] = None,
) -> dict:
    """Query normalized MDM/DDM log events for one category over a time window.

    category: one of mdm_command, enrollment, push, scheduling, asset_download,
              ddm, declaration, pkg_install, profile_payload.
    last:     time window, e.g. "30m", "2h", "1d".
    level:    "info" or "debug"; defaults to the category's recommended level.
    limit:    max events returned, capped at 5000 (count/truncated indicate if
              more exist).
    source:   optional archive_id from open_archive; defaults to the live/env source.

    Returns structured, redacted events. Never returns raw log text.
    """
    if category not in CATEGORIES:
        return {"error": f"unknown category {category!r}", "valid": list(CATEGORIES)}
    try:
        src = _build_source(source)
    except ValueError as e:
        return {"error": str(e)}
    # This tool is the guard against context blowup, so the cap is enforced here
    # rather than trusted to the caller. `count`/`truncated` still report the
    # true totals, so the model can tell it is seeing a subset.
    limit = max(1, min(limit, MAX_EVENT_LIMIT))
    return engine.query_events(src, category, last=last, level=level, limit=limit)


@mcp.tool()
def correlate_command(
    command_uuid: Optional[str] = None,
    command_type: Optional[str] = None,
    time_anchor: Optional[str] = None,
    last: str = "1h",
    source: Optional[str] = None,
) -> dict:
    """Stitch a single MDM command round-trip into one ordered timeline.

    Provide either command_uuid, or both command_type and time_anchor
    (ISO-8601). `source` is an optional archive_id from open_archive. Returns a
    timeline with outcome (Acknowledged/Error/NotNow/Idle/Unknown), latency_ms, a
    confidence rating, and the ordered events (push wake, receipt, processing,
    result), all redacted.
    """
    try:
        return engine.correlate_command(
            _build_source(source),
            command_uuid=command_uuid,
            command_type=command_type,
            time_anchor=time_anchor,
            last=last,
        )
    except ValueError as e:
        return {"error": str(e)}


@mcp.tool()
def get_install_log(
    package_name: Optional[str] = None,
    last: str = "1d",
    source: Optional[str] = None,
) -> dict:
    """Parse /var/log/install.log into installer/installd phases and outcomes.

    package_name: optional filter by bundle id or display-name substring.
    last:         time window, e.g. "1d", "2h" (live source only; ignored for
                  fixtures). Defaults to "1d".
    source:       optional archive_id from open_archive.

    Returns {count, phases, exit_codes, failures, sessions, session_summary}.
    `sessions` groups install.log into bracketed installs (Begin/End) with the
    package id, version, duration and outcome — the reportable unit, since the
    lines announcing an outcome carry no package identity of their own.
    Never returns raw log text. Archive sources do not yet supply install.log
    (pending open_archive, spec §7.6).
    """
    try:
        return engine.get_install_log(_build_source(source), package_name=package_name, last=last)
    except (NotImplementedError, ValueError) as e:
        return {"error": str(e)}


@mcp.tool()
def build_incident_bundle(
    symptom: Optional[str] = None,
    last: str = "1h",
    source: Optional[str] = None,
) -> dict:
    """Assemble one compact incident bundle for a symptom over a time window.

    symptom: a hint that routes which signals to gather.
             Failures: command_failure, install_failure, profile_failure,
             ddm_failure, enrollment_failure.
             Activity/reporting (successes included, not just errors):
             activity, app_activity, profile_activity, ddm_activity.
             Free text is keyword-matched, else a broad default is used.
    last:    time window, e.g. "1h", "30m".
    source:  optional archive_id from open_archive.

    Returns {context, command_activity, timelines, notable_errors,
    tier0_findings} (plus install_log when relevant) — structured and redacted.
    `command_activity` tallies outcomes by status and command type, and for
    install symptoms lists packages installed with success/failed counts, so
    routine activity is reportable and not only failures. Never returns raw log text. This is
    the anti-context-blowup wrapper: it caps the timelines and errors it returns.
    """
    try:
        src = _build_source(source)
    except ValueError as e:
        return {"error": str(e)}
    return engine.build_incident_bundle(src, symptom=symptom, last=last)


@mcp.tool()
def get_device_context(last: str = "1d", source: Optional[str] = None) -> dict:
    """Orient before querying: OS, enrollment, MDM server host, counts, check-in.

    last:   time window to scan for context signals, e.g. "1d", "12h".
    source: optional archive_id from open_archive.

    Returns {os, enrollment, mdm_server_host (hashed), installed_profiles,
    user_profiles, active_declarations, last_checkin}. Log-derived and redacted;
    counts come from mdmclient/declarative logs, not the live profiles store.

    `os.os_name` is already the platform name (e.g. "macOS 26.5.1") — report it
    as given. macOS major versions are literal, not a codename scheme to convert:
    26 means macOS 26, not macOS 14.
    """
    try:
        src = _build_source(source)
    except ValueError as e:
        return {"error": str(e)}
    return engine.get_device_context(src, last=last)


@mcp.tool()
def get_ddm_status(
    declaration_id: Optional[str] = None,
    last: str = "1h",
    source: Optional[str] = None,
) -> dict:
    """Reconstruct Declarative Device Management status from the device logs.

    declaration_id: optional filter (raw or hashed declaration id).
    last:           time window, e.g. "1h", "30m".
    source:         optional archive_id from open_archive.

    Returns {declarations, status_reports, failing, count} — declaration ids are
    hashed, the type prefix kept for readability. Log-derived from
    remotemanagementd / com.apple.dmd; an invalid declaration is usually
    Acknowledged and reported to the server out-of-band, so empty `failing` does
    not guarantee every declaration is valid.
    """
    try:
        src = _build_source(source)
    except ValueError as e:
        return {"error": str(e)}
    return engine.get_ddm_status(src, declaration_id=declaration_id, last=last)


def main() -> None:
    """Entry point. Bare invocation runs the MCP server over stdio — that is how
    every MCP client launches us, so it must stay the default. `--report`
    switches to the one-shot CLI for clients that cannot run MCP at all.
    """
    import sys

    if "--report" in sys.argv[1:]:
        from . import report

        raise SystemExit(report.main(sys.argv[1:]))
    if any(a in ("-h", "--help") for a in sys.argv[1:]):
        from . import report

        report._parser().print_help()
        raise SystemExit(0)
    mcp.run()


if __name__ == "__main__":
    main()
