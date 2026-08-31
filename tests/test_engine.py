"""Engine tests, runnable anywhere via FixtureLogSource (no macOS needed)."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import tempfile  # noqa: E402

from mdm_log_analyzer import engine, sources  # noqa: E402
from mdm_log_analyzer.redact import scrub_message  # noqa: E402
from mdm_log_analyzer.sources import FixtureLogSource  # noqa: E402

FIXTURE = Path(__file__).parent / "fixtures" / "mdm_sample.ndjson"
TRIAGE_FIXTURE = Path(__file__).parent / "fixtures" / "mdm_triage.ndjson"
INSTALL_FIXTURE = Path(__file__).parent / "fixtures" / "install_sample.log"
DDM_FIXTURE = Path(__file__).parent / "fixtures" / "mdm_ddm.ndjson"
DEVCTX_FIXTURE = Path(__file__).parent / "fixtures" / "mdm_device_context.ndjson"


def make_ddm_source():
    return FixtureLogSource(DDM_FIXTURE, os_major=26)


def trace_of(ref):
    """The traceID portion of a raw_ref.

    raw_ref is `traceID:machTimestamp` (or `traceID:timestamp`) so that it is
    unique per LINE — traceID alone identifies the emitting code site, which
    made dedupe collapse distinct events. Tests below use the fixtures' traceIDs
    as event labels, so they compare this portion rather than the full pointer.
    """
    return ref.split(":", 1)[0]


def make_source():
    return FixtureLogSource(FIXTURE, os_major=15)


def make_install_source():
    return FixtureLogSource(FIXTURE, os_major=15, install_log_path=INSTALL_FIXTURE)


def make_triage_source():
    return FixtureLogSource(TRIAGE_FIXTURE, os_major=15)


def codes(timeline):
    return {f["code"] for f in timeline["tier0_findings"]}


def test_query_filters_by_category():
    src = make_source()
    res = engine.query_events(src, "mdm_command", last="1h")
    # 5 mdmclient lines in the fixture; WindowServer/apsd/dasd excluded.
    assert res["count"] == 5
    assert all(e["process"] == "mdmclient" for e in res["events"])
    assert res["predicate_version"] == 15
    assert res["exact_version_match"] is True


def test_query_push_category():
    src = make_source()
    res = engine.query_events(src, "push", last="1h")
    assert res["count"] == 1
    assert res["events"][0]["process"] == "apsd"


def test_normalization_extracts_command_fields():
    src = make_source()
    res = engine.query_events(src, "mdm_command", last="1h")
    by_status = {e.get("status") for e in res["events"]}
    assert "NotNow" in by_status
    assert "Error" in by_status
    assert "Acknowledged" in by_status
    # command_type appears on the "Received" line; the response line carries the
    # error_code. (This split is exactly why correlate_command stitches them.)
    recv = next(
        e for e in res["events"] if "Received MDM command" in e["message"]
        and e.get("command_type") == "InstallApplication"
    )
    assert recv["command_uuid"].startswith("h:")
    err = next(e for e in res["events"] if e.get("status") == "Error")
    assert err["error_code"] == 12063


def test_redaction_hashes_and_scrubs():
    src = make_source()
    res = engine.query_events(src, "mdm_command", last="1h")
    recv = next(
        e for e in res["events"] if "Received MDM command" in e["message"]
    )
    # UUID is hashed, not raw.
    assert recv["command_uuid"].startswith("h:")
    assert "AAA-111" not in recv["command_uuid"]
    # Serial number scrubbed from the visible message; device_ref hashed.
    assert "C02ABC123DEF" not in recv["message"]
    assert recv["device_ref"].startswith("h:")
    # Email scrubbed from the profile-install message.
    prof = next(e for e in res["events"] if e.get("command_type") == "InstallProfile")
    assert "admin@example.com" not in prof["message"]


def test_correlate_failed_install_by_uuid():
    src = make_source()
    tl = engine.correlate_command(src, command_uuid="AAA-111", last="1h")
    assert tl["command_type"] == "InstallApplication"
    assert tl["outcome"] == "Error"
    assert tl["confidence"] == "high"
    # Should include push + download context plus the core mdmclient events.
    procs = [e["process"] for e in tl["events"]]
    assert "apsd" in procs
    assert "storedownloadd" in procs
    assert "mdmclient" in procs
    # Latency from first event to the terminal Error (~30.4s).
    assert tl["latency_ms"] is not None and tl["latency_ms"] > 25_000
    # No duplicate log lines (overlapping ddm/mdm_command predicates).
    refs = [e["raw_ref"] for e in tl["events"]]
    assert len(refs) == len(set(refs))
    # The AAA-111 round-trip is exactly 3 mdmclient lines.
    assert sum(1 for e in tl["events"] if e["process"] == "mdmclient") == 3


def test_correlate_successful_profile_by_uuid():
    src = make_source()
    tl = engine.correlate_command(src, command_uuid="BBB-222", last="1h")
    assert tl["outcome"] == "Acknowledged"
    assert tl["command_type"] == "InstallProfile"


def test_correlate_unknown_uuid_is_low_confidence():
    src = make_source()
    tl = engine.correlate_command(src, command_uuid="ZZZ-999", last="1h")
    assert tl["outcome"] == "Unknown"
    assert tl["confidence"] == "low"
    assert tl["events"] == []


def test_triage_failed_install_flags_error_and_download():
    src = make_source()
    tl = engine.correlate_command(src, command_uuid="AAA-111", last="1h")
    c = codes(tl)
    assert "terminal_error" in c
    # The asset download was in flight when the command failed.
    assert "download_stall" in c
    # A single NotNow is not a loop; push was present; latency < threshold.
    assert "notnow_loop" not in c
    assert "missing_push" not in c
    assert "high_latency" not in c
    err = next(f for f in tl["tier0_findings"] if f["code"] == "terminal_error")
    assert err["severity"] == "error"
    assert "12063" in err["summary"]
    assert err["evidence"]  # carries raw_ref pointers, not raw text


def test_triage_clean_install_has_no_error_findings():
    src = make_source()
    tl = engine.correlate_command(src, command_uuid="BBB-222", last="1h")
    assert all(f["severity"] != "error" for f in tl["tier0_findings"])
    assert "terminal_error" not in codes(tl)


def test_triage_notnow_loop_and_private_and_no_terminal():
    src = make_triage_source()
    tl = engine.correlate_command(src, command_uuid="CCC-333", last="1h")
    c = codes(tl)
    assert "notnow_loop" in c          # two NotNow responses
    assert "private_data_masked" in c  # a <private> message body
    assert "no_terminal" in c          # never reached Acknowledged/Error


def test_triage_unknown_uuid_has_no_findings():
    src = make_source()
    tl = engine.correlate_command(src, command_uuid="ZZZ-999", last="1h")
    assert tl["tier0_findings"] == []


def test_redaction_keeps_uppercase_words_but_scrubs_serials():
    # Over-match guard: all-caps diagnostic words must survive redaction; real
    # Apple serials (letters + digits) must still be scrubbed.
    out = scrub_message("NOTNOWREASON DEVICELOCKED serial C02ABC123DEF here")
    assert "NOTNOWREASON" in out
    assert "DEVICELOCKED" in out
    assert "C02ABC123DEF" not in out
    assert "<redacted-serial>" in out
    # Pure-numeric device IDs (IMEI etc.) are still scrubbed; short codes survive.
    numeric = scrub_message("IMEI 490154203237518 ErrorCode 12063 adamId 998877")
    assert "490154203237518" not in numeric
    assert "12063" in numeric and "998877" in numeric


SESSIONS_FIXTURE = Path(__file__).parent / "fixtures" / "install_sessions.log"


def test_install_sessions_name_the_package_and_outcome():
    # The lines that announce an outcome ("Starting installation:", "Displaying
    # 'Install Succeeded' UI.") carry NO package identity — the id is on a
    # PackageKit continuation line with no timestamp, which a line-anchored
    # parser drops. That is why every install used to report package=None.
    from mdm_log_analyzer import install_log

    sessions = install_log.parse_sessions(SESSIONS_FIXTURE.read_text())
    assert len(sessions) == 3, [s.package for s in sessions]

    # Selected by outcome, not position: sessions are ordered by UTC start, and
    # the fixture's offsets (+05:30 vs -04) deliberately make UTC order differ
    # from file order.
    by_outcome = {s.outcome: s for s in sessions}
    ok, failed, orphan = (
        by_outcome["success"],
        by_outcome["failed"],
        by_outcome["incomplete"],
    )
    assert [s.started for s in sessions] == sorted(s.started for s in sessions)
    assert ok.package == "com.acme.agent" and ok.version == "3.4.1"
    assert ok.outcome == "success"
    assert ok.duration_ms == 4000  # 17:45:59 -> 17:46:03

    assert failed.package == "com.acme.broken"
    assert failed.outcome == "failed"
    assert 77 in failed.exit_codes
    assert failed.failure and "Install Failed" in failed.failure

    # A bracket that never closes is reported, not silently dropped — an install
    # that never finished is exactly what a report should surface.
    assert orphan.outcome == "incomplete"
    assert orphan.package == "orphan.pkg"  # url fallback when no id= is present


def test_install_sessions_accept_every_real_timezone_shape():
    # Real logs carry -0400, +05:30 AND a bare -04. The bare form silently
    # dropped 5 of 142 sessions on a real capture before it was allowed.
    from mdm_log_analyzer import install_log

    sessions = install_log.parse_sessions(SESSIONS_FIXTURE.read_text())
    # The failed session is the one logged with the bare "-04" offset.
    failed = next(s for s in sessions if s.outcome == "failed")
    assert failed.started.endswith("Z"), failed.started
    assert failed.started.startswith("2026-08-06T21:50"), failed.started  # -04 -> UTC


def test_install_log_reports_sessions_and_a_summary():
    from mdm_log_analyzer.sources import FixtureLogSource

    src = FixtureLogSource(FIXTURE, os_major=15, install_log_path=SESSIONS_FIXTURE)
    res = engine.get_install_log(src, last="1d")
    assert len(res["sessions"]) == 3
    summary = res["session_summary"]
    assert summary["total"] == 3
    assert summary["by_outcome"] == {"success": 1, "failed": 1, "incomplete": 1}
    assert summary["packages"]["com.acme.broken"]["failed"] == 1
    # Filtering by package narrows sessions too, not just flat records.
    only = engine.get_install_log(src, package_name="broken", last="1d")
    assert [s["package"] for s in only["sessions"]] == ["com.acme.broken"]


def test_incident_bundle_reports_activity_not_only_failures():
    # The symptom vocabulary was failure-only, so "what installed in the last
    # hour?" was unaskable even though the data was already collected.
    from mdm_log_analyzer.sources import FixtureLogSource

    # 1d, not 1h: the install.log window is real now (it used to be ignored for
    # capture sources), and this fixture deliberately mixes timezone offsets, so
    # its sessions span ~9h in absolute UTC. The window itself is covered by
    # test_install_log_honours_the_time_window.
    src = FixtureLogSource(FIXTURE, os_major=15, install_log_path=SESSIONS_FIXTURE)
    b = engine.build_incident_bundle(src, symptom="app_activity", last="1d")

    activity = b["command_activity"]
    # Successes are counted, not just errors.
    assert activity["by_status"].get("Acknowledged", 0) >= 1, activity["by_status"]
    assert "InstallApplication" in activity["by_type"]
    assert activity["installs"]["by_outcome"]["success"] == 1

    # Activity symptoms route without being swallowed by the failure keywords.
    from mdm_log_analyzer.engine import _resolve_plan

    assert _resolve_plan("app_activity") == _resolve_plan("what installed")
    assert _resolve_plan("report of app installations")[1] is True  # pulls install log
    # DDM symptoms query the declarative-subsystem-only category, plus
    # mdm_command for the DeclarativeManagement command's own status. The broad
    # `ddm` category also matches all of mdmclient, which filled DDM bundles
    # with managed-app noise labelled category "ddm".
    assert _resolve_plan("ddm activity") == (("declaration", "mdm_command"), False)


def test_report_renders_a_pasteable_incident_report():
    # The --report path exists for clients that cannot run MCP at all (ChatGPT,
    # a browser, a ticket). It must carry the diagnosis AND stay small enough to
    # paste, so assert both.
    from mdm_log_analyzer import report

    src = make_source()
    bundle = report.build_bundle(src, "install_failure", "1h")
    md = report.render_markdown(bundle, symptom="install_failure", last="1h")

    # The diagnosis survives the rendering.
    assert "# MDM incident report — install_failure" in md
    assert "terminal_error" in md
    assert "InstallApplication" in md and "Error" in md
    assert "macOS 15" in md  # named, not a bare integer

    # Redaction survives it too — this text gets pasted into a third party.
    assert "C02ABC123DEF" not in md
    assert "admin@example.com" not in md
    # The fixture names the serial by its key (`SerialNumber=…`), so it is
    # HASHED rather than blanked: two events about one device still correlate,
    # which a `<redacted-serial>` placeholder cannot do. A serial appearing bare
    # in prose is still blanked by the value-shape rule — see
    # test_redaction_covers_every_class_the_docs_promise.
    assert "h-" in md

    # Small enough for any chat box (this fixture is tiny; the caps hold the
    # real ceiling). ~4 chars/token.
    assert len(md) < 8000, len(md)


def test_report_caps_runaway_timelines_and_events():
    from mdm_log_analyzer import report

    ev = [
        {"timestamp": f"2026-06-19T21:03:{i:02d}.000Z", "process": "mdmclient", "message": "x" * 400}
        for i in range(40)
    ]
    bundle = {
        "context": {"os_name": "macOS 26", "predicate_version": 26, "event_counts": {}},
        "timelines": [
            {"command_type": "InstallProfile", "outcome": "Error", "latency_ms": 1,
             "confidence": "high", "events": ev}
            for _ in range(20)
        ],
        "notable_errors": ev,
        "tier0_findings": [],
    }
    md = report.render_markdown(bundle, symptom="command_failure", last="1h")
    assert md.count("### InstallProfile") == report._MAX_TIMELINES
    assert "more timelines omitted" in md
    assert "more events" in md
    # Long messages are clipped, so one pathological line cannot blow the paste up.
    assert "x" * 400 not in md
    assert len(md) < 20000, len(md)


def test_report_json_format_is_the_uncapped_bundle():
    import json as _json

    from mdm_log_analyzer import report

    src = make_source()
    bundle = report.build_bundle(src, "install_failure", "1h")
    assert _json.loads(_json.dumps(bundle)) == bundle  # serializable as-is
    assert set(bundle) >= {"context", "timelines", "notable_errors", "tier0_findings"}


def test_device_context_labels_the_os_so_models_cannot_reinvent_it():
    # A bare `os_major: 26` reads like a number needing translation: on real
    # captures a 7B model turned 26 into "macOS 14, or Ventura" and 27 into
    # "macOS 13". The server was right both times; the prose was not. Emitting a
    # named platform leaves nothing to convert.
    work = Path(tempfile.mkdtemp()) / "mdm-logs-x"
    work.mkdir()
    (work / "os.txt").write_text(
        "ProductName:\tmacOS\nProductVersion:\t26.5.1\nBuildVersion:\t25F80\n"
    )
    (work / "m.ndjson").write_text(
        '{"process":"mdmclient","subsystem":"com.apple.ManagedClient",'
        '"timestamp":"2026-08-12 10:00:00.000000-0700","eventMessage":"x","traceID":"t"}\n'
    )
    os_info = engine.get_device_context(sources.BundleLogSource(work), last="1d")["os"]
    assert os_info["os_name"] == "macOS 26.5.1", os_info
    assert os_info["os_major"] == 26

    # No full version available -> still named, just coarser.
    fx = FixtureLogSource(FIXTURE, os_major=15)
    assert engine.get_device_context(fx, last="1h")["os"]["os_name"] == "macOS 15"

    # An os_major override must win over a disagreeing os.txt, so the label can
    # never contradict the predicates actually used.
    mixed = sources.BundleLogSource(work, os_major=15)
    assert engine.get_device_context(mixed, last="1d")["os"]["os_name"] == "macOS 15"

    # The incident bundle carries the same label.
    assert engine.build_incident_bundle(
        sources.BundleLogSource(work), symptom="command_failure", last="1d"
    )["context"]["os_name"] == "macOS 26.5.1"


def test_path_guard_uses_path_semantics_not_string_prefixes():
    # The guard used `str(target).startswith(str(root) + "/")`, which hardcodes
    # the POSIX separator: on Windows EVERY legitimate archive member failed it,
    # so bundles could not be opened at all. Assert both flavours.
    from pathlib import PurePosixPath, PureWindowsPath

    from mdm_log_analyzer.sources import _within

    win_root = PureWindowsPath(r"C:\Users\admin\AppData\Local\Temp\mdm")
    assert _within(win_root, win_root / "mdm-logs-x" / "os.txt")
    assert not _within(win_root, PureWindowsPath(r"C:\Windows\System32\drivers\etc\hosts"))

    posix_root = PurePosixPath("/tmp/mdm")
    assert _within(posix_root, PurePosixPath("/tmp/mdm/mdm-logs-x/os.txt"))
    assert not _within(posix_root, PurePosixPath("/etc/passwd"))
    # A sibling sharing a name prefix must not pass (the old string check let
    # "/tmp/mdm-evil" through against root "/tmp/mdm" only by luck of the "/").
    assert not _within(posix_root, PurePosixPath("/tmp/mdm-evil/os.txt"))


def test_ndjson_sources_honour_the_time_window():
    # FixtureLogSource/BundleLogSource used to ignore `last` entirely, so a
    # caller asking for 1h silently received the whole capture. The window is
    # anchored on the newest event in the data, not wall-clock now — a collected
    # archive is analyzed long after capture, where wall-clock returns nothing.
    fixture = Path(__file__).parent / "fixtures" / "mdm_seq_collision.ndjson"
    src = FixtureLogSource(fixture, os_major=26)  # spans 01:20 -> 03:20 (2h)

    wide = engine.query_events(src, "mdm_command", last="6h")
    narrow = engine.query_events(src, "mdm_command", last="1h")
    assert wide["count"] == 4, wide["count"]
    # Only the later check-in (c-003/c-004) is within 1h of the newest event.
    assert narrow["count"] == 2, narrow["count"]
    assert {trace_of(e["raw_ref"]) for e in narrow["events"]} == {"c-003", "c-004"}

    # An unparseable window is a no-op rather than an empty result.
    assert engine.query_events(src, "mdm_command", last="banana")["count"] == 4


def test_open_archive_accepts_a_finder_style_zip():
    # macOS Finder's "Compress" makes .zip, so that is what admins actually
    # send. Rejecting it pushed people to attach the file to the chat instead,
    # which skips redaction entirely.
    import zipfile

    work = Path(tempfile.mkdtemp())
    bundle = work / "mdm-logs-mac1"
    bundle.mkdir()
    (bundle / "os.txt").write_text("ProductName:\tmacOS\nProductVersion:\t26.5.1\n")
    (bundle / "mdmclient.ndjson").write_text(
        '{"process":"mdmclient","subsystem":"com.apple.ManagedClient",'
        '"timestamp":"2026-08-12 10:00:00.000000-0700",'
        '"eventMessage":"[Acknowledged(InstallProfile):700]","traceID":"z1"}\n'
    )
    zip_path = work / "bundle.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        for f in bundle.iterdir():
            zf.write(f, f"mdm-logs-mac1/{f.name}")
        # Finder also stores resource forks; they must not confuse detection.
        zf.writestr("__MACOSX/mdm-logs-mac1/._os.txt", "resource fork junk")

    src = sources.open_archive_source(zip_path)
    assert type(src).__name__ == "BundleLogSource"
    assert src.os_major == 26  # read from os.txt, not guessed
    assert engine.query_events(src, "mdm_command", last="1d")["count"] == 1


def test_open_archive_rejects_zip_traversal():
    import zipfile

    work = Path(tempfile.mkdtemp())
    zip_path = work / "evil.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("mdm-logs-x/os.txt", "ProductVersion:\t26.5.1\n")
        zf.writestr("../../../../tmp/pwned.txt", "escaped")
    try:
        sources.open_archive_source(zip_path)
        assert False, "expected ValueError for unsafe zip member"
    except ValueError as e:
        assert "unsafe zip member" in str(e), e


def test_redaction_covers_every_class_the_docs_promise():
    # Spec §4.3 (and README/SETUP) promise serials, UDIDs, usernames, user ids,
    # IP/MAC, tokens and SCEP/payload secrets never leave the server. One case
    # per promised class — the raw value must not survive.
    cases = [
        ("MAC colon", "en0 hwaddr 3c:22:fb:aa:bb:cc up", "3c:22:fb:aa:bb:cc"),
        ("MAC hyphen", "en0 hwaddr 3C-22-FB-AA-BB-CC up", "3C-22-FB-AA-BB-CC"),
        ("IPv6", "peer 2001:0db8:85a3:0000:0000:8a2e:0370:7334", "2001:0db8:85a3"),
        ("IPv6 compressed", "bound fe80::1c2d", "fe80::1c2d"),
        ("IPv4", "server at 10.11.12.13", "10.11.12.13"),
        ("UDID", "UDID=564D1A2B-3C4D-5E6F-7A8B-9C0D1E2F3A4B", "564D1A2B-3C4D"),
        ("serial", "SerialNumber C02ABC123DEF", "C02ABC123DEF"),
        ("username", "staging /Users/jdoe/Library", "jdoe"),
        ("uid", "PKInstallDaemonClient pid=4242, uid=501", "uid=501"),
        ("email", "profile for alice@corp.example.com", "alice@corp.example.com"),
        ("SCEP challenge", "SCEP challenge=SuperSecret123", "SuperSecret123"),
        ("password", "payload Password: hunter2", "hunter2"),
        ("bearer token", "Authorization: Bearer abc.def.ghi", "abc.def.ghi"),
        ("push token", "token 0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f6071", "0a1b2c3d"),
    ]
    for label, message, secret in cases:
        assert secret not in scrub_message(message), f"{label} leaked: {message!r}"


def test_redaction_does_not_damage_diagnostic_text():
    # The scrubbers run over every message, so over-matching costs real signal.
    # A timestamp is three colon-separated hex-valid groups ("14:03:12") and an
    # IPv6 rule permitting three groups destroys it.
    ts = "2026-06-19 14:03:12.481920-0700 mdmclient started"
    assert scrub_message(ts) == ts
    bracket = "Received HTTP response (200) [Acknowledged(InstallProfile):700]"
    assert scrub_message(bracket) == bracket
    # <private> is macOS's own masking marker and triage.py keys a finding off
    # it — scrubbing it would hide the signal that says detail is missing.
    assert "<private>" in scrub_message("challenge: <private>")
    # /Users/Shared is not a person.
    assert scrub_message("/Users/Shared/pkg") == "/Users/Shared/pkg"
    # Reverse-DNS bundle ids are the install-log analytic key.
    assert scrub_message("com.apple.MobileDevices") == "com.apple.MobileDevices"


def test_redaction_hashes_preserve_correlation():
    # Hashing (not blanking) identifiers is what lets the model still say "same
    # declaration across events" — spec §4.3. Blanking would collapse them.
    one = scrub_message("id com.acme.declaration.aaaa1111-bbbb-2222-cccc-de3344445f55")
    same = scrub_message("again com.acme.declaration.aaaa1111-bbbb-2222-cccc-de3344445f55")
    other = scrub_message("id com.acme.declaration.ffff9999-eeee-8888-ffff-0a0b1c2d3e4f")
    assert one.split()[-1] == same.split()[-1]
    assert one.split()[-1] != other.split()[-1]
    # Inline hashes must stay a single token: ddm_status re-parses declaration
    # ids out of scrubbed messages, and a ':' would truncate them there.
    assert ":" not in one.split()[-1]


def test_install_log_parses_phases_and_failure():
    src = make_install_source()
    res = engine.get_install_log(src, last="1d")
    phases = {p["phase"] for p in res["phases"]}
    # Real macOS 26 phrasing: Extracting / Executing script / 'Install Succeeded' UI.
    assert {"extract", "script", "success", "failed"} <= phases
    # The Globex postinstall script exited with status 1.
    assert res["failures"], "expected at least one failure"
    fail = next(f for f in res["failures"] if f.get("package") == "com.globex.vpn")
    assert fail["phase"] == "failed"
    codes = [c["exit_code"] for c in res["exit_codes"]]
    assert 1 in codes


def test_install_log_filters_by_package():
    src = make_install_source()
    res = engine.get_install_log(src, package_name="acme", last="1d")
    assert res["count"] >= 1
    assert all(p.get("package") == "com.acme.agent" for p in res["phases"])
    # Acme succeeded (no failed phase), so no failures in this filtered view.
    assert res["failures"] == []


def test_install_log_missing_source_returns_error_via_tool():
    # A fixture source with no install_log_path raises; engine surfaces cleanly.
    src = make_source()
    try:
        engine.get_install_log(src, last="1d")
        assert False, "expected NotImplementedError"
    except NotImplementedError:
        pass


MDM26_FIXTURE = Path(__file__).parent / "fixtures" / "mdm_sample_26.ndjson"


def make_26_source():
    return FixtureLogSource(MDM26_FIXTURE, os_major=26)


def test_macos26_normalize_extracts_bracket_status_and_type():
    # Real macOS 26 format: status+type ride in "[Status(CommandType):n]" and on
    # receipt in "Processing server request: <Type>". No CommandUUID is exposed.
    src = make_26_source()
    res = engine.query_events(src, "mdm_command", last="1h")
    events = res["events"]
    # Receipt line yields command_type without any RequestType= phrasing.
    assert any(e.get("command_type") == "InstallProfile" for e in events)
    # Result bracket yields both status and command_type.
    ack = next(e for e in events if e.get("status") == "Acknowledged")
    assert ack["command_type"] == "InstallProfile"
    err = next(e for e in events if e.get("status") == "Error")
    assert err["command_type"] == "InstallApplication"
    assert err.get("reason") == "Error (InstallApplication)"
    # Bare [Idle] keep-alive is a non-terminal status with no command type.
    assert any(e.get("status") == "Idle" for e in events)
    # The check-in sequence number is extracted from the bracket and the receipt.
    assert any(e.get("command_seq") == "700" for e in events)
    # The InstallApplication sub-step exposes an operation UUID (UUID:/ID: form).
    assert any(e.get("command_uuid", "").startswith("h:") for e in events)
    # ...but the protocol-level check-in lines still carry no UUID.
    ack = next(e for e in events if e.get("status") == "Acknowledged")
    assert "command_uuid" not in ack


def test_macos26_correlate_by_sequence_links_receipt_to_result():
    # Receipt (700) and result bracket [Acknowledged(InstallProfile):700] share a
    # sequence number -> deterministic round-trip, high confidence, no time guess.
    src = make_26_source()
    tl = engine.correlate_command(
        src, command_type="InstallProfile", time_anchor="2026-06-26T08:20:01Z", last="1h"
    )
    assert tl["command_type"] == "InstallProfile"
    assert tl["outcome"] == "Acknowledged"
    assert tl["confidence"] == "high"
    # Distinct sequence (701, the InstallApplication Error) must NOT bleed in.
    assert all(e.get("command_seq") in (None, "700") for e in tl["events"])
    assert "terminal_error" not in {f["code"] for f in tl["tier0_findings"]}


def test_sequence_collision_does_not_overmerge_distant_checkins():
    # Two InstallProfile check-ins reuse sequence 700 two hours apart. Correlating
    # the first must NOT pull in the second's Error result (seq is windowed, not
    # a global key) — otherwise confidence/outcome would be wrong.
    fixture = Path(__file__).parent / "fixtures" / "mdm_seq_collision.ndjson"
    src = FixtureLogSource(fixture, os_major=26)
    tl = engine.correlate_command(
        src, command_type="InstallProfile", time_anchor="2026-06-26T08:20:00Z", last="6h"
    )
    assert tl["outcome"] == "Acknowledged"  # the first check-in, not the later Error
    refs = {trace_of(e["raw_ref"]) for e in tl["events"]}
    assert refs == {"c-001", "c-002"}  # second check-in (c-003/c-004) excluded


def test_macos26_correlate_install_app_captures_substep_and_error():
    # The InstallApplication round-trip is keyed by (type, seq 701); the seq-less
    # StartInstall sub-step (carrying the operation UUID) attaches via thread.
    src = make_26_source()
    tl = engine.correlate_command(
        src, command_type="InstallApplication", time_anchor="2026-06-26T08:21:10Z", last="1h"
    )
    assert tl["command_type"] == "InstallApplication"
    assert tl["outcome"] == "Error"
    assert tl["confidence"] == "high"
    msgs = " ".join(e["message"] for e in tl["events"])
    assert "StartInstall" in msgs and "Error(InstallApplication)" in msgs
    # The earlier InstallProfile round-trip (seq 700, different thread) stays out.
    assert all(e.get("command_seq") in (None, "701") for e in tl["events"])


def test_macos26_ddm_predicate_matches_declarative_subsystems():
    src = make_26_source()
    res = engine.query_events(src, "ddm", last="1h")
    assert res["predicate_version"] == 26
    # The com.apple.dmd declarative line is captured by the pinned predicate.
    assert any(e.get("subsystem") == "com.apple.dmd" for e in res["events"])


def test_predicate_macos27_is_exact_match():
    # Latest shipped predicate file — a macOS 27 machine resolves to 27.json
    # exactly, not the fallback to 26.
    from mdm_log_analyzer import predicates

    res = predicates.resolve("mdm_command", os_major=27)
    assert res["predicate_version"] == 27
    assert res["exact_version_match"] is True
    # macOS 25 (never shipped) still falls back to the highest <= available file (15).
    assert predicates.resolve("mdm_command", os_major=25)["predicate_version"] == 15


def test_predicate_files_exist_and_pin_ddm():
    from mdm_log_analyzer import predicates

    for major in (11, 14, 15, 26, 27):
        res = predicates.resolve("mdm_command", os_major=major)
        assert res["predicate_version"] == major
        assert res["exact_version_match"] is True
    # Sequoia DDM is pinned to the real declarative daemons, not the old
    # mdmclient-only placeholder.
    ddm15 = predicates.resolve("ddm", os_major=15)["predicate"]
    assert "com.apple.dmd" in ddm15 and "remotemanagementd" in ddm15
    # Monterey/Ventura (12/13) have no own file; they fall back to 11, which
    # still carries the DDM daemon set so Ventura DDM keeps matching.
    for major in (12, 13):
        assert predicates.resolve("mdm_command", os_major=major)["predicate_version"] == 11
    assert "com.apple.dmd" in predicates.resolve("ddm", os_major=13)["predicate"]
    # 27 inherits the same DDM daemons from 26 (marked medium-confidence + unconfirmed).
    ddm27 = predicates.resolve("ddm", os_major=27)["predicate"]
    assert "com.apple.dmd" in ddm27 and "remotemanagementd" in ddm27
    # A future unshipped release (macOS 28) falls back to 27.
    assert predicates.resolve("mdm_command", os_major=28)["predicate_version"] == 27


def test_incident_bundle_command_failure_assembles_timelines():
    src = make_source()
    b = engine.build_incident_bundle(src, symptom="command_failure", last="1h")
    # Both fixture commands surface as timelines.
    types = {tl["command_type"] for tl in b["timelines"]}
    assert "InstallApplication" in types
    outcomes = {tl["outcome"] for tl in b["timelines"]}
    assert {"Error", "Acknowledged"} <= outcomes
    # The terminal Error is a notable error, deduped by raw_ref.
    refs = [e["raw_ref"] for e in b["notable_errors"]]
    assert len(refs) == len(set(refs))
    assert any(e.get("status") == "Error" for e in b["notable_errors"])
    # Aggregated Tier-0 findings include the failed install's terminal_error.
    assert "terminal_error" in {f["code"] for f in b["tier0_findings"]}
    # Context is present and off-Mac-derivable; no install log for this symptom.
    assert b["context"]["os_major"] == 15
    assert b["context"]["predicate_version"] == 15
    assert b["context"]["event_counts"].get("mdm_command", 0) >= 1
    assert "install_log" not in b


def test_incident_bundle_install_failure_includes_install_findings():
    src = make_install_source()
    b = engine.build_incident_bundle(src, symptom="install_failure", last="1d")
    assert "install_log" in b
    assert b["install_log"]["failures"]
    codes = {f["code"] for f in b["tier0_findings"]}
    assert "pkg_install_failure" in codes
    pkg_finding = next(f for f in b["tier0_findings"] if f["code"] == "pkg_install_failure")
    assert pkg_finding["severity"] == "error"
    assert "com.globex.vpn" in pkg_finding["summary"]


def test_incident_bundle_notable_errors_filters_subsystem_noise():
    # A real macOS 27 admin bundle over 12h picked up SQLite "cannot open" and
    # apsd XPC teardown lines as "notable errors" — because they're logged at
    # error level even though they're not MDM command failures. notable_errors
    # must only surface: (a) real MDM command Errors (status=Error from the
    # [Error(Type):n] bracket), and (b) rare `fault`-level lines. Benign
    # `error`-level subsystem noise is filtered out.
    fixture = Path(__file__).parent / "fixtures" / "mdm_noise.ndjson"
    src = FixtureLogSource(fixture, os_major=26)
    b = engine.build_incident_bundle(src, symptom="command_failure", last="1d")
    refs = {trace_of(e["raw_ref"]) for e in b["notable_errors"]}

    # KEEP: the real InstallProfile Error round-trip (status=Error).
    assert "real-err" in refs
    # KEEP: the apsd fault (rare + meaningful).
    assert "noise-003" in refs
    # DROP: subsystem noise at error level (SQLite, apsd XPC teardown).
    assert "noise-001" not in refs
    assert "noise-002" not in refs


def test_incident_bundle_free_text_symptom_falls_back_gracefully():
    # No install_log_path configured -> get_install_log raises internally and is
    # swallowed; the bundle still assembles from the default plan.
    src = make_source()
    b = engine.build_incident_bundle(src, symptom="something is broken", last="1h")
    assert set(b.keys()) >= {"context", "timelines", "notable_errors", "tier0_findings"}
    assert "install_log" not in b  # install log unavailable for this fixture source


def test_device_context_log_derived():
    src = FixtureLogSource(DEVCTX_FIXTURE, os_major=26)
    ctx = engine.get_device_context(src, last="1d")
    assert ctx["enrollment"] == "managed"
    # MDM server host is hashed, never raw.
    assert ctx["mdm_server_host"].startswith("h:")
    assert "example-tenant.com" not in ctx["mdm_server_host"]
    # Profile counts by scope, declaration count, and OS resolution.
    assert ctx["installed_profiles"] == 13
    assert ctx["user_profiles"] == 2
    assert ctx["active_declarations"] == 1
    assert ctx["os"]["predicate_version"] == 26
    # last check-in is the most recent event (the "No commands from server" line).
    assert ctx["last_checkin"] == "2026-06-26T09:01:00.000Z"


def test_device_context_unmanaged_when_no_server():
    # A capture with no MDM server line -> enrollment unknown, host None.
    src = make_source()  # the legacy mdm_sample fixture has no MDM_Connect/server line
    ctx = engine.get_device_context(src, last="1h")
    assert ctx["enrollment"] == "unknown"
    assert ctx["mdm_server_host"] is None


def test_incident_bundle_includes_device_context():
    src = FixtureLogSource(DEVCTX_FIXTURE, os_major=26)
    b = engine.build_incident_bundle(src, symptom="command_failure", last="1d")
    assert b["context"]["device"] is not None
    assert b["context"]["device"]["enrollment"] == "managed"


def test_ddm_status_declarations_and_reports():
    src = make_ddm_source()
    res = engine.get_ddm_status(src, last="1h")
    # Two declarations seen: one being applied, one marked for deletion.
    states = {d["state"] for d in res["declarations"]}
    assert len(res["declarations"]) == 2
    assert "removing" in states
    # Ids are hashed; the type prefix is preserved for readability.
    assert all(d["declaration_ref"].startswith("h:") for d in res["declarations"])
    assert any(d["declaration_type"] == "com.acme.declaration" for d in res["declarations"])
    # Status-report cadence to the MDM server is captured.
    kinds = {r["kind"] for r in res["status_reports"]}
    assert {"status_sent", "mdm_response", "subscriptions_ack"} <= kinds
    assert next(r for r in res["status_reports"] if r["kind"] == "mdm_response")["http_status"] == 200
    # The "Unable to apply … invalid payload" line is flagged as failing.
    assert any("invalid" in f["message"].lower() for f in res["failing"])
    # ...but the declaration id (with its UUID) is redacted to a hash even in the
    # failing message, consistent with declaration_ref.
    assert all("de3344445f55" not in f["message"] for f in res["failing"])
    assert any("h:" in f["message"] for f in res["failing"])
    # A status-report line whose subscription key-paths contain "failure-reason"
    # is NOT counted as a failure (status lines are exempt from the text heuristic).
    assert all("status subscriptions" not in f["message"] for f in res["failing"])


def test_ddm_status_filter_by_declaration_id():
    src = make_ddm_source()
    decl_id = "com.acme.declaration.dddd9999-eeee-8888-ffff-0a0b1c2d3e4f"
    res = engine.get_ddm_status(src, declaration_id=decl_id, last="1h")
    assert len(res["declarations"]) == 1
    assert res["declarations"][0]["state"] == "removing"


def test_ddm_status_big_sur_predates_ddm():
    # macOS 11 has no declarative subsystems; the predicate matches nothing.
    src = FixtureLogSource(DDM_FIXTURE, os_major=11)
    res = engine.get_ddm_status(src, last="1h")
    # 11.json still resolves the declaration predicate (parity), but on Big Sur
    # there is no real DDM — the fixture's subsystems still match the CONTAINS
    # terms, so this asserts the call is well-formed rather than empty.
    assert set(res.keys()) >= {"declarations", "status_reports", "failing", "count"}


def test_open_archive_source_fixture_roundtrip():
    # A captured .ndjson opened as an archive becomes a normal source: probe
    # reports a time span, and the engine queries it like any other source.
    src = sources.open_archive_source(str(MDM26_FIXTURE), os_major=26)
    assert src.os_major == 26
    info = src.probe()
    assert info["time_span"] is not None
    assert info["time_span"]["start"] <= info["time_span"]["end"]
    res = engine.query_events(src, "mdm_command", last="1h")
    assert res["count"] >= 1


def test_open_archive_source_rejects_bad_and_unsupported():
    # Missing path.
    try:
        sources.open_archive_source("/no/such/path.logarchive")
        assert False, "expected FileNotFoundError"
    except FileNotFoundError:
        pass
    # A .tar.gz that's not a valid tarball (or not a bundle) raises ValueError
    # with a clear message. Sysdiagnose tarballs land here too — they'd extract
    # OK but fail the bundle check with a "sysdiagnose isn't supported" message.
    with tempfile.NamedTemporaryFile(suffix=".tar.gz") as tf:
        try:
            sources.open_archive_source(tf.name)
            assert False, "expected ValueError"
        except ValueError:
            pass
    # Unrecognized type.
    with tempfile.NamedTemporaryFile(suffix=".txt") as tf:
        try:
            sources.open_archive_source(tf.name)
            assert False, "expected ValueError"
        except ValueError:
            pass


def test_open_archive_logarchive_builds_archive_source(tmp_path=None):
    # A .logarchive path (we only need it to exist) builds an ArchiveLogSource
    # without running `log show` (that needs a Mac).
    from mdm_log_analyzer.sources import ArchiveLogSource

    with tempfile.TemporaryDirectory(suffix=".logarchive") as d:
        src = sources.open_archive_source(d, os_major=15)
        assert isinstance(src, ArchiveLogSource)
        assert src.os_major == 15


def _build_bundle_dir(tmp: Path) -> Path:
    """Assemble a tools/collect-mdm-logs.sh-shaped bundle in tmp/."""
    b = tmp / "mdm-logs-testhost"
    b.mkdir()
    (b / "os.txt").write_text(
        "ProductName:\tmacOS\nProductVersion:\t26.5.1\nBuildVersion:\t25F80\n"
    )
    # Copy the existing macOS-26 fixture as the mdmclient category.
    (b / "mdmclient.ndjson").write_text(MDM26_FIXTURE.read_text())
    (b / "push.ndjson").write_text(
        '{"timestamp":"2026-06-26 01:20:00.000000-0700","process":"apsd",'
        '"subsystem":"com.apple.apsd","messageType":"Info",'
        '"eventMessage":"Received notification for topic com.apple.mgmt.External",'
        '"traceID":"b-push-1"}\n'
    )
    # A minimal install.log so read_install_log works from the bundle.
    (b / "install.log").write_text(INSTALL_FIXTURE.read_text())
    return b


def test_bundle_source_from_extracted_dir():
    # Open a directory bundle directly (no tarball).
    with tempfile.TemporaryDirectory() as tmp:
        b = _build_bundle_dir(Path(tmp))
        src = sources.open_archive_source(b)
        assert isinstance(src, sources.BundleLogSource)
        assert src.os_major == 26  # auto-detected from os.txt

        # query_events works across the union of ndjson files.
        r = engine.query_events(src, "mdm_command", last="1h")
        assert r["count"] >= 1
        # push category, aggregated across the bundle's ndjson files (the
        # mdmclient fixture already contains one apsd line, so we get ≥1).
        rp = engine.query_events(src, "push", last="1h")
        assert rp["count"] >= 1

        # probe() surfaces the OS build and a real time span.
        info = src.probe()
        assert "26.5.1" in (info["os_build"] or "")
        assert info["time_span"] is not None

        # install.log is threaded through, so get_install_log works.
        il = engine.get_install_log(src, last="1d")
        assert il["count"] >= 1


def test_bundle_source_from_tar_gz_auto_extracts():
    import tarfile as _tf

    with tempfile.TemporaryDirectory() as tmp:
        b = _build_bundle_dir(Path(tmp))
        tar_path = Path(tmp) / "mdm-logs-testhost.tar.gz"
        with _tf.open(tar_path, "w:gz") as tf:
            tf.add(b, arcname=b.name)

        src = sources.open_archive_source(tar_path)
        assert isinstance(src, sources.BundleLogSource)
        r = engine.query_events(src, "mdm_command", last="1h")
        assert r["count"] >= 1


def test_bundle_tarball_rejects_non_bundle_shape():
    # A well-formed tarball that isn't a collect-mdm-logs bundle (e.g. a
    # sysdiagnose stand-in) must fail cleanly with an explanatory ValueError.
    import tarfile as _tf

    with tempfile.TemporaryDirectory() as tmp:
        stray = Path(tmp) / "stray"
        stray.mkdir()
        (stray / "readme.txt").write_text("not a bundle")
        tar_path = Path(tmp) / "sysdiagnose-like.tar.gz"
        with _tf.open(tar_path, "w:gz") as tf:
            tf.add(stray, arcname=stray.name)
        try:
            sources.open_archive_source(tar_path)
            assert False, "expected ValueError"
        except ValueError as e:
            assert "bundle" in str(e).lower() or "sysdiagnose" in str(e).lower()


def test_bundle_source_tarball_path_traversal_guard():
    # A tarball with a member trying to escape the extraction root must be
    # rejected — no writing outside the temp dir.
    import tarfile as _tf, io

    with tempfile.TemporaryDirectory() as tmp:
        tar_path = Path(tmp) / "evil.tar.gz"
        with _tf.open(tar_path, "w:gz") as tf:
            data = b"pwned"
            ti = _tf.TarInfo(name="../escape.txt")
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
        try:
            sources.open_archive_source(tar_path)
            assert False, "expected ValueError for unsafe tarball member"
        except ValueError:
            pass



# --- regressions: the bundle must not report "nothing found" for "did not look" ---


def _mdmclient_line(ts, msg, trace, mach, sub="com.apple.ManagedClient"):
    import json

    return json.dumps(
        {
            "timestamp": ts,
            "processImagePath": "/usr/libexec/mdmclient",
            "subsystem": sub,
            "messageType": "Default",
            "eventMessage": msg,
            "traceID": trace,
            "machTimestamp": mach,
        }
    )


def _write_fixture(lines):
    tmp = tempfile.NamedTemporaryFile(
        "w", suffix=".ndjson", delete=False, encoding="utf-8"
    )
    tmp.write("\n".join(lines))
    tmp.close()
    return Path(tmp.name)


def test_bundle_tallies_commands_past_the_query_limit():
    # query_events caps at `limit` (default 500) and used to keep the OLDEST
    # events, while build_incident_bundle computed its tally from that slice.
    # On a real 1h capture (17,018 mdmclient events) every command result sat
    # past the cap, so the bundle reported by_status {} / notable_errors [] for
    # a window containing 9 failed commands. The tally must cover the whole
    # window regardless of the presentation cap.
    lines = [
        _mdmclient_line(
            f"2026-08-21 10:00:{i % 60:02d}.{i:06d}+0530",
            "MDMDaemon: routine housekeeping chatter",
            f"noise-{i}",
            1000 + i,
        )
        for i in range(700)
    ]
    # The only command brackets are at the very END of the window.
    lines.append(
        _mdmclient_line(
            "2026-08-21 10:20:00.000000+0530",
            "Processing server request: InstallProfile for: <Device> (900)",
            "recv",
            9001,
        )
    )
    lines.append(
        _mdmclient_line(
            "2026-08-21 10:20:01.000000+0530",
            ">>>>> Sending HTTP request (PUT) [Error(InstallProfile):900] >>>>>",
            "res",
            9002,
        )
    )
    fixture = _write_fixture(lines)
    src = FixtureLogSource(fixture, os_major=26)

    # query_events still caps, but now keeps the most RECENT events...
    res = engine.query_events(src, "mdm_command", last="1h", limit=100)
    assert res["count"] == 702
    assert res["truncated"] is True
    assert res["truncation"]["keeps"] == "most_recent"
    assert "res" in {trace_of(e["raw_ref"]) for e in res["events"]}

    # ...and the bundle tallies over everything, not the capped slice.
    b = engine.build_incident_bundle(src, symptom="profile_failure", last="1h")
    assert b["context"]["event_counts"]["mdm_command"] == 702
    assert b["command_activity"]["by_status"].get("Error") == 1
    assert "InstallProfile" in b["command_activity"]["by_type"]
    assert any(e.get("status") == "Error" for e in b["notable_errors"])


def test_raw_ref_is_unique_per_line_so_dedupe_keeps_distinct_errors():
    # traceID identifies the emitting code site, not the line: 452 distinct
    # traceIDs across 17,019 real mdmclient events. notable_errors dedupes by
    # raw_ref, so a traceID-only ref collapsed genuinely different failures into
    # one entry.
    shared = "same-code-site"
    lines = [
        _mdmclient_line(
            "2026-08-21 10:20:01.000000+0530",
            ">>>>> Sending HTTP request (PUT) [Error(InstallProfile):901] >>>>>",
            shared,
            5001,
        ),
        _mdmclient_line(
            "2026-08-21 10:20:02.000000+0530",
            ">>>>> Sending HTTP request (PUT) [Error(RemoveProfile):902] >>>>>",
            shared,
            5002,
        ),
    ]
    src = FixtureLogSource(_write_fixture(lines), os_major=26)
    b = engine.build_incident_bundle(src, symptom="profile_failure", last="1h")

    refs = [e["raw_ref"] for e in b["notable_errors"]]
    assert len(refs) == len(set(refs)) == 2, refs
    assert {trace_of(r) for r in refs} == {shared}  # same code site...
    seqs = {e.get("command_seq") for e in b["notable_errors"]}
    assert seqs == {"901", "902"}  # ...but both failures survived


def test_managed_app_install_abort_is_extracted_and_flagged():
    # An InstallApplication can be Acknowledged and still fail afterwards inside
    # PackageKit. That failure is logged ONLY by mdmclient's ManagedApps
    # subsystem — install.log has no session for a package rejected up front —
    # so it was invisible to every tool: get_install_log reported "all success"
    # while the app never installed.
    uuid = "C5B37B2A-47C8-4B1D-9DE6-3242973749AD"
    lines = [
        _mdmclient_line(
            "2026-08-21 10:10:12.000000+0530",
            "Processing server request: InstallApplication for: <Device> (13273034)",
            "recv",
            7001,
        ),
        _mdmclient_line(
            "2026-08-21 10:10:13.000000+0530",
            ">>>>> Sending HTTP request (PUT) [Acknowledged(InstallApplication):13273034] >>>>>",
            "ack",
            7002,
        ),
        _mdmclient_line(
            "2026-08-21 10:17:04.000000+0530",
            "<ASDApp: 0x1>: {bundleID = com.qa.timelogger; installed = 0; "
            'installError = Error Domain=PKInstallErrorDomain Code=100 '
            '"Authorisation is required to install the packages."}',
            "asd",
            7003,
        ),
        _mdmclient_line(
            "2026-08-21 10:17:04.100000+0530",
            "[ERROR] [0:MDMDaemon:ManagedApps:<0x1>] Aborting app install: "
            "Package signature cannot be verified <PKInstallErrorDomain:100>",
            "abort",
            7004,
        ),
        _mdmclient_line(
            "2026-08-21 10:17:04.200000+0530",
            f"Install '{uuid}' finished.  Sucess: no  Error: {{\n    code = 100;\n"
            "    domain = PKInstallErrorDomain;\n}",
            "fin",
            7005,
        ),
    ]
    src = FixtureLogSource(_write_fixture(lines), os_major=26)

    res = engine.query_events(src, "mdm_command", last="1h")
    by_ref = {trace_of(e["raw_ref"]): e for e in res["events"]}

    abort = by_ref["abort"]
    assert abort["status"] == "Error"
    assert abort["command_type"] == "InstallApplication"
    assert abort["error_code"] == 100
    assert abort["reason"] == "Package signature cannot be verified"

    # The ASD line is the only one naming the app, so it must count as a failure
    # too — otherwise the report says an install failed without saying which.
    assert by_ref["asd"]["app_id"] == "com.qa.timelogger"
    assert by_ref["asd"]["status"] == "Error"

    # The log's own misspelling ("Sucess:") is matched literally.
    assert by_ref["fin"]["status"] == "Error"
    assert by_ref["fin"]["command_uuid"]  # install operation uuid, hashed

    # ...and it surfaces as a Tier-0 finding, not just an event.
    b = engine.build_incident_bundle(src, symptom="install_failure", last="1h")
    findings = {f["code"] for f in b["tier0_findings"]}
    assert "app_install_abort" in findings, findings
    abort_finding = next(
        f for f in b["tier0_findings"] if f["code"] == "app_install_abort"
    )
    assert abort_finding["severity"] == "error"
    assert "Package signature cannot be verified" in abort_finding["summary"]
    # The Acknowledged command and the failed install coexist: the command
    # succeeded, the install did not.
    assert b["command_activity"]["by_type"]["InstallApplication"]["Acknowledged"] == 1
    assert b["command_activity"]["by_type"]["InstallApplication"]["Error"] >= 1


def test_install_log_honours_the_time_window_and_caps_phases():
    # BundleLogSource ignored `last` for install.log, on the assumption that
    # collect-mdm-logs.sh had windowed it. It had not — it `cp`s the file — so a
    # 10-minute request returned 9 days of history: 31,760 phase records
    # (8.7 MB), over the MCP 1 MB response limit, and reported installs from
    # days outside the window as if they were inside it.
    old_lines = [
        f"2026-08-12 10:{m:02d}:00+05:30 host installd[1]: PackageKit: "
        f"Executing script for stale-{m}"
        for m in range(10, 50)
    ]
    recent = [
        f"2026-08-21 10:{m:02d}:00+05:30 host installd[2]: PackageKit: "
        f"Executing script for fresh-{m}"
        for m in range(10, 20)
    ]
    tmp = tempfile.NamedTemporaryFile(
        "w", suffix=".log", delete=False, encoding="utf-8"
    )
    tmp.write("\n".join(old_lines + recent))
    tmp.close()
    src = FixtureLogSource(FIXTURE, os_major=26, install_log_path=Path(tmp.name))

    narrow = engine.get_install_log(src, last="30m")
    assert narrow["count"] == 10, narrow["count"]  # Aug 12 excluded entirely
    assert narrow["time_span"]["start"].startswith("2026-08-21")

    wide = engine.get_install_log(src, last="30d")
    assert wide["count"] == 50

    # An unparseable window stays a no-op rather than returning nothing.
    assert engine.get_install_log(src, last="banana")["count"] == 50

    # phases is the biggest thing this tool can emit, so it is capped like every
    # other list — keeping the most recent, and saying so.
    from mdm_log_analyzer.engine import _MAX_PHASES

    many = [
        f"2026-08-21 10:00:00+05:30 host installd[3]: PackageKit: "
        f"Executing script for bulk-{i}"
        for i in range(_MAX_PHASES + 25)
    ]
    tmp2 = tempfile.NamedTemporaryFile(
        "w", suffix=".log", delete=False, encoding="utf-8"
    )
    tmp2.write("\n".join(many))
    tmp2.close()
    src2 = FixtureLogSource(FIXTURE, os_major=26, install_log_path=Path(tmp2.name))
    res = engine.get_install_log(src2, last="1d")
    assert res["count"] == _MAX_PHASES + 25
    assert len(res["phases"]) == _MAX_PHASES
    assert res["phases_truncated"] is True
    assert res["truncation"]["keeps"] == "most_recent"


def test_install_summary_carries_the_span_it_actually_covers():
    # "31 installs, all success" read as describing the requested 10 minutes
    # when it actually covered 9 days. The counts must travel with their span.
    src = FixtureLogSource(
        FIXTURE, os_major=15, install_log_path=SESSIONS_FIXTURE
    )
    summary = engine.get_install_log(src, last="1d")["session_summary"]
    assert summary["total"] >= 1
    assert summary["time_span"]["start"] <= summary["time_span"]["end"]



def test_command_tally_counts_commands_not_log_lines():
    # mdmclient logs a result TWICE — once on the outgoing HTTP request and
    # again on the response — and the receipt line repeats the same sequence
    # number. Counting lines reported 58 Acknowledged / 20 Error for a real
    # window holding 29 / 9. The sequence number is the command's identity.
    lines = [
        _mdmclient_line(
            "2026-08-21 10:20:00.000000+0530",
            "Processing server request: InstallProfile for: <Device> (900)",
            "recv",
            8001,
        ),
        _mdmclient_line(
            "2026-08-21 10:20:01.000000+0530",
            ">>>>> Sending HTTP request (PUT) [Error(InstallProfile):900] >>>>>",
            "send",
            8002,
        ),
        _mdmclient_line(
            "2026-08-21 10:20:02.000000+0530",
            "<<<<< Received HTTP response (200) [Error(InstallProfile):900] <<<<<",
            "resp",
            8003,
        ),
    ]
    src = FixtureLogSource(_write_fixture(lines), os_major=26)
    b = engine.build_incident_bundle(src, symptom="profile_failure", last="1h")

    # Three lines, one command.
    assert b["command_activity"]["by_status"] == {"Error": 1}, b["command_activity"]
    assert b["command_activity"]["by_type"]["InstallProfile"] == {"Error": 1}
    # ...and the failure is reported as a finding, not just a tally. These
    # commands carry no CommandUUID (macOS logs none), so no timeline covers
    # them — findings used to come only from timelines.
    summary = next(
        f["summary"] for f in b["tier0_findings"] if f["code"] == "command_failures"
    )
    assert "InstallProfile×1" in summary, summary


def test_one_failed_app_install_is_one_failure_not_six():
    # A single aborted install spans ~6 lines: phases sharing the operation
    # uuid, an App Store notification carrying only the bundle id, and an abort
    # line carrying neither. Keyed independently they tallied as 3 separate
    # InstallApplication errors for one failed install.
    uuid = "C5B37B2A-47C8-4B1D-9DE6-3242973749AD"
    lines = [
        _mdmclient_line(
            "2026-08-21 10:10:12.000000+0530",
            "Processing server request: InstallApplication for: <Device> (13273034)",
            "recv",
            6001,
        ),
        _mdmclient_line(
            "2026-08-21 10:10:13.000000+0530",
            ">>>>> Sending HTTP request (PUT) [Acknowledged(InstallApplication):13273034] >>>>>",
            "ack",
            6002,
        ),
        _mdmclient_line(
            "2026-08-21 10:17:04.000000+0530",
            "<ASDApp: 0x1>: {bundleID = com.qa.timelogger; installed = 0; "
            'installError = Error Domain=PKInstallErrorDomain Code=100 "nope."}',
            "asd",
            6003,
        ),
        _mdmclient_line(
            "2026-08-21 10:17:04.100000+0530",
            f"Processing install phase 99 for {uuid} ==> {{\n \"__Error__\" = "
            "{ code = 100;\n domain = PKInstallErrorDomain;\n };\n "
            '"__Success__" = 0;\n}',
            "p99",
            6004,
        ),
        _mdmclient_line(
            "2026-08-21 10:17:04.200000+0530",
            f"Install phase 97 ({uuid}) completed. Result: <Abort> ==> Package "
            "signature cannot be verified <PKInstallErrorDomain:100>",
            "p97",
            6005,
        ),
        _mdmclient_line(
            "2026-08-21 10:17:04.300000+0530",
            "[ERROR] [0:MDMDaemon:ManagedApps:<0x1>] Aborting app install: "
            "Package signature cannot be verified <PKInstallErrorDomain:100>",
            "abort",
            6006,
        ),
    ]
    src = FixtureLogSource(_write_fixture(lines), os_major=26)
    b = engine.build_incident_bundle(src, symptom="install_failure", last="1h")

    tally = b["command_activity"]["by_type"]["InstallApplication"]
    assert tally == {"Acknowledged": 1, "Error": 1}, tally
    # The tally and the finding must agree on how many commands failed.
    summary = next(
        f["summary"] for f in b["tier0_findings"] if f["code"] == "command_failures"
    )
    assert "InstallApplication×1" in summary, summary
    assert b["command_activity"]["by_status"]["Error"] == 1


def test_bundle_stays_small_enough_to_return():
    # build_incident_bundle documents itself as the anti-context-blowup wrapper,
    # but capped only the NUMBER of timelines. On a real capture 7 timelines of
    # unclipped events, each carrying findings whose evidence listed every
    # matching raw_ref, rendered a 34 MB bundle — 34x the MCP 1 MB limit.
    import json

    from mdm_log_analyzer.engine import _MAX_TIMELINE_EVENTS
    from mdm_log_analyzer.schema import MAX_EVIDENCE

    lines = []
    for i in range(400):
        lines.append(
            _mdmclient_line(
                f"2026-08-21 10:{i % 60:02d}:00.{i:06d}+0530",
                "MDMDaemon: <private> chatter that triggers the masked finding",
                f"noise-{i}",
                3000 + i,
            )
        )
    lines.append(
        _mdmclient_line(
            "2026-08-21 10:59:00.000000+0530",
            "StartInstall using UUID: C5B37B2A-47C8-4B1D-9DE6-3242973749AD",
            "sub",
            3900,
        )
    )
    src = FixtureLogSource(_write_fixture(lines), os_major=26)
    b = engine.build_incident_bundle(src, symptom="command_failure", last="1h")

    assert len(json.dumps(b)) < 1_000_000

    for tl in b["timelines"]:
        assert len(tl["events"]) <= _MAX_TIMELINE_EVENTS
        if tl.get("events_omitted"):
            assert tl["events_total"] > _MAX_TIMELINE_EVENTS
    for f in b["tier0_findings"]:
        assert len(f["evidence"]) <= MAX_EVIDENCE
        if f.get("evidence_total"):
            assert f["evidence_total"] > len(f["evidence"])

    # Generic findings fire per timeline; the bundle must report each once with
    # merged evidence rather than repeating it. (Codes may legitimately repeat
    # when the summary differs — one app_install_abort per app — so this checks
    # the generic rule that used to appear six times over.)
    masked = [f for f in b["tier0_findings"] if f["code"] == "private_data_masked"]
    assert len(masked) <= 1, masked


def test_overlapping_categories_are_not_counted_twice():
    # profile_payload and mdm_command both match mdmclient, so the bundle sees
    # every line once per category. ARCHITECTURE.md calls for de-duplicating by
    # raw_ref; the tally never did, so one Error counted once per matching
    # category.
    lines = [
        _mdmclient_line(
            "2026-08-21 10:20:01.000000+0530",
            ">>>>> Sending HTTP request (PUT) [Error(InstallProfile):950] >>>>>",
            "one",
            4001,
        ),
    ]
    src = FixtureLogSource(_write_fixture(lines), os_major=26)
    b = engine.build_incident_bundle(src, symptom="profile_failure", last="1h")

    # Both categories matched the single line...
    assert b["context"]["event_counts"]["profile_payload"] == 1
    assert b["context"]["event_counts"]["mdm_command"] == 1
    # ...but it is one error, once.
    assert b["command_activity"]["by_status"] == {"Error": 1}
    assert len(b["notable_errors"]) == 1



def test_bundle_drops_timelines_that_say_nothing():
    # `UUID:`/`ID:`-shaped text appears in messages that are not commands at all
    # (keychain persistent refs, attestation certs), and each one seeded a
    # correlation. On a real capture that padded the bundle with four
    # one-event round-trips carrying no command type and outcome "Unknown".
    lines = [
        _mdmclient_line(
            "2026-08-21 10:30:00.000000+0530",
            "Keychain: Saved ref: <Keychain: DPSystem; "
            "ID: A1B2C3D4-1111-2222-3333-444455556666>",
            "junk",
            2001,
        ),
        _mdmclient_line(
            "2026-08-21 10:30:01.000000+0530",
            "Processing server request: InstallProfile for: <Device> (777)",
            "recv",
            2002,
        ),
        _mdmclient_line(
            "2026-08-21 10:30:02.000000+0530",
            ">>>>> Sending HTTP request (PUT) [Error(InstallProfile):777] >>>>>",
            "res",
            2003,
        ),
    ]
    src = FixtureLogSource(_write_fixture(lines), os_major=26)
    b = engine.build_incident_bundle(src, symptom="command_failure", last="1h")

    for tl in b["timelines"]:
        assert not (tl["command_type"] is None and tl["outcome"] == "Unknown"), tl
    # The real failure is still reported, via the tally and a finding.
    assert b["command_activity"]["by_type"]["InstallProfile"] == {"Error": 1}
    assert "command_failures" in {f["code"] for f in b["tier0_findings"]}



def test_errorchain_gives_the_reason_a_command_failed():
    # The status bracket says a command failed; the ErrorChain says why, and on
    # a real macOS 26.6.1 capture it is NOT masked. Nothing extracted it, so the
    # tool could report "9 commands returned Error" and not one reason — the
    # count without the diagnosis.
    lines = [
        _mdmclient_line(
            "2026-08-21 10:10:07.283000+0530",
            "Processing server request: InstallProfile for: <Device> (13273053)",
            "recv",
            5101,
        ),
        _mdmclient_line(
            "2026-08-21 10:10:07.314000+0530",
            "[ERROR] [506:MDMAgent:<0x191a53>] [ErrorChain.0] (InstallProfile) "
            "[CPProfile:-102] The profile is either missing some required "
            "information or contains information in an invalid format.>",
            "chain",
            5102,
        ),
        _mdmclient_line(
            "2026-08-21 10:10:07.344000+0530",
            ">>>>> Sending HTTP request (PUT) [Error(InstallProfile):13273053] >>>>>",
            "put",
            5103,
        ),
    ]
    src = FixtureLogSource(_write_fixture(lines), os_major=26)
    res = engine.query_events(src, "mdm_command", last="1h")
    chain = next(e for e in res["events"] if trace_of(e["raw_ref"]) == "chain")

    assert chain["error_code"] == -102
    assert "invalid format" in chain["reason"]
    assert chain["command_type"] == "InstallProfile"
    # Deliberately NO status: the chain is detail about a command counted via
    # its bracket, and a status here would tally the failure twice.
    assert "status" not in chain

    b = engine.build_incident_bundle(src, symptom="profile_failure", last="1h")
    assert b["command_activity"]["by_type"]["InstallProfile"] == {"Error": 1}
    # The reason reaches notable_errors even without a status...
    assert any(e.get("error_code") == -102 for e in b["notable_errors"])
    # ...and the finding quotes it.
    summary = next(
        f["summary"] for f in b["tier0_findings"] if f["code"] == "command_failures"
    )
    assert "invalid format" in summary, summary


def test_command_response_payload_is_attributed_to_its_command():
    # The response payload spells keys as "Key = Value" with spaces, which the
    # older `Key[=:]` patterns never matched, and its numeric "CommandUUID" is
    # really the check-in sequence — the key that ties it to the round-trip.
    payload = (
        "[ERROR] [506:MDMAgent:<0x191d24>] Error in pending response: {\n"
        "    CommandUUID = 13273055;\n"
        "    ErrorChain =     (\n                {\n"
        '            ErrorCode = "-102";\n'
        "            ErrorDomain = CPProfile;\n"
        '            LocalizedDescription = "The profile is either missing some '
        'required information or contains information in an invalid format.";\n'
        "        }\n    );\n"
        "    RequestType = InstallProfile;\n"
        "    Status = Error;\n"
        "    UserLongName = jappleseed;\n}"
    )
    src = FixtureLogSource(
        _write_fixture(
            [_mdmclient_line("2026-08-21 10:10:12.160000+0530", payload, "resp", 5201)]
        ),
        os_major=26,
    )
    e = engine.query_events(src, "mdm_command", last="1h")["events"][0]

    assert e["command_type"] == "InstallProfile"
    assert e["status"] == "Error"
    assert e["command_seq"] == "13273055"
    assert e["error_code"] == -102
    assert "invalid format" in e["reason"]
    # Redaction still applies to the payload body (see the username test below).
    assert "jappleseed" not in e["message"]


def test_account_names_in_payloads_are_redacted():
    # §4.3 requires usernames masked. The home-directory rule only caught a name
    # inside a /Users/ path, so a command response spelling it out
    # ("UserLongName = jappleseed;") walked through in the clear.
    from mdm_log_analyzer.redact import scrub_message

    for spelling in (
        "UserLongName = jappleseed;",
        "UserShortName = jappleseed;",
        'UserName = "jappleseed";',
        "AccountName = jappleseed;",
    ):
        out = scrub_message(spelling)
        assert "jappleseed" not in out, out
        assert "h-" in out, out

    # Hashing, not blanking: the same account stays correlatable across events.
    a = scrub_message("UserLongName = jappleseed;")
    b = scrub_message("UserShortName = jappleseed;")
    assert a.split("= ")[1] == b.split("= ")[1]

    # The "<User: 506>" spelling of a user id is hashed too, and the device
    # channel (which carries no user) is left alone — the distinction is
    # diagnostic, and a stable hash preserves it.
    assert "506" not in scrub_message("Processing server request: X for: <User: 506>")
    assert scrub_message("Number of <Device> profiles found: 3") == (
        "Number of <Device> profiles found: 3"
    )


def test_correlate_command_response_stays_within_the_transport_limit():
    # correlate_command pulled every push/scheduling event within +/-60s of the
    # command as "context". On a real capture (197k apsd lines) that was ~30k
    # events and an 8.4 MB response, which the MCP transport refuses outright —
    # the tool did not answer at all.
    import json

    from mdm_log_analyzer.engine import _MAX_CONTEXT_EVENTS, _MAX_TIMELINE_EVENTS

    lines = [
        _mdmclient_line(
            "2026-08-21 10:20:00.000000+0530",
            "Processing server request: InstallProfile for: <Device> (900)",
            "recv",
            7101,
        ),
        _mdmclient_line(
            "2026-08-21 10:20:01.000000+0530",
            ">>>>> Sending HTTP request (PUT) [Error(InstallProfile):900] >>>>>",
            "res",
            7102,
        ),
    ]
    # A flood of apsd context around the command.
    for i in range(3000):
        lines.append(
            json.dumps(
                {
                    "timestamp": f"2026-08-21 10:20:{i % 60:02d}.{i:06d}+0530",
                    "process": "apsd",
                    "processImagePath": "/System/Library/PrivateFrameworks/apsd",
                    "messageType": "Default",
                    "eventMessage": "APS: connection state changed, topic churn " * 4,
                    "traceID": f"aps-{i}",
                    "machTimestamp": 20000 + i,
                }
            )
        )
    src = FixtureLogSource(_write_fixture(lines), os_major=26)
    tl = engine.correlate_command(
        src, command_type="InstallProfile", time_anchor="2026-08-21T04:50:01Z", last="1h"
    )

    assert len(json.dumps(tl)) < 1_000_000
    assert len(tl["events"]) <= _MAX_TIMELINE_EVENTS
    ctx = [e for e in tl["events"] if e["process"] == "apsd"]
    assert len(ctx) <= _MAX_CONTEXT_EVENTS, len(ctx)
    assert tl["outcome"] == "Error"


def test_time_anchor_picks_one_command_not_every_command_of_that_type():
    # A busy window holds many commands of the same type (18 InstallProfile
    # check-ins inside one minute on a real capture). Taking them all as anchors
    # merged them into one "round-trip" whose outcome was whichever finished
    # last, so correlating a FAILURE reported Acknowledged.
    lines = []
    # An earlier InstallProfile that fails...
    lines.append(
        _mdmclient_line(
            "2026-08-21 10:20:00.000000+0530",
            "Processing server request: InstallProfile for: <Device> (500)",
            "f-recv",
            7201,
        )
    )
    lines.append(
        _mdmclient_line(
            "2026-08-21 10:20:01.000000+0530",
            ">>>>> Sending HTTP request (PUT) [Error(InstallProfile):500] >>>>>",
            "f-res",
            7202,
        )
    )
    # ...and a later one that succeeds, inside the same context window.
    lines.append(
        _mdmclient_line(
            "2026-08-21 10:20:30.000000+0530",
            "Processing server request: InstallProfile for: <Device> (501)",
            "s-recv",
            7203,
        )
    )
    lines.append(
        _mdmclient_line(
            "2026-08-21 10:20:31.000000+0530",
            ">>>>> Sending HTTP request (PUT) [Acknowledged(InstallProfile):501] >>>>>",
            "s-res",
            7204,
        )
    )
    src = FixtureLogSource(_write_fixture(lines), os_major=26)

    failed = engine.correlate_command(
        src, command_type="InstallProfile", time_anchor="2026-08-21T04:50:01Z", last="1h"
    )
    assert failed["outcome"] == "Error", failed["outcome"]
    assert {trace_of(e["raw_ref"]) for e in failed["events"]} == {"f-recv", "f-res"}

    ok = engine.correlate_command(
        src, command_type="InstallProfile", time_anchor="2026-08-21T04:50:31Z", last="1h"
    )
    assert ok["outcome"] == "Acknowledged", ok["outcome"]
    assert {trace_of(e["raw_ref"]) for e in ok["events"]} == {"s-recv", "s-res"}



def test_failure_reasons_are_grouped_by_class_and_never_silently_dropped():
    # Listing distinct reason STRINGS looked fine until a real window produced
    # five "Profile with identifier '<different id>' not found" reasons: they
    # filled the 5-reason cap and two other error classes vanished with nothing
    # saying so — a reader concluded there were 3 affected identifiers, not 4.
    from mdm_log_analyzer.engine import _MAX_REASONS

    lines = []
    mach = 9000
    # Six RemoveProfile failures, each naming a different identifier, all one class.
    for i in range(6):
        mach += 1
        lines.append(
            _mdmclient_line(
                f"2026-08-21 10:20:{i:02d}.000000+0530",
                f">>>>> Sending HTTP request (PUT) [Error(RemoveProfile):{600 + i}] >>>>>",
                f"rp-res-{i}",
                mach,
            )
        )
        mach += 1
        lines.append(
            _mdmclient_line(
                f"2026-08-21 10:20:{i:02d}.500000+0530",
                "[ERROR] [506:MDMAgent:<0x1>] [ErrorChain.0] (RemoveProfile) "
                f"[MDMClientError:89] Profile with identifier 'ident-{i}' not found.>",
                f"rp-chain-{i}",
                mach,
            )
        )
    # ...plus two other, rarer classes that must not be crowded out.
    mach += 1
    lines.append(
        _mdmclient_line(
            "2026-08-21 10:20:30.000000+0530",
            ">>>>> Sending HTTP request (PUT) [Error(InstallProfile):700] >>>>>",
            "ip-res",
            mach,
        )
    )
    mach += 1
    lines.append(
        _mdmclient_line(
            "2026-08-21 10:20:30.500000+0530",
            "[ERROR] [506:MDMAgent:<0x2>] [ErrorChain.0] (InstallProfile) "
            "[CPProfile:-102] The profile is either missing some required "
            "information or contains information in an invalid format.>",
            "ip-chain",
            mach,
        )
    )
    mach += 1
    lines.append(
        _mdmclient_line(
            "2026-08-21 10:20:40.000000+0530",
            ">>>>> Sending HTTP request (PUT) [Error(ActivationLockBypassCode):800] >>>>>",
            "al-res",
            mach,
        )
    )
    mach += 1
    lines.append(
        _mdmclient_line(
            "2026-08-21 10:20:40.500000+0530",
            "[ERROR] [0:MDMDaemon:<0x3>] [ErrorChain.0] (ActivationLockBypassCode) "
            "[MCMDMErrorDomain:12085] The operation couldn’t be completed.>",
            "al-chain",
            mach,
        )
    )

    src = FixtureLogSource(_write_fixture(lines), os_major=26)
    b = engine.build_incident_bundle(src, symptom="profile_failure", last="1h")
    summary = next(
        f["summary"] for f in b["tier0_findings"] if f["code"] == "command_failures"
    )

    # Three classes, not six near-identical strings — so all three fit.
    assert "MDMClientError:89" in summary, summary
    assert "CPProfile:-102" in summary, summary
    assert "MCMDMErrorDomain:12085" in summary, summary
    # The repeated class reports how many lines it covers.
    assert "(6 log line(s))" in summary, summary
    # Nothing was dropped, so no overflow marker.
    assert "more error class(es)" not in summary, summary
    # And the command tally is unchanged by the detail lines.
    assert b["command_activity"]["by_status"]["Error"] == 8


def test_reason_overflow_is_announced_not_silent():
    from mdm_log_analyzer.engine import _MAX_REASONS

    lines = []
    mach = 4000
    for i in range(_MAX_REASONS + 2):
        mach += 1
        lines.append(
            _mdmclient_line(
                f"2026-08-21 10:21:{i:02d}.000000+0530",
                f">>>>> Sending HTTP request (PUT) [Error(RemoveProfile):{900 + i}] >>>>>",
                f"res-{i}",
                mach,
            )
        )
        mach += 1
        lines.append(
            _mdmclient_line(
                f"2026-08-21 10:21:{i:02d}.500000+0530",
                "[ERROR] [506:MDMAgent:<0x1>] [ErrorChain.0] (RemoveProfile) "
                # Letter-only domain, matching every real Apple error domain
                # (CPProfile, MDMClientError, MCMDMErrorDomain, PKInstallError…).
                f"[Domain{chr(65 + i)}:{100 + i}] Distinct failure class {i}.>",
                f"chain-{i}",
                mach,
            )
        )
    src = FixtureLogSource(_write_fixture(lines), os_major=26)
    b = engine.build_incident_bundle(src, symptom="profile_failure", last="1h")
    summary = next(
        f["summary"] for f in b["tier0_findings"] if f["code"] == "command_failures"
    )
    assert "more error class(es)" in summary, summary



def test_collect_script_captures_every_category_the_analyzer_queries():
    # collect-mdm-logs.sh routes captures by symptom, mirroring _SYMPTOM_PLANS.
    # The two drifted: the script had no installd/installer step at all, so the
    # pkg_install category that install_failure and app_activity both query was
    # structurally always 0 — a real capture reported "pkg_install 0" and the
    # reader took it as "no installer activity". Likewise a bundle without apsd
    # made correlate_command report "no APNs push correlated" when the truth was
    # that no apsd was captured.
    import re

    from mdm_log_analyzer.engine import _SYMPTOM_PLANS

    script = (ROOT / "tools" / "collect-mdm-logs.sh").read_text()
    block = re.search(r'case "\$SYMPTOM" in(.*?)\nesac', script, re.S)
    assert block, "could not find the symptom case block"

    wants = {}
    for m in re.finditer(r'^\s*(\w+)\)\s*WANT="([^"]+)"', block.group(1), re.M):
        wants[m.group(1)] = set(m.group(2).split())
    assert "all" in wants and "install_failure" in wants, wants

    # Which capture step feeds each analyzer category.
    feeds = {
        "mdm_command": "mdmclient",
        "profile_payload": "mdmclient",
        "ddm": "ddm",
        "declaration": "ddm",
        "push": "push",
        "scheduling": "dasd",
        "asset_download": "storedownloadd",
        "pkg_install": "installd",
        "enrollment": "enrollment",
    }

    for symptom, want in wants.items():
        if symptom == "all":
            continue
        plan = _SYMPTOM_PLANS.get(symptom)
        if plan is None:
            continue  # the script may offer fewer symptoms than the engine
        categories, want_install = plan
        for cat in categories:
            step = feeds[cat]
            assert step in want, (
                f"symptom {symptom!r} queries category {cat!r} but the script "
                f"does not capture {step!r} (WANT={sorted(want)})"
            )
        if want_install:
            assert "install" in want, symptom
        # correlate_command pulls push for EVERY symptom, so a capture without
        # apsd cannot distinguish "no push" from "push not collected".
        assert "push" in want or symptom in ("profile_failure", "ddm_failure"), symptom

    # `all` must be a superset of every targeted capture, or "capture everything
    # and stay re-queryable" is not true.
    union = set().union(*(w for k, w in wants.items() if k != "all"))
    assert union <= wants["all"], union - wants["all"]


def test_collect_script_names_archives_uniquely():
    # Every run produced "mdm-logs-<host>.tar.gz", so a second capture from the
    # same Mac either overwrote the first or was distinguishable only by which
    # folder someone filed it in.
    script = (ROOT / "tools" / "collect-mdm-logs.sh").read_text()
    assert 'STAMP="$(date ' in script, "no timestamp is computed"
    assert 'OUT="mdm-logs-$(hostname -s)-$STAMP"' in script, "archive name is not unique"
    # The manifest records the capture time and offset, so the bundle stays
    # unambiguous after it leaves the machine that made it.
    assert "captured=$(date" in script



def test_asset_download_predicate_covers_appstored():
    # A device-assigned VPP install on macOS 27 is carried by appstored, not
    # storedownloadd. The predicate matched only storedownloadd, so a real
    # managed-install capture reported asset_download 0 while the app plainly
    # downloaded and installed — no download telemetry between "requested" and
    # "installed" at all.
    from mdm_log_analyzer import predicates

    for os_major in (11, 14, 15, 26, 27):
        spec = predicates.resolve("asset_download", os_major)
        assert "storedownloadd" in spec["predicate"], os_major
        assert "appstored" in spec["predicate"], os_major
        assert spec.get("note"), f"{os_major} should record why appstored is here"

    # And the collector must capture what the predicate matches, or the widened
    # predicate is inert for bundles.
    script = (ROOT / "tools" / "collect-mdm-logs.sh").read_text()
    assert "appstored" in script, "collect script still captures storedownloadd only"


def test_capture_inventory_separates_empty_from_absent():
    # When a category returns 0 events, was nothing logged or was that process
    # never captured? The tools could not say, so a reader reasoned it out from
    # side evidence and got it backwards: the file was present and empty.
    import json as _json

    with tempfile.TemporaryDirectory() as td:
        d = Path(td) / "mdm-logs-host-20260824-144439"
        d.mkdir()
        (d / "os.txt").write_text("ProductName:\tmacOS\nProductVersion:\t26.0\n")
        (d / "mdmclient.ndjson").write_text(
            _mdmclient_line(
                "2026-08-24 10:00:00.000000+0530",
                ">>>>> Sending HTTP request (PUT) [Idle] >>>>>",
                "one",
                1,
            )
            # log show ends every export with this trailer, even an empty one.
            + "\n" + _json.dumps({"count": 1, "finished": 1})
        )
        # Captured, matched nothing — trailer only.
        (d / "storedownloadd.ndjson").write_text(
            _json.dumps({"count": 0, "finished": 1})
        )
        # dasd.ndjson deliberately absent.

        src = sources.open_archive_source(str(d))
        inv = src.capture_inventory()

        assert inv["files"]["mdmclient.ndjson"] == 1  # trailer not counted
        assert inv["files"]["storedownloadd.ndjson"] == 0  # captured, silent
        assert "dasd.ndjson" not in inv["files"]  # never captured
        assert inv["install_log"] is False

        b = engine.build_incident_bundle(src, symptom="app_activity", last="1h")
        assert b["context"]["capture"]["files"]["storedownloadd.ndjson"] == 0

    # A live source has no capture to inventory.
    assert FixtureLogSource(FIXTURE, os_major=15).capture_inventory() is None


def test_successful_app_install_is_not_reported_as_stuck():
    # The failure path set a status on the install phases; the success path did
    # not. So a managed app install that WORKED produced phase lines carrying an
    # operation id and no status, the correlator found no terminal event, and the
    # bundle reported `outcome: Idle` plus no_terminal — "received but reached no
    # terminal status" for an install that had finished 2 seconds earlier.
    uuid = "ACF5ADE3-F198-45F5-BCA5-613838418B34"
    lines = [
        _mdmclient_line(
            "2026-08-24 14:43:20.000000+0530",
            "Processing server request: InstallApplication for: <Device> (13277150)",
            "recv",
            1001,
        ),
        _mdmclient_line(
            "2026-08-24 14:43:21.000000+0530",
            ">>>>> Sending HTTP request (PUT) [Acknowledged(InstallApplication):13277150] >>>>>",
            "ack",
            1002,
        ),
        _mdmclient_line(
            "2026-08-24 14:43:48.767000+0530",
            f'Processing install phase 99 for {uuid} ==> {{\n    "__Success__" = 1;\n}}',
            "p99",
            1003,
        ),
        _mdmclient_line(
            "2026-08-24 14:43:48.768000+0530",
            f"Install '{uuid}' finished.  Sucess: YES  Error: (null)",
            "fin",
            1004,
        ),
    ]
    src = FixtureLogSource(_write_fixture(lines), os_major=26)

    res = engine.query_events(src, "mdm_command", last="1h")
    fin = next(e for e in res["events"] if trace_of(e["raw_ref"]) == "fin")
    assert fin["status"] == "Acknowledged"
    assert fin["command_type"] == "InstallApplication"
    assert fin["install_uuid"]  # the operation id, hashed

    b = engine.build_incident_bundle(src, symptom="app_activity", last="1h")
    # ONE command, counted once — not the command plus its install operation.
    assert b["command_activity"]["by_type"]["InstallApplication"] == {"Acknowledged": 1}
    codes = {f["code"] for f in b["tier0_findings"]}
    assert "no_terminal" not in codes, codes
    assert "app_install_abort" not in codes, codes
    for tl in b["timelines"]:
        if tl["command_type"] == "InstallApplication":
            assert tl["outcome"] == "Acknowledged", tl["outcome"]


def test_two_install_operations_one_failed_counts_one_failure():
    # A window can hold a successful install and a failed one. The old
    # fragment-merge bailed out whenever there was more than one install
    # operation, so the uuid-less abort fragments were counted separately and one
    # failed install tallied as three.
    ok_uuid = "AAAAAAAA-1111-2222-3333-444444444444"
    bad_uuid = "BBBBBBBB-1111-2222-3333-444444444444"
    lines = [
        _mdmclient_line(
            "2026-08-24 14:00:00.000000+0530",
            ">>>>> Sending HTTP request (PUT) [Acknowledged(InstallApplication):100] >>>>>",
            "ack1",
            2001,
        ),
        _mdmclient_line(
            "2026-08-24 14:00:10.000000+0530",
            f"Install '{ok_uuid}' finished.  Sucess: YES  Error: (null)",
            "ok",
            2002,
        ),
        _mdmclient_line(
            "2026-08-24 14:05:00.000000+0530",
            ">>>>> Sending HTTP request (PUT) [Acknowledged(InstallApplication):101] >>>>>",
            "ack2",
            2003,
        ),
        _mdmclient_line(
            "2026-08-24 14:05:10.000000+0530",
            '<ASDApp: 0x1>: {bundleID = com.qa.app; installed = 0; installError = '
            'Error Domain=PKInstallErrorDomain Code=100 "nope."}',
            "asd",
            2004,
        ),
        _mdmclient_line(
            "2026-08-24 14:05:11.000000+0530",
            f"Install phase 97 ({bad_uuid}) completed. Result: <Abort> ==> "
            "Package signature cannot be verified <PKInstallErrorDomain:100>",
            "p97",
            2005,
        ),
        _mdmclient_line(
            "2026-08-24 14:05:12.000000+0530",
            "[ERROR] [0:MDMDaemon:ManagedApps:<0x1>] Aborting app install: "
            "Package signature cannot be verified <PKInstallErrorDomain:100>",
            "abort",
            2006,
        ),
        _mdmclient_line(
            "2026-08-24 14:05:13.000000+0530",
            f"Install '{bad_uuid}' finished.  Sucess: no  Error: {{ code = 100; }}",
            "fin",
            2007,
        ),
    ]
    src = FixtureLogSource(_write_fixture(lines), os_major=26)
    b = engine.build_incident_bundle(src, symptom="install_failure", last="1h")

    tally = b["command_activity"]["by_type"]["InstallApplication"]
    assert tally == {"Acknowledged": 2, "Error": 1}, tally
    # The tally and the finding must agree.
    summary = next(
        f["summary"] for f in b["tier0_findings"] if f["code"] == "command_failures"
    )
    assert "InstallApplication×1" in summary, summary
    abort = next(f for f in b["tier0_findings"] if f["code"] == "app_install_abort")
    assert "com.qa.app" in abort["summary"], abort["summary"]



def test_notnow_reason_is_extracted_and_reported():
    # The [NotNow(Type):n] bracket says a command was deferred; the REASON rides
    # on a separate unbracketed line with no sequence number. Nothing read it, so
    # a real capture could report "NotNow x2" and not one reason — and the old
    # code manufactured a fake reason by splitting the bracket text, yielding
    # "NotNow: (ProfileList):13277315] >>>>>".
    lines = [
        _mdmclient_line(
            "2026-08-24 14:54:27.743000+0530",
            "[0:MDMDaemon:<0x464d>] Responding 'NotNow' to server request: "
            "ProfileList for: <Device> reason: Not supported during DarkWake",
            "why",
            1001,
        ),
        _mdmclient_line(
            "2026-08-24 14:54:27.769000+0530",
            ">>>>> Sending HTTP request (PUT) [NotNow(ProfileList):13277315] >>>>>",
            "put",
            1002,
        ),
        _mdmclient_line(
            "2026-08-24 14:54:28.073000+0530",
            "<<<<< Received HTTP response (200) [NotNow(ProfileList):13277315] <<<<<",
            "resp",
            1003,
        ),
    ]
    src = FixtureLogSource(_write_fixture(lines), os_major=26)
    res = engine.query_events(src, "mdm_command", last="1h")
    by = {trace_of(e["raw_ref"]): e for e in res["events"]}

    assert by["why"]["reason"] == "NotNow: Not supported during DarkWake"
    assert by["why"]["command_type"] == "ProfileList"
    # No status on the reason line: it explains a command counted via its
    # bracket, so a status here tallies a phantom extra deferral.
    assert "status" not in by["why"]
    assert by["put"]["status"] == "NotNow"
    # ...and the bracket line no longer invents a reason out of its own text.
    assert "reason" not in by["put"]

    b = engine.build_incident_bundle(src, symptom="command_failure", last="1h")
    # Three lines, ONE deferred command.
    assert b["command_activity"]["by_status"] == {"NotNow": 1}, b["command_activity"]
    f = next(x for x in b["tier0_findings"] if x["code"] == "command_deferred")
    assert "ProfileList×1" in f["summary"], f["summary"]
    assert "Not supported during DarkWake" in f["summary"], f["summary"]


def test_timelines_cover_the_commands_that_failed():
    # Seeds were only events carrying a command_uuid, but macOS logs no protocol
    # UUID for ordinary commands. On a real command_failure window holding 3
    # Errors and 2 NotNows the single timeline produced was a *successful*
    # InstallApplication — the only thing with an operation uuid — and every
    # command the caller asked about got none.
    lines = [
        # A successful InstallApplication carrying an operation uuid.
        _mdmclient_line(
            "2026-08-24 14:00:00.000000+0530",
            ">>>>> Sending HTTP request (PUT) [Acknowledged(InstallApplication):100] >>>>>",
            "ok-ack",
            2001,
        ),
        _mdmclient_line(
            "2026-08-24 14:00:05.000000+0530",
            "Install 'AAAAAAAA-1111-2222-3333-444444444444' finished.  Sucess: YES  Error: (null)",
            "ok-fin",
            2002,
        ),
        # A failing InstallProfile identified only by its sequence number.
        _mdmclient_line(
            "2026-08-24 14:05:00.000000+0530",
            "Processing server request: InstallProfile for: <Device> (200)",
            "err-recv",
            2003,
        ),
        _mdmclient_line(
            "2026-08-24 14:05:01.000000+0530",
            ">>>>> Sending HTTP request (PUT) [Error(InstallProfile):200] >>>>>",
            "err-res",
            2004,
        ),
    ]
    src = FixtureLogSource(_write_fixture(lines), os_major=26)
    b = engine.build_incident_bundle(src, symptom="command_failure", last="1h")

    outcomes = {(tl["command_type"], tl["outcome"]) for tl in b["timelines"]}
    assert ("InstallProfile", "Error") in outcomes, outcomes
    # Failures are seeded first, so they survive the _MAX_TIMELINES cap.
    assert b["timelines"][0]["outcome"] in ("Error", "NotNow"), b["timelines"][0]


def test_notnow_outranks_idle_as_a_timeline_outcome():
    # Idle means no command was pending on that check-in; NotNow means the device
    # actively deferred one. Reporting whichever came last called a deferred
    # command "Idle" and lost the deferral entirely.
    lines = [
        _mdmclient_line(
            "2026-08-24 14:10:00.000000+0530",
            "Processing server request: ProfileList for: <Device> (300)",
            "recv",
            3001,
        ),
        _mdmclient_line(
            "2026-08-24 14:10:01.000000+0530",
            ">>>>> Sending HTTP request (PUT) [NotNow(ProfileList):300] >>>>>",
            "notnow",
            3002,
        ),
        _mdmclient_line(
            "2026-08-24 14:10:02.000000+0530",
            ">>>>> Sending HTTP request (PUT) [Idle] >>>>>",
            "idle",
            3003,
        ),
    ]
    src = FixtureLogSource(_write_fixture(lines), os_major=26)
    tl = engine.correlate_command(
        src, command_type="ProfileList", time_anchor="2026-08-24T08:40:01Z", last="1h"
    )
    assert tl["outcome"] == "NotNow", tl["outcome"]


def test_time_span_compares_instants_not_strings():
    # A real capture mixed UTC offsets: an apsd export carried 1,858 events at
    # +0000 alongside 30,116 at +0530. min()/max() over the raw strings ordered
    # them lexicographically, so a LATER instant became the reported "start" and
    # the two bounds rendered in different zones — an incoherent span.
    import json as _json

    with tempfile.TemporaryDirectory() as td:
        d = Path(td) / "mdm-logs-host-20260824-000000"
        d.mkdir()
        (d / "os.txt").write_text("ProductName:\tmacOS\nProductVersion:\t26.0\n")
        # 09:20 +0000 is 14:50 +0530 — LATER than 14:40 +0530, though its string
        # sorts earlier.
        (d / "mdmclient.ndjson").write_text(
            "\n".join(
                [
                    _mdmclient_line(
                        "2026-08-24 14:40:00.000000+0530", "early event", "a", 1
                    ),
                    _mdmclient_line(
                        "2026-08-24 09:20:00.000000+0000", "later event", "b", 2
                    ),
                ]
            )
        )
        span = sources.open_archive_source(str(d)).probe()["time_span"]

    # Both bounds normalized to UTC, and ordered by instant.
    assert span["start"].endswith("Z") and span["end"].endswith("Z"), span
    assert span["start"] == "2026-08-24T09:10:00.000Z", span
    assert span["end"] == "2026-08-24T09:20:00.000Z", span
    assert span["start"] < span["end"]



def test_latency_measures_the_command_not_the_check_in_around_it():
    # Thread-id bridging used the full +/-60s pad, and mdmclient reuses thread
    # ids heavily, so unrelated work the daemon did earlier on the same thread
    # (DEP-state queries, profile-store reads) landed in the command's core. That
    # padded the timeline and started the latency clock before the command was
    # dispatched: a real managed-app install reported 29,370 ms where the
    # command's own receipt-to-terminal span was 28,210 ms.
    lines = [
        # Unrelated work on the SAME thread, 5s before the command.
        _mdmclient_line(
            "2026-08-24 14:43:14.000000+0530",
            "[0:MDMDaemon:<0xea8bc>] Calling MAEGetUCRTDEPEnrollmentStateMacOSWithError.",
            "dep",
            1001,
        ),
        _mdmclient_line(
            "2026-08-24 14:43:19.000000+0530",
            "[0:MDMDaemon:<0xea8bc>] === CPF_GetInstalledProfiles === (<Device>)",
            "profiles",
            1002,
        ),
        # The command itself.
        _mdmclient_line(
            "2026-08-24 14:43:20.000000+0530",
            "[0:MDMDaemon:<0xea8bc>] Processing server request: InstallApplication "
            "for: <Device> (13277150)",
            "recv",
            1003,
        ),
        _mdmclient_line(
            "2026-08-24 14:43:30.000000+0530",
            ">>>>> Sending HTTP request (PUT) [Acknowledged(InstallApplication):13277150] >>>>>",
            "ack",
            1004,
        ),
    ]
    src = FixtureLogSource(_write_fixture(lines), os_major=26)
    tl = engine.correlate_command(
        src,
        command_type="InstallApplication",
        time_anchor="2026-08-24T09:13:20Z",
        last="1h",
    )

    assert tl["outcome"] == "Acknowledged"
    # Receipt -> terminal is 10s. The pre-command work on the same thread must
    # not be billed to the command.
    assert tl["latency_ms"] == 10_000, tl["latency_ms"]
    refs = {trace_of(e["raw_ref"]) for e in tl["events"]}
    assert "dep" not in refs, refs
    assert "profiles" not in refs, refs
    assert {"recv", "ack"} <= refs, refs


def test_one_round_trip_is_one_timeline():
    # A command keyed by its sequence and the operation it triggered keyed by an
    # operation uuid are two seeds that resolve to the same terminal event, so
    # the same install rendered twice — once at low confidence and once at high.
    uuid = "ACF5ADE3-F198-45F5-BCA5-613838418B34"
    lines = [
        _mdmclient_line(
            "2026-08-24 14:43:20.000000+0530",
            "[0:MDMDaemon:<0xea8bc>] Processing server request: InstallApplication "
            "for: <Device> (13277150)",
            "recv",
            2001,
        ),
        _mdmclient_line(
            "2026-08-24 14:43:20.500000+0530",
            f"[0:MDMDaemon:ManagedApps:<0xea8bc>] StartInstall using UUID: {uuid}",
            "start",
            2002,
        ),
        _mdmclient_line(
            "2026-08-24 14:43:48.000000+0530",
            f"Install '{uuid}' finished.  Sucess: YES  Error: (null)",
            "fin",
            2003,
        ),
        _mdmclient_line(
            "2026-08-24 14:43:49.000000+0530",
            ">>>>> Sending HTTP request (PUT) [Acknowledged(InstallApplication):13277150] >>>>>",
            "ack",
            2004,
        ),
    ]
    src = FixtureLogSource(_write_fixture(lines), os_major=26)
    b = engine.build_incident_bundle(src, symptom="app_activity", last="1h")

    installs = [t for t in b["timelines"] if t["command_type"] == "InstallApplication"]
    assert len(installs) == 1, [(t["outcome"], t["confidence"]) for t in installs]
    # The surviving one is the better-evidenced correlation.
    assert installs[0]["confidence"] == "high", installs[0]["confidence"]

    # No two timelines share a terminal event.
    terminals = []
    for t in b["timelines"]:
        term = [
            e["raw_ref"]
            for e in t["events"]
            if e.get("status") in ("Acknowledged", "Error", "CommandFormatError")
        ]
        if term:
            terminals.append(term[-1])
    assert len(terminals) == len(set(terminals)), terminals



def test_manual_enrollment_failure_is_visible():
    # cloudconfigurationd is DEP/ADE only. A MANUAL profile enrollment never
    # touches it, so the enrollment category returned 0 events for a real failed
    # manual enrollment and the tool could not say whether enrollment completed —
    # while the failure sat unread in mdmclient's own check-in lines: SCEP
    # succeeded, then the server refused MDM_Authenticate with HTTP 401.
    lines = [
        _mdmclient_line(
            "2026-08-24 15:10:27.018000+0530",
            "[0:Cert_PI:SCEP:<0x8b46>] Processing MDM_SCEP_Enroll for server: "
            "https://mdm.example.com/scep/abc",
            "scep",
            1001,
        ),
        _mdmclient_line(
            "2026-08-24 15:10:29.974000+0530",
            "[0:MDM_PI:<0x8b4a>] Enrolling MDM of type: <DeviceEnrollment>",
            "enrolling",
            1002,
        ),
        _mdmclient_line(
            "2026-08-24 15:10:30.085000+0530",
            ">>>>> Sending HTTP request (PUT) [MDM_Authenticate] >>>>>",
            "put",
            1003,
        ),
        _mdmclient_line(
            "2026-08-24 15:10:30.425000+0530",
            "<<<<< Received HTTP response (401) [MDM_Authenticate] <<<<<",
            "401",
            1004,
        ),
        _mdmclient_line(
            "2026-08-24 15:10:30.429000+0530",
            "[ERROR] [0:MDM_PI:<0x8b4a>] [CE] XPC: InstallMDMv1Profile <system> "
            '==> Error Domain=MDMResponseStatus Code=401 "(null)"',
            "domain",
            1005,
        ),
    ]
    src = FixtureLogSource(_write_fixture(lines), os_major=26)

    # The manual path is in the enrollment category now, not just DEP.
    enrol = engine.query_events(src, "enrollment", last="1h")
    assert enrol["count"] > 0, "manual enrollment must produce enrollment events"

    res = engine.query_events(src, "mdm_command", last="1h")
    by = {trace_of(e["raw_ref"]): e for e in res["events"]}
    got = by["401"]
    assert got["status"] == "Error"
    assert got["error_code"] == 401
    assert got["command_type"] == "MDM_Authenticate"
    assert "401" in got["reason"]
    # "Error Domain=MDMResponseStatus" does not end in "ErrorDomain"; the old
    # pattern required that and missed it.
    assert by["domain"]["error_code"] == 401

    b = engine.build_incident_bundle(src, symptom="enrollment_failure", last="1h")
    # A check-in is NOT a command: folding it in turned a verified 29/9 window
    # into 11 errors and would not reconcile against the server's command log.
    assert "MDM_Authenticate" not in b["command_activity"].get("by_type", {})
    assert b["command_activity"]["checkins"]["MDM_Authenticate"] == {"Error": 1}
    f = next(x for x in b["tier0_findings"] if x["code"] == "checkin_failure")
    assert "MDM_Authenticate(401)" in f["summary"], f["summary"]
    assert "enrollment did not complete" in f["summary"], f["summary"]


def test_checkin_failure_does_not_blame_enrollment_wrongly():
    # A TokenUpdate or RemoteManagement 503 is a different problem from a
    # refused enrollment, and must not carry the enrollment sentence.
    lines = [
        _mdmclient_line(
            "2026-08-24 15:10:30.425000+0530",
            "<<<<< Received HTTP response (503) [MDM_TokenUpdate] <<<<<",
            "503",
            2001,
        ),
    ]
    src = FixtureLogSource(_write_fixture(lines), os_major=26)
    b = engine.build_incident_bundle(src, symptom="enrollment_failure", last="1h")
    f = next(x for x in b["tier0_findings"] if x["code"] == "checkin_failure")
    assert "MDM_TokenUpdate(503)" in f["summary"], f["summary"]
    assert "enrollment" not in f["summary"], f["summary"]


def test_apsd_faults_cannot_crowd_out_real_errors():
    # 977 of 987 "notable errors" on a real capture were apsd dark-wake faults.
    # At a cap of 25 they can bury every command error, so real errors are
    # listed first and fault shapes are deduped to one example each.
    import json as _json

    from mdm_log_analyzer.engine import _MAX_NOTABLE

    lines = [
        _mdmclient_line(
            "2026-08-24 15:00:00.000000+0530",
            ">>>>> Sending HTTP request (PUT) [Error(InstallProfile):700] >>>>>",
            "real-err",
            3001,
        )
    ]
    for i in range(200):
        lines.append(
            _json.dumps(
                {
                    "timestamp": f"2026-08-24 15:00:{i % 60:02d}.{i:06d}+0530",
                    "process": "apsd",
                    "processImagePath": "/usr/libexec/apsd",
                    "messageType": "Fault",
                    "eventMessage": f"<APSCourier: 0x{i:x}> recategorizing topic {i}",
                    "traceID": f"aps-{i}",
                    "machTimestamp": 40000 + i,
                }
            )
        )
    src = FixtureLogSource(_write_fixture(lines), os_major=26)
    b = engine.build_incident_bundle(src, symptom="command_failure", last="1h")

    refs = [trace_of(e["raw_ref"]) for e in b["notable_errors"]]
    assert refs[0] == "real-err", refs[:3]
    assert len(b["notable_errors"]) <= _MAX_NOTABLE
    # 200 near-identical faults collapse to their distinct shapes.
    assert b["notable_errors_total"] < 50, b["notable_errors_total"]



def test_declined_command_reports_how_fast_it_was_declined():
    # A NotNow has no terminal status, so latency_ms was null — discarding a
    # number that is both derivable and useful: receipt -> the NotNow response.
    # It also had no identity, because command_uuid is null for ordinary
    # commands and the sequence number was not carried on the timeline.
    lines = [
        _mdmclient_line(
            "2026-08-24 14:54:27.743000+0530",
            "Processing server request: ProfileList for: <Device> (13277315)",
            "recv",
            1001,
        ),
        _mdmclient_line(
            "2026-08-24 14:54:28.073000+0530",
            ">>>>> Sending HTTP request (PUT) [NotNow(ProfileList):13277315] >>>>>",
            "notnow",
            1002,
        ),
    ]
    src = FixtureLogSource(_write_fixture(lines), os_major=26)
    tl = engine.correlate_command(
        src, command_type="ProfileList", time_anchor="2026-08-24T09:24:27Z", last="1h"
    )

    assert tl["outcome"] == "NotNow"
    assert tl["command_seq"] == "13277315", tl["command_seq"]
    assert tl["latency_ms"] == 330, tl["latency_ms"]


def test_notnow_loop_does_not_invent_a_resolution():
    # The old finding said "Device returned NotNow 2 times before resolving"
    # whenever it saw two NotNow EVENTS. But the bracket is logged on both the
    # PUT and the response, so ONE declined command produced two events — and
    # nothing had resolved. Two different commands declined once each is also
    # not a loop.
    lines = [
        _mdmclient_line(
            "2026-08-24 14:54:27.743000+0530",
            "Processing server request: ProfileList for: <Device> (100)",
            "recv",
            2001,
        ),
        _mdmclient_line(
            "2026-08-24 14:54:28.000000+0530",
            ">>>>> Sending HTTP request (PUT) [NotNow(ProfileList):100] >>>>>",
            "put",
            2002,
        ),
        _mdmclient_line(
            "2026-08-24 14:54:28.300000+0530",
            "<<<<< Received HTTP response (200) [NotNow(ProfileList):100] <<<<<",
            "resp",
            2003,
        ),
    ]
    src = FixtureLogSource(_write_fixture(lines), os_major=26)
    b = engine.build_incident_bundle(src, symptom="command_failure", last="1h")

    # One declined command, two log lines: no loop, and no claim of resolution.
    assert not any(f["code"] == "notnow_loop" for f in b["tier0_findings"])
    deferred = next(
        f for f in b["tier0_findings"] if f["code"] == "command_deferred"
    )
    assert "1 command(s) deferred" in deferred["summary"], deferred["summary"]
    assert "resolving" not in deferred["summary"]
    # No reason line in this window — say so rather than leaving it blank.
    assert "No reason line was logged" in deferred["summary"], deferred["summary"]


def test_responses_name_the_source_that_answered():
    # A caller that omits `source` silently falls back to the environment, and a
    # live `log show` on a busy Mac takes minutes — which reads as the tool
    # hanging rather than as it reading something else entirely.
    src = FixtureLogSource(FIXTURE, os_major=15)
    assert engine.query_events(src, "mdm_command", last="1h")["source"] == (
        "FixtureLogSource"
    )


def test_correlate_command_rejects_incomplete_input_immediately():
    # Reported as "hangs for four minutes on invalid input". It does not: the
    # guard fires before any log is read, and names what is missing.
    src = FixtureLogSource(FIXTURE, os_major=15)
    for kwargs in (
        {"command_type": "InstallProfile"},
        {"command_type": "InstallProfile", "time_anchor": ""},
        {},
    ):
        try:
            engine.correlate_command(src, **kwargs)
            assert False, f"expected ValueError for {kwargs}"
        except ValueError as exc:
            assert "command_uuid" in str(exc) and "time_anchor" in str(exc)



def _install_log_fixture(lines):
    tmp = tempfile.NamedTemporaryFile(
        "w", suffix=".log", delete=False, encoding="utf-8"
    )
    tmp.write("\n".join(lines))
    tmp.close()
    return Path(tmp.name)


def test_failing_package_is_named_by_packagekit_not_the_cache_path():
    # The reverse-DNS scan took the FIRST such token in the line, and on a
    # managed-app failure that is the App Store cache path
    # (…/C/com.apple.appstore/<uuid>/…) — so the finding named
    # com.apple.appstore instead of the package that actually failed.
    log = _install_log_fixture(
        [
            "2026-08-24 15:51:15+05:30 host installd[849]: PackageKit: ----- Begin install -----",
            "2026-08-24 15:51:17+05:30 host package_script_service[4016]: ./preinstall: "
            "serverinfo.plist is not found, hence installation was aborted!",
            "2026-08-24 15:51:18+05:30 host installd[849]: PackageKit: Install Failed: "
            'Error Domain=PKInstallErrorDomain Code=112 "An error occurred while running '
            'scripts from the package." UserInfo={NSFilePath=./preinstall, '
            "NSURL=file:///var/folders/zz/C/com.apple.appstore/EDED9D38/UEMS_MacAgent.pkg, "
            "PKInstallPackageIdentifier=com.desktopcentral.agent}",
        ]
    )
    src = FixtureLogSource(FIXTURE, os_major=26, install_log_path=log)
    res = engine.get_install_log(src, last="1d")

    pkgs = {f.get("package") for f in res["failures"]}
    assert "com.desktopcentral.agent" in pkgs, pkgs
    assert "com.apple.appstore" not in pkgs, pkgs

    # A script that reports it aborted IS a failure, and is usually the only
    # line that says WHY — PackageKit only says "an error occurred".
    msgs = " ".join(f["message"] for f in res["failures"])
    assert "serverinfo.plist is not found" in msgs, msgs

    b = engine.build_incident_bundle(src, symptom="install_failure", last="1d")
    finding = next(
        f for f in b["tier0_findings"] if f["code"] == "pkg_install_failure"
    )
    assert "com.desktopcentral.agent" in finding["summary"], finding["summary"]
    assert "com.apple.appstore" not in finding["summary"], finding["summary"]


def test_session_span_ends_where_the_install_got_to():
    # session_summary.time_span used `started` for BOTH bounds, so its end was
    # the last session's START. On a real capture it reported 10:21:15 while the
    # failure that ended the install landed at 10:21:18 — the span excluded the
    # very event the bundle was opened to find — and a single-session window
    # produced a zero-width span.
    log = _install_log_fixture(
        [
            "2026-08-24 15:36:59+05:30 host installd[849]: PackageKit: ----- Begin install -----",
            "2026-08-24 15:37:17+05:30 host installd[849]: PackageKit: ----- End install -----",
            "2026-08-24 15:51:15+05:30 host installd[900]: PackageKit: ----- Begin install -----",
            "2026-08-24 15:51:18+05:30 host installd[900]: PackageKit: Install Failed: "
            "Error Domain=PKInstallErrorDomain Code=112",
        ]
    )
    src = FixtureLogSource(FIXTURE, os_major=26, install_log_path=log)
    res = engine.get_install_log(src, last="1d")
    span = res["session_summary"]["time_span"]

    assert span["start"] == "2026-08-24T10:06:59.000Z", span
    # 10:21:18, the failure — not 10:21:15, the second session's start.
    assert span["end"] == "2026-08-24T10:21:18.000Z", span

    # An unclosed bracket that recorded a failure is FAILED, not merely
    # incomplete: installd tears down without an End marker when a script
    # aborts, which kept a definite failure out of by_outcome["failed"].
    assert res["session_summary"]["by_outcome"] == {"success": 1, "failed": 1}
    failed = next(s for s in res["sessions"] if s["outcome"] == "failed")
    assert failed["last_record"] == "2026-08-24T10:21:18.000Z", failed



def test_ddm_bundle_reports_the_declaration_failure():
    # A ddm_failure bundle queried the broad `ddm` category, which also matches
    # ALL of mdmclient — so it filled with managed-app-install noise labelled
    # category "ddm" and produced no DDM finding at all, while get_ddm_status
    # found the failure in one call from the declarative subsystems.
    import json as _json

    lines = [
        # The DeclarativeManagement command is Acknowledged — that is correct
        # and is NOT the failure: validity is resolved asynchronously after.
        _mdmclient_line(
            "2026-08-24 15:58:50.698000+0530",
            "Processing server request: DeclarativeManagement for: <Device> (13277825)",
            "recv",
            1001,
        ),
        _mdmclient_line(
            "2026-08-24 15:58:51.035000+0530",
            ">>>>> Sending HTTP request (PUT) [Acknowledged(DeclarativeManagement):13277825] >>>>>",
            "ack",
            1002,
        ),
        # The subscriber rejects the payload 1.2s later, naming the key.
        _json.dumps(
            {
                "timestamp": "2026-08-24 15:58:52.453000+0530",
                "process": "ManagedSettingsSubscriber",
                "processImagePath": "/usr/libexec/ManagedSettingsSubscriber",
                "subsystem": "com.apple.remotemanagementd",
                "messageType": "Error",
                "eventMessage": (
                    "Invalid value type for configuration key: "
                    "Calculator.BasicMode.AddSquareRoot, setting key "
                    "calculator.forceSquareRootOnBasicCalculator"
                ),
                "traceID": "sub-1",
                "machTimestamp": 5001,
            }
        ),
    ]
    src = FixtureLogSource(_write_fixture(lines), os_major=26)
    b = engine.build_incident_bundle(src, symptom="ddm_failure", last="1h")

    # The declarative failure is a finding, with the offending key quoted.
    f = next(x for x in b["tier0_findings"] if x["code"] == "declaration_failure")
    assert "Calculator.BasicMode.AddSquareRoot" in f["summary"], f["summary"]
    assert f["severity"] == "error"
    # The declaration status travels with the bundle.
    assert b["ddm_status"]["failing"], b["ddm_status"]
    # No event is labelled "ddm" just because the symptom was ddm_failure.
    assert "ddm" not in {e.get("category") for e in b["notable_errors"]}
    # The command itself was Acknowledged, and that is not contradicted.
    assert b["command_activity"]["by_type"]["DeclarativeManagement"] == {
        "Acknowledged": 1
    }


def test_missing_push_is_not_reported_when_push_was_not_captured():
    # push.ndjson absent from the bundle cannot answer "was a push delivered?",
    # and context.capture already says so. Reporting missing_push presented a
    # collection gap as a possible delivery problem.
    import json as _json

    with tempfile.TemporaryDirectory() as td:
        d = Path(td) / "mdm-logs-host-20260824-000000"
        d.mkdir()
        (d / "os.txt").write_text("ProductName:\tmacOS\nProductVersion:\t26.0\n")
        (d / "mdmclient.ndjson").write_text(
            "\n".join(
                [
                    _mdmclient_line(
                        "2026-08-24 15:00:00.000000+0530",
                        "Processing server request: InstallProfile for: <Device> (900)",
                        "recv",
                        1,
                    ),
                    _mdmclient_line(
                        "2026-08-24 15:00:01.000000+0530",
                        ">>>>> Sending HTTP request (PUT) [Error(InstallProfile):900] >>>>>",
                        "res",
                        2,
                    ),
                ]
            )
        )
        src = sources.open_archive_source(str(d))
        b = engine.build_incident_bundle(src, symptom="command_failure", last="1h")

        assert "push.ndjson" not in b["context"]["capture"]["files"]
        codes = {f["code"] for f in b["tier0_findings"]}
        assert "missing_push" not in codes, codes
        # The real failure is still reported.
        assert "command_failures" in codes, codes



def test_camelcase_mdm_secret_keys_are_redacted():
    # `\b(token|…)\b` can never fire on a camelCase key: there is no word
    # boundary inside `DeviceToken`. So the highest-value secrets in the MDM
    # protocol all passed through untouched. Each string below was verified
    # leaking before the fix.
    from mdm_log_analyzer.redact import scrub_message

    leaked = {
        "APNs push token": "DeviceToken = <8a2f9c1d 4b7e0a33 91ffee02 3b7c8d19>;",
        "unlock token": 'UnlockToken = "TXlTZWNyZXRVbmxvY2tUb2tlbg==";',
        "escrow key": "EscrowKey = ABCDEFGHIJKLMNOP;",
        "await-configured token": "AwaitDeviceConfiguredToken=hunter2secret",
        "bootstrap token": "BootstrapToken = <deadbeef cafebabe>;",
    }
    for label, line in leaked.items():
        out = scrub_message(line)
        assert "<redacted>" in out, f"{label} not redacted: {out!r}"
        for secret in ("8a2f9c1d", "TXlTZWNyZXRVbmxvY2tUb2tlbg", "ABCDEFGHIJKLMNOP",
                       "hunter2secret", "deadbeef"):
            assert secret not in out, f"{label} leaked {secret}: {out!r}"

    # The value is consumed to a STRUCTURAL terminator, not to whitespace.
    # `\S+` stopped at the first space, so a quoted value leaked its tail and a
    # space-grouped push token leaked every group after the first.
    out = scrub_message('password = "hunter 2 with spaces";')
    assert "hunter" not in out and "spaces" not in out, out

    # Still handles the scheme-word form it always did.
    assert "abc.def.ghi" not in scrub_message("Authorization: Bearer abc.def.ghi")


def test_secret_rule_does_not_eat_diagnostic_prose():
    # The word "key" appears in ordinary log text — "Invalid value type for
    # configuration key: Calculator.BasicMode.AddSquareRoot" is the entire
    # diagnosis of an invalid DDM declaration. Treating a bare prose "key" as a
    # secret key redacted the answer the tool exists to produce.
    from mdm_log_analyzer.redact import scrub_message

    ddm = ("Invalid value type for configuration key: "
           "Calculator.BasicMode.AddSquareRoot, setting key "
           "calculator.forceSquareRootOnBasicCalculator")
    assert scrub_message(ddm) == ddm

    # macOS's own masking marker must survive — triage keys the
    # private_data_masked finding off it. The guard must also survive
    # backtracking: `\s*[=:]\s*(?!<private>)` can give back its space and check
    # the wrong position.
    assert "<private>" in scrub_message("challenge: <private>")
    assert "<private>" in scrub_message("challenge:<private>")
    assert "<private>" in scrub_message("Keys: <private>")

    # Keychain prose is diagnostic and starts with "Key".
    kc = "Keychain: Getting identity with ref: <IdentCert: foo>"
    assert scrub_message(kc) == kc


def test_keyed_identifiers_are_redacted_by_key_not_by_value_shape():
    # normalize.py already recognised `SerialNumber = …` as a serial by its KEY,
    # hashed it into device_ref, and left the plaintext in message. The
    # value-shape heuristic is a backstop: it requires both a letter and a digit
    # (so all-caps words like DEVICELOCKED survive), which drops an all-alpha
    # serial, and it never matched a hyphenated IMEI.
    from mdm_log_analyzer.redact import scrub_message

    for line, secret in [
        ("SerialNumber = FVFXQLMNPQRS;", "FVFXQLMNPQRS"),      # all-alpha serial
        ("IMEI = 35-209900-176148-1", "35-209900-176148-1"),   # hyphenated
        ("UDID = ABCDEFGHIJKLMNOPQRST;", "ABCDEFGHIJKLMNOPQRST"),
        ("PushMagic = QWERTYUIOP;", "QWERTYUIOP"),
        ("EthernetMAC = notamacaddress;", "notamacaddress"),
    ]:
        out = scrub_message(line)
        assert secret not in out, f"leaked: {out!r}"
        # Hashed, not blanked, so two events about one device still correlate.
        assert "h-" in out, out

    # The same value hashes the same way, so correlation survives.
    a = scrub_message("SerialNumber = FVFXQLMNPQRS;")
    b = scrub_message("Serial: FVFXQLMNPQRS")
    assert a.split("h-")[1].rstrip(";") == b.split("h-")[1]


def test_mdm_server_url_is_not_returned_in_cleartext():
    # get_device_context hashes the MDM host into mdm_server_host because it IS
    # an identifier — it names the tenant — but with no rule here the same host
    # came back raw from every other tool, which made the hashing cosmetic.
    from mdm_log_analyzer.redact import hash_id, scrub_message

    out = scrub_message("Calling MDM_Connect for: https://mdm.example-tenant.com/apple/mdm")
    assert "mdm.example-tenant.com" not in out, out
    assert "h-" in out

    # The host hashes to the same digest as get_device_context's `h:` form, so a
    # reader can still tie a message to the reported server.
    field = hash_id("mdm.example-tenant.com")
    assert field.split("h:")[1] in out, (field, out)

    # The PATH is dropped, not hashed: a real capture carried a SCEP challenge
    # inside it.
    scep = scrub_message(
        "Processing MDM_SCEP_Enroll for server: https://api.example.com/apple/scep/TUNMUkQ3UGd"
    )
    assert "TUNMUkQ3UGd" not in scep, scep
    assert "<redacted-path>" in scep


if __name__ == "__main__":
    import traceback

    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for t in tests:
        try:
            t()
            print(f"PASS {t.__name__}")
            passed += 1
        except Exception:
            print(f"FAIL {t.__name__}")
            traceback.print_exc()
    print(f"\n{passed}/{len(tests)} passed")
    sys.exit(0 if passed == len(tests) else 1)
