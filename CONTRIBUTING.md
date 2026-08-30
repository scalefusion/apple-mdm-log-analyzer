# Contributing

Thanks for looking at this. It is a small, deliberately boring codebase: a local
MCP server that turns macOS MDM logs into structured events. The engine is
stdlib-only and the tests run anywhere.

## Getting set up

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e .
python3 tests/test_engine.py        # engine suite, zero dependencies
python3 tests/test_server_smoke.py  # MCP server over real stdio (needs `mcp`)
```

You do **not** need a Mac to work on the engine, the parsers, the redaction layer
or the predicates — `FixtureLogSource` and `BundleLogSource` read plain NDJSON.
You **do** need a Mac to exercise `LiveLogSource` and `.logarchive` reading,
because those shell out to Apple's `log` binary, which is the only supported
decoder for the unified log's TraceV3 format.

## The three rules that are not up for negotiation

These are the product's reason for existing. If a change seems to require
breaking one, please open an issue first rather than a merge request.

1. **The server is egress-free.** No outbound network calls, no telemetry, no
   phone-home. Which model sees the data is the *client's* choice, never
   something this server decides or enables.
2. **Redaction is mandatory and on by default.** Every event passes through
   `redact.py` before leaving. Identifiers are hashed with a per-session salt or
   scrubbed, on an allowlist basis. Never weaken the default.
3. **No tool returns raw log text.** Tools return `Event` / `Timeline` objects.

`tools/redaction-audit.sh` checks a rendered report against a machine's real
identifiers. If you touch `redact.py`, run it on a real capture from the machine
you captured on, and say so in the merge request.

## What good changes look like

**Fix things with a real capture, not a hunch.** Almost every bug found in this
codebase was found by running it against real macOS logs and seeing it report
something false — usually "nothing found" when the answer was right there. If you
have a capture that the tool reads wrongly, that is the most valuable thing you
can bring. Sanitise it before attaching anything (see below).

**Add a regression test that names the shape that broke it.** Every fix here has
one, written from the real log line rather than an imagined one. The tests are
plain asserts in `tests/test_engine.py` with a comment explaining what the bug
looked like from the outside; match that style.

**Supporting a new macOS release is a data change.** Predicates live in
`src/mdm_log_analyzer/data/predicates/<os_major>.json`. Add a file; do not branch
on OS version in code. That versioned-data approach *is* the version-drift
strategy.

**Expect to tune the heuristics.** Unified-log message text is not a stable API.
`normalize.py`, `install_log.py`, `ddm_status.py` and `device_context.py` are all
heuristic and version-sensitive by design, and each one has needed retuning for a
macOS release. That is expected, not a design flaw — but keep the regexes in
those modules rather than spreading them.

**A source abstraction that only works for one source is a bug.** New logic must
work across Live, Archive, Bundle and Fixture with no source-specific branches.

## Reporting a bug in the analysis

The useful report says what the tool claimed, what the log actually contained,
and how you know. "It said the window was clean; here are the three failed
commands in it" is worth more than a stack trace.

**Never attach a raw capture to an issue.** Unfiltered MDM logs contain device
serials, hardware UUIDs, usernames, MDM server URLs, push tokens and certificate
material, and the analyzer redacts on *read*, not on capture. If you need to show
data, paste the output of:

```bash
mcp-mdm-log-analyzer --report --format json --symptom activity --last 20m \
  --source <your-bundle.tar.gz>
```

…and check it first with `tools/redaction-audit.sh`.

## Merge requests

- Small and reviewable beats large and complete. One logical change per MR.
- Run `python3 tests/test_engine.py` and say what it printed.
- Show evidence rather than asserting success — the command you ran and what it
  returned. If you could not verify it, say which part.
- If your change alters what a tool *returns*, say so plainly: a client is
  parsing that shape.

## Things known to be unfinished

Worth reading before starting, so you do not rediscover them:

- macOS 14's declarative subsystems are inherited from later releases and
  unconfirmed — no DDM-active Sonoma capture exists yet.
- macOS 27's declarative set is likewise inherited; its command-bracket format
  *is* confirmed.
- `.logarchive` `time_span` is unimplemented (needs TraceV3 header parsing).
- sysdiagnose tarballs are not wired into `open_archive` — extract the
  `.logarchive` and pass that.
- `get_install_log` does not work against a `.logarchive` source, only bundles
  and the live log.
- A time+type anchored correlation can absorb a neighbouring command's terminal
  status via the operation-uuid key, and reports `confidence: low` when it does.

## Licence

MIT. By contributing you agree your contribution is licensed under it.
