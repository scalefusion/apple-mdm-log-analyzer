# MDM/DDM Log Analyzer

**Ask why an MDM command failed, in English, and get an answer from the device's
own logs.** A local [MCP](https://modelcontextprotocol.io) server that turns
macOS unified-log noise into correlated MDM command round-trips, install
sessions, and declarative-management status.

> Point it at a log bundle and ask *"why did this profile installation fail?"*
> It answers from `mdmclient`, `installd` and `remotemanagementd` — correlated,
> redacted, and without the logs leaving your control.

**First time here?** → **[SETUP.md](./SETUP.md)** takes you end to end, from
installing Python to your first answer.

## What it looks like

Rendering a report over a sample capture (`--report`, no MCP client needed):

```
## Findings
- [error] terminal_error   — Command terminated with Error (error_code 12063).
- [info]  download_stall   — Asset download was in progress but the command did
                             not complete successfully.
- [error] command_failures — 1 MDM command(s) returned Error: InstallApplication×1.

### InstallApplication → Error (29300 ms, confidence high)
- 21:03:10.100  apsd:        Received notification for topic com.apple.mgmt.External.…
- 21:03:11.200  mdmclient:   Received MDM command: RequestType=InstallApplication
                             for SerialNumber=<redacted-serial>
- 21:03:11.900  storedownloadd: Begin downloading asset for managed install
- 21:03:12.300  mdmclient:   Sending response: Status=NotNow … device is locked
- 21:03:40.500  mdmclient:   Sending response: Status=Error ErrorCode=12063
```

Six processes' worth of interleaved log lines, resolved into one round-trip with
an outcome, a latency and a confidence rating — with the serial already redacted.
Reproduce it yourself after installing:

```bash
mcp-mdm-log-analyzer --report --symptom install_failure --last 1d \
  --source tests/fixtures/mdm_sample.ndjson
```

## AI disclosure

This codebase was written with [Claude Code](https://github.com/anthropics/claude-code)
(Anthropic). Direction, test scenarios and validation came from a human
maintainer: almost every behaviour here was corrected after being run against
real macOS 26/27 captures and found wrong, and each correction has a regression
test naming the capture that exposed it.

What has not happened: no independent security review, and no formal audit of
the redaction layer. Redaction is mandatory and tested, and
[`tools/redaction-audit.sh`](./tools/redaction-audit.sh) checks a rendered report
against a machine's real identifiers — **run it on your own data before trusting
the privacy posture for anything sensitive.**

## Quickstart

```bash
python3 -m venv ~/mdm-analyzer && ~/mdm-analyzer/bin/pip install mdm-log-analyzer
```

Collect a bundle on the Mac with the problem, then ask your MCP client about it:

```bash
./tools/collect-mdm-logs.sh 20m          # → mdm-logs-<host>-<stamp>.tar.gz
```

Full walkthrough — Claude Desktop config, a fully local model via Ollama,
collecting from a remote Mac, troubleshooting — in [SETUP.md](./SETUP.md).

## Why it is safe to point at device logs

Three properties, in the code rather than the docs:

- **Egress-free.** The server makes no outbound network calls. Which model sees
  the data is your client's choice, never something this server decides.
- **Redaction is mandatory and on by default.** Serials, UDIDs, usernames,
  IP/MAC addresses, tokens and certificate material are hashed with a
  per-session salt or scrubbed, on an allowlist basis, before anything is
  returned. Verify it against your own machine with
  [`tools/redaction-audit.sh`](./tools/redaction-audit.sh).
- **No tool returns raw log text.** Tools return structured events, never lines.

**Never attach raw logs to a ticket or a chat.** Give the analyzer a *path* — it
redacts on read, not on capture. See SETUP.md §8b.

## Status

Seven tools, 94 engine tests (stdlib-only) plus a stdio smoke test of the server
itself. Per-OS predicate files for **macOS 11 / 14 / 15 / 26 / 27**.

Known limits, so you do not rediscover them:

- macOS 14's and 27's *declarative* subsystem sets are inherited and
  unconfirmed. Command extraction is validated on 11 / 14 / 15 / 26 / 27.
- `.logarchive` `time_span` is unimplemented; `get_install_log` works against
  bundles and the live log, not a `.logarchive`.
- sysdiagnose tarballs are not wired into `open_archive` — extract the
  `.logarchive` and pass that.
- The heuristics are version-sensitive by design: unified-log message text is
  not a stable API. Predicates are *data* so that supporting a new macOS is a
  data change.

## Stability

Semantic versioning applies to the **MCP tool names and their arguments**.

- Fields may be **added** to returned objects in a minor release; a client must
  tolerate unknown fields.
- A change to what an **existing field means** — what it counts, how it is
  measured — is **breaking**: it gets a major bump and a
  [changelog](./CHANGELOG.md) entry, not a quiet fix.
- The `h:`/`h-` hashes use a **per-session salt** by design — stable within one
  server process, meaningless across restarts. Never persist them or compare
  them between sessions.
- Files under `data/predicates/` are data, not API. Adding a macOS release is a
  minor release.

## Docs

| | |
|---|---|
| [SETUP.md](./SETUP.md) | Install, client config, collecting logs, troubleshooting |
| [ARCHITECTURE.md](./ARCHITECTURE.md) | Module reference, and the log-format traps found on real captures |
| [CONTRIBUTING.md](./CONTRIBUTING.md) | How to work on it, and the invariants that are not negotiable |
| [MAINTAINING.md](./MAINTAINING.md) | Releases, CI, deploy tokens (maintainers) |
| [CHANGELOG.md](./CHANGELOG.md) | What changed, and which changes were breaking |
| [spec](./mdm-log-analyzer-mcp-spec.md) | The design the code cites by section number |

## Prerequisite on managed devices

For real diagnostic value, deploy
[`tools/private-data-logging.mobileconfig`](./tools/private-data-logging.mobileconfig)
on the source Mac *before* collecting. Without it macOS masks MDM command detail
as `<private>`, and DDM failure detail is not logged at all. See SETUP.md §5.

## License

MIT — see [LICENSE](./LICENSE). © 2026 Scalefusion.
