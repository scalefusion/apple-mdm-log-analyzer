# Changelog

Versioning follows the contract in [README.md § Stability](./README.md#stability):
semantic versioning applies to the MCP tool names and their arguments. Fields may
be *added* to returned objects in a minor release. A change to what an **existing
field means** is breaking, and is listed here under a major version.

## 1.1.0

**Security — upgrade from 1.0.0.** An external review found that the scrubber
missed the highest-value secrets in the MDM protocol. Every string below was
verified leaking in 1.0.0 and is redacted now.

| Leaked in 1.0.0 | Cause |
|---|---|
| `DeviceToken` (the APNs push token), `UnlockToken`, `EscrowKey`, `AwaitDeviceConfiguredToken` | `\b(token\|…)\b` cannot match a camelCase key — there is no word boundary inside `DeviceToken` |
| the tail of any quoted secret, e.g. `password = "hunter 2 with spaces"` | the value was consumed with `\S+`, which stops at the first space |
| `SerialNumber`, `UDID`, `IMEI`, `PushMagic`, MAC fields | redacted by value SHAPE only; an all-alpha serial or a hyphenated IMEI matched nothing |
| the MDM server URL, and a SCEP challenge inside its path | there was no URL rule at all, so the host `get_device_context` hashes came back in cleartext from every other tool |

Keys are now matched by their tail, values to a structural terminator, keyed
identifiers by name (hashed, so devices still correlate), and URL hosts hashed
with the path dropped.

**Field meanings changed** (per README § Stability, called out rather than
quietly fixed):

- `Event.message` content differs wherever the above appeared. A consumer
  parsing message text will see redacted values where 1.0.0 showed plaintext.
- A keyed serial renders as `h-<hash>` rather than `<redacted-serial>`. Hashed so
  two events about one device correlate; a serial appearing bare in prose is
  still blanked.

**Added fields** (additive, tolerate-unknown-fields applies):

- `query_events` → `truncation.messages_clipped`, `truncation.dropped_for_size`.

**Also fixed**

- `<private>` was being redacted when written `challenge: <private>` — the guard
  was defeatable by regex backtracking, and that marker is what `triage.py` keys
  `private_data_masked` off.
- Archive extraction is bounded (1 GiB of uncompressed bytes, refused from the
  member headers before anything is written) and reused by resolved path. A
  well-formed 538 KB tarball expanded to 188 MB, and three `open_archive` calls
  on one path held 564 MB until the process exited.
- `query_events` responses are capped by bytes, not only by event count: 15.4 MB
  measured at the event ceiling with realistic payload-dump lines, against a
  1 MB transport limit. Now 0.83 MB, with the true `count` still reported.
- A `.json`/`.ndjson` source must look like `log show` output. Any readable file
  was accepted, so an unrelated `.json` could be opened and returned through
  `query_events`, and a binary file became a valid *empty* archive — reading as
  "the window was clean" rather than as an error.
- Tools honour the `{"error": …}` contract: the engine call sat outside the try
  in five of six, and `probe()` sat outside it in `open_archive`.
- `log show` has a 180s timeout; without one a wide window presented as a hang.
- `collect-mdm-logs.sh` sets `umask 077` (the bundle is unredacted and was
  world-readable, contradicting its own PRIVACY header), validates the time
  window, and warns when a category captured nothing.
- `mdm_log_analyzer.__version__` is derived from metadata; it said `0.1.0` while
  the package was 1.0.0.
- `SETUP.md` no longer suggests running the server as root.

**Tooling:** macOS CI (the `log show` paths had zero coverage), ruff (F/E/W/B —
`F821` is the rule that would have caught an unimported annotation), the release
action pinned to a commit SHA, and CI now runs the suites under pytest as well
as directly. 105 engine tests, up from 94.

## 1.0.0

First public release.

Seven MCP tools — `open_archive`, `query_events`, `correlate_command`,
`get_install_log`, `get_ddm_status`, `get_device_context`,
`build_incident_bundle` — with deterministic Tier-0 triage, mandatory
field-level redaction, and per-OS predicate files for macOS 11 / 14 / 15 / 26 / 27.

The tool names and arguments have been stable since 0.1 and are what this
version's compatibility promise covers.

**Field meanings settled before 1.0.0.** Listed because anything comparable after
this point is a major bump:

- `command_activity.by_status` / `by_type` count **commands, not log lines**. A
  result is logged on both the outgoing HTTP request and the response, and the
  receipt repeats the sequence number, so a per-line tally over-reported by ~2x.
- Protocol check-ins (`MDM_Authenticate`, `MDM_TokenUpdate`,
  `MDM_RemoteManagement`, `MDM_CheckOut`) are counted in
  `command_activity.checkins`, **not** in the command tally. A refused check-in
  is how enrollment fails, but it is not a failed command.
- A successful managed-app install operation is not counted as a second
  `InstallApplication`; a failed one is, because that is new information.
- `session_summary.time_span` ends where the last install session **ended**, not
  where it started.
- A deferred command's `outcome` is `NotNow`, not `Idle`.
- An install session whose bracket never closed but which recorded a failure is
  `failed`, not `incomplete`.
- `latency_ms` measures the command's own events, never the padded context
  around it.
- `truncation` is always stated when a list is capped, and caps keep the **most
  recent** entries.

**Known limits at 1.0.0** — see README § Status. In short: the declarative
subsystem sets for macOS 14 and 27 are inherited and unconfirmed; `.logarchive`
`time_span` is unimplemented and `get_install_log` does not read that source;
sysdiagnose tarballs are not wired into `open_archive`.
