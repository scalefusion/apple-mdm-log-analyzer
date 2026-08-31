# Architecture & Component Reference

A detailed, module-by-module breakdown of the MDM/DDM Log Analyzer. For the
high-level design and rationale see [`mdm-log-analyzer-mcp-spec.md`](./mdm-log-analyzer-mcp-spec.md);
for contributor guidance and the project's invariants see
[`CONTRIBUTING.md`](./CONTRIBUTING.md). This document
describes **what each component does** and how data flows between them.

---

## 1. The shape of the system

Every tool is a thin wrapper over one reusable pipeline. Raw logs enter on the
left; clean, redacted `Event` / `Timeline` objects leave on the right. The
**redact** step is the last gate and is never optional.

```
                          predicate      source          parse          normalize        correlate        redact
  category + OS  ──►  predicates.resolve ─► sources.fetch ─► parser ──► normalize.normalize ─► engine ──► redact ──► Event / Timeline
                       (data/*.json)      (log show ndjson)  (ndjson+ts)   (heuristic fields)   (stitch)    (denylist)   (JSON out)
```

Layers, bottom to top:

| Layer | Modules | Responsibility |
|-------|---------|----------------|
| **Data shapes** | `schema.py` | The `Event`, `Timeline`, `Finding` dataclasses everything speaks in. |
| **Acquisition** | `sources.py`, `predicates.py`, `parser.py` | Get raw log text for a category + OS and turn it into dicts with normalized time. |
| **Extraction** | `normalize.py`, `redact.py`, `install_log.py`, `ddm_status.py`, `device_context.py` | Heuristic, version-sensitive parsing of message text into fields; mandatory redaction. |
| **Reasoning (deterministic)** | `triage.py`, `engine.py` | Correlate round-trips, derive outcomes, Tier-0 findings, and the tool functions. |
| **Transport** | `server.py` | `MCPServer` (mcp 2.x) exposing the seven tools + the archive registry. |

The engine is **stdlib-only**; `mcp` is the single runtime dependency.

---

## 2. Data structures — `schema.py`

Three dataclasses. `to_dict()` drops `None` fields so serialized output stays
compact and additive fields don't break older consumers.

### `Event` — one normalized log line (spec §6)

| Field | Meaning |
|-------|---------|
| `timestamp` | ISO-8601 UTC, ms precision (`2026-06-19T21:03:12.481Z`). |
| `process` | e.g. `mdmclient`, `apsd`, `remotemanagementd`. |
| `subsystem` | e.g. `com.apple.ManagedClient`, `com.apple.dmd`. |
| `category` | which predicate category produced it (§8 enum). |
| `message_type` | `default` / `info` / `debug` / `error` / `fault`. |
| `message` | the human-readable text, **scrubbed**. |
| `command_type` | `InstallProfile`, `DeclarativeManagement`, … when derivable. |
| `command_uuid` | hashed (`h:…`); legacy `CommandUUID=` or the modern operation `UUID:`. |
| `command_seq` | per-check-in sequence number — the macOS receipt↔result key. |
| `status` | `Acknowledged` / `Error` / `NotNow` / `Idle` / `CommandFormatError`. |
| `error_code`, `reason` | when present / a short normalized reason. |
| `device_ref` | hashed serial/UDID. |
| `raw_ref` | a pointer back into the source (`traceID` or `process#index`) — never the raw line. |

### `Finding` — a deterministic Tier-0 signal (spec §4.1)

`{ code, severity (info/warn/error), summary, evidence: [raw_ref…], confidence }`.
A structured observation, never prose. `evidence` holds `raw_ref` pointers only.

### `Timeline` — a correlated round-trip (output of `correlate_command`)

`{ command_uuid, command_type, outcome, latency_ms, confidence, events: [Event], tier0_findings: [Finding] }`.

`TERMINAL_STATUSES = {Acknowledged, Error, CommandFormatError}`;
`NONTERMINAL = {NotNow, Idle}` — used to decide when a round-trip has resolved.

---

## 3. Acquisition layer

### `sources.py` — where log text comes from

One abstraction, three implementations, so the engine never branches on source.

- **`LogSource` (ABC)** — the interface: `fetch(predicate, last, level) -> ndjson text`,
  `read_install_log(last) -> text` (optional; raises `NotImplementedError` if unsupported),
  and `probe() -> {os_build, time_span}` (for `open_archive`).
- **`LiveLogSource`** — shells `log show --style ndjson --last … --predicate …`
  (`--info`/`--debug` per level) on the current Mac. `read_install_log` reads
  `/var/log/install.log` plus rotated `install.log.N.gz`, concatenated
  oldest→newest, then time-filtered.
- **`ArchiveLogSource`** — same, with `--archive <path>` for a collected
  `.logarchive`/sysdiagnose.
- **`FixtureLogSource`** — reads a local NDJSON file; applies a coarse
  predicate filter (matches the quoted process/subsystem terms) so fixtures
  behave like the real thing **without** an NSPredicate engine. This is what
  makes the whole engine testable off-Mac. `probe()` computes the time span from
  the fixture's timestamps.
- **`open_archive_source(path, os_major)`** — factory used by the `open_archive`
  tool: `.logarchive` → `ArchiveLogSource`, `.ndjson` → `FixtureLogSource`,
  sysdiagnose tarball → `NotImplementedError` (Mac follow-up), missing →
  `FileNotFoundError`.
- Helpers: `_build_argv` (assembles the `log show` command line),
  `_window_seconds` / `_filter_install_window` (parse `30m`/`2h`/`1d` and trim
  install.log to the window).

### `predicates.py` — which filter to run, per OS (spec §8)

Predicates are **data, not code**: `data/predicates/<os_major>.json`.

- **`load(os_major)`** — reads the JSON for that version, **falling back to the
  highest available version ≤ requested** (so an unknown newer build still
  resolves), and tags the result with `_resolved_version` / `_exact`.
- **`resolve(category, os_major)`** — returns `{predicate, level, confidence,
  note, predicate_version, exact_version_match}` for one category.
- `CATEGORIES` — the §8 enum: `mdm_command, enrollment, push, scheduling,
  asset_download, ddm, declaration, pkg_install, profile_payload`.
- **Adding macOS support = adding one JSON file.** No code change.

### `parser.py` — ndjson + time

- **`parse_ndjson(text)`** — yields one dict per line; tolerates array brackets
  and trailing commas; skips malformed lines.
- **`to_iso_utc(raw_ts)`** — normalizes `log show` timestamps (and the ISO-colon
  `+05:30` form macOS 26 uses) to ISO-8601 UTC with ms precision.
- **`epoch_ms(iso_utc)`** — ms since epoch, for time math in correlation.

---

## 4. Extraction layer (heuristic, version-sensitive)

> Unified-log message text is **not a stable API**. All version-sensitive
> regexes live in these four modules so tuning per macOS build is contained.

### `normalize.py` — raw dict → `Event`

`normalize(raw, category, index)` extracts the MDM fields. The modern macOS
format (validated on 11/14/15/26) carries status + type in a check-in bracket;
there is **no protocol CommandUUID**. Extraction order:

- **`command_type`** — `RequestType=` (legacy) → `Processing server request: <Type>`
  → the `[Status(Type):n]` bracket → DDM declaration id.
- **`status`** — `Status=` (legacy) → the bracket status (`Acknowledged`/`Error`/
  `NotNow`/`Idle`/`CommandFormatError`).
- **`command_uuid`** — `CommandUUID=` (legacy) → the operation `UUID:`/`ID:` form
  (InstallApplication sub-steps). Hashed.
- **`command_seq`** — the `(n)` on the receipt and the `:n` in the result bracket
  — the deterministic receipt↔result key.
- `message` is run through `scrub_message`; `device_ref` is hashed.

### `redact.py` — the mandatory gate (spec §4.3)

- **`hash_id(value)`** — `h:` + first 12 hex of `sha256(per-session-salt + value)`.
  The salt is `os.urandom(16)`, fresh per process, never persisted — so the model
  can correlate "same device/command" across events without ever seeing the real
  value, and nothing is reversible after the process exits.
- **`scrub_message(message)`** — a **denylist of scrubbers** applied to free
  text: keyed secrets (any key ending in token/key/secret/password/…, so
  camelCase MDM payload keys like `DeviceToken` and `EscrowKey` are covered),
  keyed identifiers (`SerialNumber`, `UDID`, `IMEI`, `PushMagic`, … — hashed by
  KEY rather than by value shape), server URLs (host hashed, path dropped),
  ≥32-char hex blobs, emails, IPv4/IPv6, MACs, account names, and ≥10-digit runs.

  **This is a denylist, and that matters.** Anything not matched by a pattern
  passes through. Every gap found so far was found by running real Apple output
  rather than by reading the regexes — a `\b(token|…)\b` rule that looked
  correct could not fire on `DeviceToken` at all. When you add a field to any
  parser, check the value against `scrub_message` before returning it, and
  verify a rendered report with `tools/redaction-audit.sh` on the machine that
  produced the capture.

### `install_log.py` — `/var/log/install.log` → `InstallRecord` (spec §7.4)

install.log is plain syslog text, not unified-log ndjson, so it has its own
parser. `parse(text)` → ordered `InstallRecord`s. `_classify` maps message
phrasing to a phase (`failed` checked before `script` so a script line with a
nonzero exit is a failure); `is_failure` keys off phase, `fault` level, or a
nonzero exit code. Package attribution is **reverse-DNS bundle ids only** (the
quoted-display-name heuristic over-matched on real macOS 26 and was dropped).
Tuned + validated against a real 37 MB macOS 26 install.log.

### `ddm_status.py` — declarative logs → declaration status (spec §7.5)

`build(events, declaration_id)` reconstructs DDM state from the `declaration`
predicate category (remotemanagementd / com.apple.dmd / SoftwareUpdateMacController):

- **declarations** — id extracted from `configuration UI for:` / `Marked for
  deletion:` / a reverse-DNS `…declaration.<id>`; hashed into `declaration_ref`
  (type prefix kept for readability); state machine `seen → processing → active →
  removing`.
- **status_reports** — the cadence to the server: `status_sent`, `no_status`,
  `mdm_response` (+ HTTP code), `subscriptions_ack`, `sync`, `tokens_saved`.
- **failing** — keyed off message **text** (`invalid` / `failed to` / `unable to`
  / `Error Domain=` …) plus only the rarer `fault` level — **never**
  `messageType=="error"`, because macOS logs benign declaration lines at error
  level. Status-report lines are exempt (their key-paths can contain "failure").

### `device_context.py` — mdmclient logs → orientation (spec §7.1)

`build(events)` extracts the **MDM server host** (hashed), **installed-profile
counts** by scope (`Number of <Device> profiles found: N`), **last check-in**
(latest event), and an enrollment guess (`managed` iff an MDM server URL was
seen). Log-derived counts, not the live `profiles` store.

---

## 5. Reasoning layer

### `triage.py` — deterministic Tier-0 findings (spec §4.1)

`triage_timeline(events, outcome, latency_ms)` runs pure rules over an
already-correlated timeline and returns `Finding`s: `terminal_error`,
`notnow_loop`, `no_terminal`, `missing_push`, `high_latency`, `download_stall`,
`private_data_masked`. No network, no raw text — evidence is `raw_ref` pointers.
This is Tier 0: it works with no model at all.

### `engine.py` — the heart

`_collect(source, category, last, level)` is the shared path: resolve predicate →
`source.fetch` → `parse_ndjson` → `normalize` → sort by time. The tool functions:

- **`query_events`** — `_collect` for one category, capped by `limit`; returns
  `{events, count, truncated, predicate_version, exact_version_match}`.
- **`correlate_command`** — the crown jewel (detail below).
- **`get_install_log`** — `install_log.parse(source.read_install_log(...))`,
  optional `package_name` filter → `{phases, exit_codes, failures, count}`.
- **`get_ddm_status`** — `_collect("declaration")` → `ddm_status.build`.
- **`get_device_context`** — `device_context.build` + OS resolution + active
  declaration count (via `get_ddm_status`).
- **`build_incident_bundle`** — symptom-routed orchestration; `_resolve_plan`
  maps a symptom to which categories to pull, fans out, caps + de-dupes, embeds
  device context, and assembles `{context, timelines, notable_errors,
  tier0_findings}` (+ `install_log` when relevant).

**Correlation internals** (`correlate_command`):
- Build a de-duped **pool** of events across round-trip-relevant categories
  (`_dedupe` by `raw_ref`).
- **Anchor** by `command_uuid` or by `command_type` + `time_anchor`.
- **`_expand_core`** grows the anchor into the full round-trip using deterministic
  keys: `command_uuid` and `command_seq` are *global* strong keys; the thread id
  (`_thread`) is a *windowed* weak key (±60 s) so a recurring small sequence or a
  single-thread device can't over-merge unrelated commands.
- `_derive_outcome` (last terminal wins), `_latency_ms`, and `_confidence`
  (`high` only on a deterministic uuid/seq link to a terminal — `_linked_to_terminal`)
  produce the timeline; `triage_timeline` attaches Tier-0 findings.

### `server.py` — the MCP transport

An `MCPServer("mdm-log-analyzer")` exposing seven `@mcp.tool()` wrappers. Each is a
thin shell that builds a source and calls the engine.

- **`_build_source(source)`** — resolves the source: a registered `archive_id`
  (from `open_archive`) if given, else from environment
  (`MDM_LOG_ARCHIVE` > `MDM_LOG_FIXTURE` > live), with `MDM_LOG_OS_MAJOR` /
  `_detect_os_major` choosing the predicate version.
- **`open_archive(path, os_major)`** — registers a source under a deterministic
  `archive_id` in the in-memory `_ARCHIVES` registry; returns
  `{archive_id, os_build, time_span}`. The registry holds only handles — no corpus.
- Every other tool takes an optional **`source`** arg (the `archive_id`), so you
  open an archive once and target it everywhere. Unknown ids return a clean error.

---

## 6. Cross-cutting guarantees

- **Egress-free** — nothing in the server makes a network call. `sources.py` only
  shells to `log` or reads files.
- **Redaction mandatory** — every `Event.message` is scrubbed and every identifier
  hashed *inside* `normalize` / the extraction modules, before anything reaches a
  tool's return value. No tool returns raw log text.
- **Stateless** — no module writes the unredacted corpus to disk; the
  `_ARCHIVES` registry is in-memory and holds only paths/handles.
- **Version drift = data** — `data/predicates/11|14|15|26.json`. The engine never
  branches on OS; the predicate loader's fallback handles unknown builds.

---

## 7. File map

```
src/mdm_log_analyzer/
  schema.py        Event / Finding / Timeline dataclasses (§6)
  predicates.py    versioned predicate loader + resolve (§8)
  parser.py        ndjson parse + timestamp normalization
  sources.py       Live / Archive / Fixture + open_archive_source + probe (§5)
  normalize.py     raw dict -> Event, heuristic MDM field extraction
  redact.py        per-session salted hashing + scrub denylist (§4.3)
  install_log.py   install.log -> InstallRecord (§7.4)
  ddm_status.py    declarative logs -> declaration status (§7.5)
  device_context.py mdmclient logs -> device context (§7.1)
  triage.py        deterministic Tier-0 findings (§4.1)
  engine.py        _collect + the six tool functions + correlation internals
  server.py        MCPServer (mcp 2.x): 7 tools + archive registry (§7)
  data/predicates/ 11.json 14.json 15.json 26.json   (versioned predicate data)
```

---

## Log-format notes (the version-sensitive part)

Everything below was learned by running this code against real macOS captures and
finding it wrong. Unified-log message text is not a stable API, so this is the
part most likely to need retuning for a new release — and the part where a wrong
assumption produces a confident, false answer rather than an error.

### Environment

- **`log show` is macOS-only.** Develop and test against `FixtureLogSource`;
  validate Live/Archive on a Mac. Validated on macOS 26.5.1 (build 25F80, a
  DEP/Scalefusion-enrolled machine): the live path works without sudo at default
  level (~1k mdmclient events / 30m), `install.log` parsing is tuned to the real
  format there, and **`.logarchive` ingestion is validated end-to-end** —
  `sudo log collect --last 10m --output test.logarchive` → `open_archive` →
  `query_events` reads via `log show --archive` (~250 ms for 188 events, macOS 26
  predicate resolved exactly). `ArchiveLogSource.probe()` now reads
  os_build from the archive's Info.plist; time_span remains null (requires
  parsing TraceV3 headers or an undocumented `log stats` shape, deferred).
- Full live logs at info/debug level require root.
- **install.log format drifted on macOS 26:** ISO-colon timezone (`+05:30`),
  no `<Level>` tag, `Install Succeeded` only via `Installer` UI text, and quoted
  strings are script/component names (not display names). `install_log.py` is
  tuned for this; keep package attribution to reverse-DNS bundle ids only.

---

### Traps found on real captures

- On managed devices, MDM detail logs as `<private>` until the MDM private-data
  logging profile is deployed (spec §4.5; `tools/private-data-logging.mobileconfig`).
  With it deployed, ~5-11% of mdmclient lines remain masked but command status/
  type become readable. **No protocol CommandUUID** is logged in the check-in
  lines — status+type ride in a check-in bracket `[Status(CommandType):n]` (e.g.
  `[Acknowledged(InstallProfile):12804726]`) and on receipt in
  `Processing server request: <Type> for: <Device> (n)`. But two real
  correlation keys DO exist and `normalize.py`/`correlate_command` use them:
  the per-check-in **sequence `n`** ties receipt↔result, and InstallApplication
  logs an **operation UUID** (`UUID:`/`ID:`) across its sub-steps (bridged to the
  round-trip by thread id). Time+type is the fallback when neither is present.
- **A DDM payload error may or may not be logged — it depends on the
  declaration type.** Earlier this file stated flatly that an invalid
  declaration is invisible to the device log. That was over-generalized from one
  capture. What is always true: the `DeclarativeManagement` command is
  `Acknowledged` (the ack confirms receipt of the declaration set, not the
  validity of what is inside), evaluation is async, and the authoritative result
  goes back as a **StatusReport**. But the *subscriber* often does log the
  reason. On a real macOS 27 (26A5416b) invalid-declaration capture,
  `ManagedSettingsSubscriber` (subsystem `com.apple.remotemanagementd`) logged
  it explicitly ~1.2 s after the ack, naming the offending key:
  `Invalid value type for configuration key: Calculator.BasicMode.AddSquareRoot,
  setting key calculator.forceSquareRootOnBasicCalculator`, then
  `AdapterError.invalidValueType(...)`. The declaration stalls at `seen` and
  never reaches activated/applied. An earlier 25F80 capture logged nothing —
  so treat "no error logged" as inconclusive, never as proof the declaration is
  valid. `get_ddm_status` surfaces whatever the device did log, and
  `build_incident_bundle` folds its `failing` array into a
  `declaration_failure` finding for ddm symptoms.
- **Don't treat `messageType == "error"` as a failure signal** — macOS logs many
  benign declarative lines (e.g. `Get configuration UI for: …`) at error level.
  `ddm_status.py` keys `failing` off message TEXT (`invalid`/`unable to`/`failed
  to`/…) and only trusts the rarer `fault` level. (Over-reported 5 false
  failures on a real capture before this fix.)
- **The `ErrorChain` says WHY a command failed, and it is not masked.** The
  status bracket only says a command errored. The reason arrives either inline —
  `[ErrorChain.0] (InstallProfile) [CPProfile:-102] The profile is either
  missing some required information…` — or as a full response payload
  (`Error in pending response: { CommandUUID = …; ErrorChain = ( … ); RequestType
  = …; Status = Error; }`). Both were readable on a real 26.6.1 capture *without*
  the private-data profile, so "the reason is masked" is usually wrong: check for
  an ErrorChain first. Two traps: the payload spells keys as `Key = Value` with
  spaces, which the older `Key[=:]` patterns miss; and its `CommandUUID` is the
  numeric **check-in sequence**, not a UUID — that is what ties it to the
  round-trip. Inline chain lines carry code+reason but deliberately get NO
  status, since they describe a command already counted via its bracket.
- **Redaction must cover account names spelled as keys.** The `/Users/<name>`
  rule does not catch `UserLongName = jappleseed;` in a command response
  payload, which leaked a real username past §4.3. `redact.py` now hashes
  `UserLongName`/`UserShortName`/`UserName`/`AccountName`/`ManagedAppleID` and
  the `<User: 506>` spelling of a uid. When adding a field to any payload
  parser, check the value against the scrubbers before returning it.
- **A command result is logged twice, and the receipt repeats its sequence.**
  mdmclient emits the `[Status(Type):n]` bracket on both the outgoing HTTP
  request and the response, and `Processing server request: … (n)` carries the
  same `n`. Anything that counts commands must key on the sequence number (or
  the InstallApplication operation UUID) — a per-line tally over-reported a real
  window by 2x (58 Acknowledged / 20 Error where the truth was 29 / 9).
- **`traceID` is not a per-line id** — it identifies the emitting code site
  (452 distinct values across 17,019 real mdmclient lines). `raw_ref` is
  `traceID:machTimestamp`, which is unique per line and still intrinsic, so it
  stays stable when the same line is fetched under a different category. Never
  de-duplicate by `traceID` alone; it collapses distinct errors.
- **An aborted managed-app install is invisible to install.log.** When
  PackageKit rejects the package up front, installd never opens a session, so
  `get_install_log` sees nothing — the failure exists only in mdmclient's
  `ManagedApps` lines (`Aborting app install: … <PKInstallErrorDomain:100>`,
  `Install '<uuid>' finished.  Sucess: no` — note macOS's own misspelling).
  `normalize.py` extracts code/reason/`app_id` from these and `triage.py` raises
  `app_install_abort`. The InstallApplication command itself is `Acknowledged`:
  the command succeeded and the install did not. One abort spans ~6 lines
  (phases keyed by operation uuid, an ASD notification carrying only the bundle
  id, an abort line carrying neither), so the engine folds the uuid-less
  fragments into the single install operation.
- **`collect-mdm-logs.sh` windows install.log now, but rotations are copied
  whole.** It used to `cp` the live file wholesale, so a 10-minute capture
  shipped 9 days / 34k lines, and `get_install_log` reported installs from days
  outside the window as if they were inside it. Capture sources window
  install.log anchored on its newest line (wall-clock only for the live log).
- Unified-log retention is short on busy machines — for after-the-fact analysis
  prefer a collected sysdiagnose/archive over the live log.
- DDM declarative subsystems are **pinned for macOS 15 and 26** (`com.apple.dmd`,
  `remotemanagementd`, `SoftwareUpdateMacController`, plus `ManagedAppDistribution`
  on 26; confirmed on 24G90 and 25F80). macOS 14 inherits the same set but is
  **unconfirmed** (no declarative activity captured on 23A344). The serial
  scrubber over-match was fixed (letter+digit).
- **The `[Status(CommandType):n]` mdmclient format is the same across macOS 11,
  14, 15, 26 and 27** (validated on real captures from each — 27 confirmed on
  26A5416b: `[Acknowledged(InstallApplication):13277150]`) — `normalize.py` needs
  no per-version branching. No build logs a protocol CommandUUID, but the
  check-in **sequence `n`** (receipt↔result) and the InstallApplication
  **operation UUID** are correlation keys `correlate_command` uses; time+type is
  the fallback. Big Sur (11) predates DDM, so its ddm category matches nothing
  real; 12/13 resolve to 11.json by fallback.
