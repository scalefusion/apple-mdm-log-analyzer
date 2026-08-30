# Changelog

Versioning follows the contract in [README.md § Stability](./README.md#stability):
semantic versioning applies to the MCP tool names and their arguments. Fields may
be *added* to returned objects in a minor release. A change to what an **existing
field means** is breaking, and is listed here under a major version.

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
