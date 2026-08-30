# MDM/DDM Log Analyzer — MCP Server Specification

**Status:** Draft v0.1
**Date:** 2026-06-19
**Audience:** Engineering (implementer), security review
**One-line:** A local-only, stateless MCP server that extracts, parses, and correlates macOS MDM/DDM/installer log events into compact structured bundles, leaving model-based reasoning to a pluggable, admin-chosen client.

---

## 1. Purpose & scope

Mac admins debugging MDM problems today read raw unified-log output by hand, correlating events across several processes to reconstruct what happened to a single command, declaration, or package install. This is slow and error-prone, and the useful detail is cryptic.

This server exposes that log corpus to an LLM client as a small set of well-scoped tools that return **structured, pre-filtered, pre-correlated** events — so the model reasons over a clean timeline rather than millions of raw lines.

**In scope:** legacy MDM commands, Declarative Device Management (DDM) declarations and status, PKG/installer events, configuration-profile/payload installation, APNs push and scheduling signals; both live-machine and collected-archive (sysdiagnose / `.logarchive`) sources.

**Out of scope (v1):** modifying device state, sending MDM commands, talking to the MDM server's API, fleet aggregation/dashboards, non-macOS platforms.

---

## 2. Goals & non-goals

**Goals**
- Turn noisy multi-process logs into a normalized event schema and correlated timelines.
- Make the privacy posture a property of the architecture, not a configuration the admin can accidentally get wrong.
- Be model-agnostic: the same server works behind a local model, Apple's models, or a zero-retention commercial API.
- Track macOS version drift in predicates as data, not hardcoded logic.

**Non-goals**
- The server does not reason, diagnose, or generate prose. That is the client/model's job.
- The server does not phone home, emit telemetry, or persist data by default.

---

## 3. Architecture overview

```
                          (admin's choice of brain)
                          ┌───────────────────────────┐
  ┌──────────────┐  MCP   │  MCP client + model        │
  │  This server │◄──────►│  • local model (Ollama/MLX)│
  │  (local,     │ stdio  │  • Apple Foundation Models │
  │  stateless)  │        │  • ZDR commercial API      │
  └──────┬───────┘        └───────────────────────────┘
         │ reads (root)
   ┌─────┴───────────────────────────┐
   │ macOS log sources               │
   │ • live unified log (log show)   │
   │ • /var/log/install.log (+ .gz)  │
   │ • collected .logarchive /       │
   │   sysdiagnose (log show --archive)
   └─────────────────────────────────┘
```

**Core principle: the server is egress-free.** It reads logs locally and returns structured results over the MCP transport to the local client. Whether any data crosses the network is determined entirely by the client's model choice — never by this server. This keeps the privacy decision in one place and lets a single build serve every privacy tier in §4.

The reusable heart of the server is the **extraction + correlation engine** (predicate resolution → `log show --style ndjson` → parse → normalize → correlate → redact). Every tool is a thin wrapper over this engine.

---

## 4. Privacy & data-handling model (priority requirement)

Requirement: log data must not leak and must not be used to train models. The design satisfies this with a privacy spectrum plus a mandatory redaction layer.

### 4.1 Tiers (strongest → most capable)

| Tier | Brain | Network egress | Notes |
|------|-------|----------------|-------|
| 0 | None — deterministic rules | None | Server emits a rule-based triage report. Stronger than any cloud option: nothing is ever inferred off-device. Doubles as the correlation engine. |
| 1 | Local model (Ollama / LM Studio / MLX, or Apple on-device Foundation Model) | None | Data never leaves the Mac; air-gappable. Reasoning quality bounded by local model size. |
| 2 | Confidential cloud, by explicit consent | Scrubbed view only | Apple PCC (eligibility-gated) or a commercial API under no-training + zero-retention terms. |

Recommended default: **Tier 0 always available; Tier 1 as the standard interactive mode; Tier 2 opt-in per incident with explicit admin consent.**

### 4.2 Model-routing options and their guarantees (verify before relying)

- **Apple on-device Foundation Model** — no network, strongest guarantee. Requires a Swift `FoundationModels` component (the Python/Node server would call it via a small native helper). Reasoning capacity is modest.
- **Apple Private Cloud Compute** — strong privacy model (stateless processing, no retained access after the response, no privileged Apple-staff access, verifiable transparency, IP hidden via an OHTTP relay). **But** access is gated to App Store Small Business Program developers under 2M first-time downloads, is Apple-models-only, has no paid tier, and is reached via the Swift framework. Treat as a possible option only if eligibility and model capability both fit — not the primary path for a fleet-admin tool.
- **Commercial API with Zero Data Retention (ZDR)** — e.g. Claude via the Messages API. Under commercial terms the provider does not train on inputs/outputs (absent an explicit opt-in program), and ZDR means inputs/outputs are not stored at rest beyond abuse/legal screening (safety-classifier results may still be retained). Design caveats:
  - ZDR is granted **per organization, subject to approval** — confirm it is active before enabling Tier 2.
  - **Do not** route logs through the Files API or explicit prompt caching: those require persistent storage and can override ZDR. Send events inline in the Messages API only.
  - Web-search or other third-party tool calls are not covered by ZDR — keep them off in this path.

### 4.3 Mandatory redaction / minimization layer

Applied by the server to every event before it leaves toward any model (all tiers above 0), driven by a field-level allowlist:

- **Always masked or hashed:** device serial numbers, UDIDs/hardware UUIDs, usernames and user IDs, IP/MAC addresses, SCEP/payload secrets, tokens, push tokens, certificate material.
- **Hashing:** use a per-session salt so the model can still correlate "the same device/command across events" without seeing the real identifier.
- **Allowlist, not denylist:** emit only the fields the analysis needs; everything else is dropped.
- **Redaction profiles** are configurable but ship with a conservative default that satisfies a no-PII-egress posture out of the box.

### 4.4 State & telemetry

- Stateless by default. No analytics, no crash reporting, no network calls originating from the server.
- Any local cache is opt-in, encrypted at rest, and ephemeral (TTL-bounded), and never holds the unredacted corpus longer than the request.

### 4.5 Prerequisite: unmasking private data

By default much MDM detail (command UUIDs, payload bodies, declaration contents) logs as `<private>`. To capture it, deploy the MDM debug / private-data logging configuration profile to target devices (feasible here because the operator has full MDM control). Document this as a deployment step; without it, Tier-0/1/2 analysis is materially degraded. Note that enabling private data also increases the sensitivity of the corpus, which is exactly why §4.3 is mandatory.

---

## 5. Deployment models

1. **Archive-ingesting (recommended primary).** Admin collects a sysdiagnose or `.logarchive` from the affected Mac; the server runs on the admin's machine and reads it via `log show --archive`. Fits real fleet support, where an interactive shell on the user's Mac is rare.
2. **On-device.** Server runs on the Mac being diagnosed and reads the live unified log. Requires root. Best for hands-on or lab/VM reproduction.

Both models resolve the same predicates against a `source` parameter, so no category logic changes between them.

---

## 6. Event schema

All query/correlation tools emit objects of this shape. `count` and `truncated` let the model know whether it is seeing the full set.

```json
{
  "timestamp": "2026-06-19T14:03:12.481Z",
  "process": "mdmclient",
  "subsystem": "com.apple.ManagedClient",
  "category": "mdm_command",            // see §8 enum
  "message_type": "error",              // default | info | debug | error | fault
  "command_type": "InstallApplication", // when derivable
  "command_uuid": "h:3f9c…",            // hashed unless allowlisted
  "command_seq": "12804726",            // per-check-in sequence (macOS receipt↔result key)
  "status": "Error",                    // Acknowledged | Error | NotNow | Idle | n/a
  "error_code": 12063,                  // when present
  "reason": "NotNow: device locked",    // short normalized reason
  "device_ref": "h:a17b…",              // hashed serial/UDID
  "message": "…redacted human-readable text…",
  "raw_ref": "src#offset"               // pointer back into source, not the raw line
}
```

Timeline objects (from `correlate_command`) wrap an ordered list of these plus a derived `outcome` and `latency_ms`.

---

## 7. Tool surface

Each tool returns structured JSON, applies §4.3 redaction, and is safe to call repeatedly. Signatures are language-neutral.

### 7.1 `get_device_context`
Orient the model before querying.
- **Params:** `source` (`live` | archive id)
- **Returns:** OS name/build, enrollment status, installed configuration profiles, active DDM declarations (read directly — the `profiles` command does not list declarations, since they live in a tamper-proof store), MDM server URL host (redacted), last check-in time.

### 7.2 `query_events`
The workhorse.
- **Params:** `category` (§8 enum), `time_window` (`{last: "30m"}` or `{start, end}`), `source`, `level` (`info` default | `debug`), `limit` (default 500).
- **Behavior:** resolves the versioned predicate for `category` + OS, runs `log show --style ndjson` (or `--archive`), parses, normalizes, redacts.
- **Returns:** `{ events: Event[], count, truncated }`.

### 7.3 `correlate_command`
The crown jewel — stitches one round-trip.
- **Params:** `command_uuid` (hashed or raw) **or** `time_anchor` + `command_type`; `source`.
- **Behavior:** gathers the APNs wake → `mdmclient` receipt → processing → result (`Acknowledged` / `Error` / `NotNow` + reason) across processes and orders them.
- **Returns:** a timeline object with `outcome`, `latency_ms`, and the ordered `events`.

### 7.4 `get_install_log`
- **Params:** `package_name` (optional), `time_window`, `source`.
- **Behavior:** parses `/var/log/install.log` (+ rotated `.gz`) into installer/installd phases and exit codes.
- **Returns:** `{ phases: [...], exit_codes: [...], failures: [...] }`.

### 7.5 `get_ddm_status`
- **Params:** `source`, optional `declaration_id`.
- **Behavior:** reads the active declaration set and latest device status reports (these arrive as JSON from the device) and flags failed/pending declarations.
- **Returns:** `{ declarations: [...], status_reports: [...], failing: [...] }`.

### 7.6 `open_archive`
- **Params:** `path` to a `.logarchive` or sysdiagnose tarball.
- **Behavior:** validates and registers the archive, returning an `archive_id` usable as `source` in every other tool.
- **Returns:** `{ archive_id, os_build, time_span }`.

### 7.7 `build_incident_bundle`
Anti-context-blowup convenience wrapper.
- **Params:** `symptom` (enum or free text), `time_window`, `source`.
- **Behavior:** runs the relevant `query_events` + `correlate_command` calls and assembles one compact bundle. Never returns raw log text.
- **Returns:** `{ context, timelines: [...], notable_errors: [...], tier0_findings: [...] }`.

---

## 8. Predicate library (versioned)

`category` enum and the starting predicates. **Verify and pin per macOS major version** — subsystem names and (especially) DDM predicates drift across releases. Treat this table as the seed of a versioned lookup, keyed by OS build.

| category | predicate (NSPredicate form) | level | confidence / notes |
|----------|------------------------------|-------|--------------------|
| `mdm_command` | `processImagePath CONTAINS "mdmclient"` OR `subsystem CONTAINS "com.apple.ManagedClient"` | info+debug | High. Catches both the daemon and the agent. |
| `enrollment` | `subsystem CONTAINS "com.apple.ManagedClient.cloudconfigurationd"` | info+debug | High. DEP/ADE enrollment + cloud config. |
| `push` | `process == "apsd"` | info | High. APNs wake/delivery. |
| `scheduling` | `process == "dasd"` | info+debug | Medium. Activity scheduling/throttling that delays commands. |
| `asset_download` | `process == "storedownloadd"` | info+debug | High. App/asset download for InstallApplication. |
| `ddm` | `processImagePath CONTAINS "mdmclient"` OR `subsystem CONTAINS "com.apple.ManagedClient"` (+ declarative-specific subsystems per OS) | info+debug | **Version-sensitive.** Sequoia changed DDM logging; derive the exact declarative subsystem set per build and pin it. |
| `pkg_install` | `process IN {"installd","installer"}` OR `subsystem == "com.apple.install"` | info+debug | High. Pair with `get_install_log`. |
| `profile_payload` | `process == "profiles"` OR `processImagePath CONTAINS "mdmclient"` (+ `subsystem CONTAINS "com.apple.ManagedClient"`) | info+debug | Medium-high. Profile/payload install + removal. |

**Cross-cutting rules**
- Always bound queries by time; an unbounded `log show` can return millions of entries.
- Always use `--style ndjson` for parsing; `--info --debug` for the detailed messages.
- Every category must resolve against both a `live` and an `--archive` source with no other code change.
- Keep the table in a versioned data file (e.g. `predicates/<os-major>.json`), not in code, so adding macOS 27 support is a data change.

---

## 9. Permissions & prerequisites

- **Root** is generally required to read full system logs at info/debug across processes on a live machine.
- **Private-data logging profile** deployed to targets (see §4.5).
- **Log retention** is short on busy machines — capture sysdiagnose at/near incident time; prefer the archive-ingesting model for after-the-fact analysis.
- macOS 10.12+ for unified logging; DDM features require recent macOS (validate per build).

---

## 10. Risks & open questions

- **Version drift** is the main maintenance cost. Mitigation: §8 versioned predicate files + a small conformance test per supported OS.
- **Correlation accuracy** is the core engineering risk; round-trips can interleave across processes and clock domains. Mitigation: anchor on command UUID where available; fall back to time+type heuristics and surface confidence.
- **Sensitivity of unmasked logs** rises once private data is enabled. Mitigation: §4.3 is mandatory and on by default.
- **Open:** which local model (if any) is good enough for Tier 1 correlation/explanation? Needs an eval.
- **Open:** exact declarative-subsystem predicate set per macOS major version — needs empirical capture on each build.
- **Open:** do we support iOS/iPadOS log capture (USB-tethered) in a later version?

---

## 11. Suggested build phases

1. **Engine + Tier 0.** Predicate resolution, ndjson parsing, normalization, redaction, `query_events`, `correlate_command`, deterministic triage. Validate on a live VM you can re-enroll from a snapshot.
2. **Archive ingestion.** `open_archive` + sysdiagnose support → fleet-realistic workflow.
3. **Remaining tools.** `get_device_context`, `get_install_log`, `get_ddm_status`, `build_incident_bundle`.
4. **Model tiers.** Wire Tier 1 (local) and Tier 2 (ZDR cloud, consent-gated) clients; run the Tier-1 model eval.
5. **Versioned predicate library + per-OS conformance tests.**

---

## 12. References

- macOS unified logging predicates for MDM (process/subsystem filters): https://micromdm.io/blog/troubleshoot-dep/
- `log show`/`log stream`, ndjson output, time-bounding: https://fullmetalmac.com/cybersecurity/logging-diagnostics/log-show-stream-commands/
- Vendor troubleshooting predicates (mdmclient, apsd, dasd): https://techzone.omnissa.com/troubleshooting-macos-management-workspace-one-operational-tutorial
- Reading DDM logging on macOS Sequoia: https://derflounder.wordpress.com/2025/08/19/reading-ddm-logging-on-macos-sequoia/
- DDM declarations are tamper-proof / status reports are JSON: https://simplemdm.pdq.com/hc/en-us/articles/19355848135707-Declarative-Device-Management-DDM
- MDM debug/private-data logging profile: https://github.com/micromdm/docs/blob/master/content/03-troubleshooting/03-known-issues.md
- `mdmclient` subcommands: https://mosen.github.io/profiledocs/troubleshooting/mdmclient.html
- Apple Private Cloud Compute security model: https://security.apple.com/blog/private-cloud-compute/
- PCC developer access limits (Small Business, <2M downloads, Apple models only): https://developer.apple.com/private-cloud-compute/
- Anthropic API data retention & ZDR: https://platform.claude.com/docs/en/manage-claude/api-and-data-retention
- ZDR scope and Files API/prompt-caching caveats: https://support.anthropic.com/en/articles/8956058-i-have-a-zero-data-retention-agreement-with-anthropic-what-products-does-it-apply-to
- Commercial terms (no training on commercial/API data): https://docs.anthropic.com/en/docs/claude-code/data-usage
