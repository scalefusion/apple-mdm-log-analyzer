# Setup guide — MDM/DDM Log Analyzer

A step-by-step guide for **Mac admins and QA** to get the analyzer running on
their machine, wire it into an MCP-capable client, and run their first analysis
against either live logs or a bundle collected from another Mac.

> **What it is.** A local, stateless MCP server that turns macOS
> MDM / DDM / installer logs into structured, redacted event timelines. The
> server itself never diagnoses — that's the LLM client's job. The server
> **never sends anything over the network**; whether data leaves your Mac is
> decided entirely by which model your client uses (Claude in the cloud, a
> local model via Ollama, etc.).
>
> **Collection requires macOS** — capturing logs shells Apple's `log` binary.
> **Analysis** of a `collect-mdm-logs.sh` bundle or a captured `.ndjson` runs on
> any OS, so an admin on Windows or Linux can diagnose a Mac's logs. Live-log
> and `.logarchive` reading stay Mac-only.

---

## Table of contents

1. [Prerequisites](#1-prerequisites)
2. [Install Python (if you don't have 3.11+)](#2-install-python-if-you-dont-have-311)
3. [Install the MCP server](#3-install-the-mcp-server)
4. [Verify the install](#4-verify-the-install)
5. [Optional but recommended — unmask MDM detail on managed devices](#5-optional-but-recommended--unmask-mdm-detail-on-managed-devices)
6. [Use it with Claude Desktop (cloud model)](#6-use-it-with-claude-desktop-cloud-model)
7. [Use it with mcphost + Ollama (local model, zero network)](#7-use-it-with-mcphost--ollama-local-model-zero-network)
8. [Test against live logs (this Mac)](#8-test-against-live-logs-this-mac)
9. [No MCP client? Render a report instead](#8a-no-mcp-client-render-a-report-instead)
10. [Never attach the logs — give the analyzer a path](#8b-never-attach-the-logs--give-the-analyzer-a-path)
11. [Test against a collected log bundle (another Mac)](#9-test-against-a-collected-log-bundle-another-mac)
12. [Troubleshooting](#10-troubleshooting)

---

## 1. Prerequisites

- **macOS 11 (Big Sur) or later** — validated on macOS 11 / 14 / 15 / 26 / 27.
- **Python 3.11 or newer.** Check with `python3 --version`.
- **Terminal** access (Terminal.app, iTerm2, or similar).
- For the cloud-model path: **Claude Desktop** (free download from anthropic.com).
- For the local-model path: **Ollama** (`brew install ollama` or from ollama.com) — about 5 GB free disk for a small tool-use model.
- Optional for capturing logs from other Macs: `sudo` on that Mac (for `log collect`).

**Nothing else is required.** No Docker, no databases, no cloud accounts.

---

## 2. Install Python (if you don't have 3.11+)

```bash
python3 --version
```

If it says 3.11 or higher, skip to step 3.

Otherwise install via [Homebrew](https://brew.sh):

```bash
# install Homebrew if you don't have it
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# then Python
brew install python@3.12
```

After install, `python3 --version` should report 3.12+ (or whichever version you picked).

---

## 3. Install the MCP server

Three install paths. **Most testers should use Option A.**

### Option A — from a `.whl` file the maintainer handed you (recommended)

Simplest path — nothing to clone, no URLs to get wrong. The
maintainer sends you one file (e.g. `mdm_log_analyzer-0.2.0-py3-none-any.whl`);
you install it once.

```bash
python3 -m venv ~/mdm-analyzer
source ~/mdm-analyzer/bin/activate
pip install ~/Downloads/mdm_log_analyzer-0.2.0-py3-none-any.whl
```

**To update later:** the maintainer sends a new `.whl`; you activate the same
venv and repeat the `pip install` (pip will replace the old version):

```bash
source ~/mdm-analyzer/bin/activate
pip install --force-reinstall ~/Downloads/mdm_log_analyzer-0.2.1-py3-none-any.whl
```

### Option B — straight from the repository (self-service upgrades)

Use this if you want to upgrade without waiting on the maintainer to send a new
file. Public repository, so there is no token and no index URL to get wrong.

```bash
python3 -m venv ~/mdm-analyzer
source ~/mdm-analyzer/bin/activate
pip install "git+https://github.com/scalefusion/apple-mdm-log-analyzer.git"
```

To pin a released version rather than whatever `main` holds, append a tag:

```bash
pip install "git+https://github.com/scalefusion/apple-mdm-log-analyzer.git@v1.0.0"
```

**To update later** — same command with `--upgrade`, or re-run it with a newer
tag:

```bash
source ~/mdm-analyzer/bin/activate
pip install --upgrade "git+https://github.com/scalefusion/apple-mdm-log-analyzer.git"
```

> Needs `git` on the machine (it ships with the Xcode command line tools). If
> the package is later published to PyPI this becomes plain
> `pip install mdm-log-analyzer`.

### Option C — from source (contributors only)

```bash
git clone git@github.com:scalefusion/apple-mdm-log-analyzer.git
cd apple-mdm-log-analyzer
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

All three produce the **`mcp-mdm-log-analyzer`** command inside the venv you
created. That's what your MCP client will launch.

---

## 4. Verify the install

Still inside the same terminal (with the venv activated):

```bash
# 1. the entry point exists
which mcp-mdm-log-analyzer
# → /Users/you/mdm-analyzer/bin/mcp-mdm-log-analyzer

# 2. the server registers all 7 tools (no client needed)
python -c "
import asyncio
from mdm_log_analyzer.server import mcp
tools = asyncio.run(mcp.list_tools())
print(len(tools), 'tools:', sorted(t.name for t in tools))
"
# → 7 tools: ['build_incident_bundle', 'correlate_command',
#             'get_ddm_status', 'get_device_context',
#             'get_install_log', 'open_archive', 'query_events']
```

If both work, the server is installed correctly. **Note the full path from
step 1 above** — you'll paste it into the client config next.

---

## 5. Optional but recommended — unmask MDM detail on managed devices

By default macOS logs MDM command detail as `<private>`. Without unmasking:
- Command types and statuses are still readable (they're in a bracket format
  that isn't private-flagged).
- But **DDM failure detail** and some payload information is hidden.

If you have MDM control over the source Mac, deploy the **private-data logging
profile** shipped in the repo at `tools/private-data-logging.mobileconfig`.

**Install on the source Mac:**
1. Copy `private-data-logging.mobileconfig` to the source Mac.
2. Double-click it → `System Settings ▸ General ▸ Device Management` (or `Privacy & Security ▸ Profiles`) → approve.
3. Reproduce/trigger the MDM activity you want to diagnose.
4. **After collecting logs, remove the profile** (`System Settings ▸ Profiles ▸ select ▸ remove`) — it enables private-data logging system-wide, which raises log sensitivity.

You can still use the analyzer without doing this — you'll just get less
detail on DDM failures specifically.

---

## 6. Use it with Claude Desktop (cloud model)

**Privacy note:** Claude Desktop sends the redacted tool output to Anthropic
for Claude to reason over. Identifiers are hashed by the server, but if your
organization has policies about device logs leaving the device, use the local
Ollama path in step 7 instead.

1. **Generate a ready-to-paste config with your real path baked in.** With your
   venv activated, run:
   ```bash
   python -c "import shutil, json; print(json.dumps({'mcpServers': {'mdm-log-analyzer': {'command': shutil.which('mcp-mdm-log-analyzer')}}}, indent=2))"
   ```
   That prints something like:
   ```json
   {
     "mcpServers": {
       "mdm-log-analyzer": {
         "command": "/Users/admin/mdm-analyzer/bin/mcp-mdm-log-analyzer"
       }
     }
   }
   ```
   **Copy the whole output — it already has your correct path.** If the value
   ends up as `null`, your venv isn't activated; run `source ~/mdm-analyzer/bin/activate` first.
2. Paste it into Claude Desktop's config file:
   `~/Library/Application Support/Claude/claude_desktop_config.json`
   (Create the file if it doesn't exist. If you already have other `mcpServers`
   entries, merge the `mdm-log-analyzer` block into your existing `mcpServers`
   dict instead of replacing the whole file.)
3. **Fully quit** Claude Desktop (⌘Q) and reopen it.
4. Look at the tools icon near the message input — you should see
   `mdm-log-analyzer` listed with 7 tools.
5. Ask a plain-language question. Examples:
   - *"Is this Mac enrolled in MDM? Which server?"*
   - *"Any MDM command failures in the last 24 hours?"*
   - *"Show DDM declaration status."*

If the tools don't appear, check the MCP log at
`~/Library/Logs/Claude/mcp-server-mdm-log-analyzer.log` — usually it's a
wrong path in step 2.

---

## 7. Use it with mcphost + Ollama (local model, zero network)

This path keeps every byte on your Mac — nothing crosses the network at any
step. Slightly more setup than Claude Desktop, but the strongest privacy
posture.

### One-time install

```bash
# a small CLI that bridges MCP servers to local models
brew install mcphost

# Ollama itself (skip if you already have it)
brew install ollama
brew services start ollama          # or launch Ollama.app

# a tool-use-capable model (~4.7 GB — first pull takes a few minutes)
ollama pull qwen2.5:7b
```

Larger, better options if you have the disk/RAM (32 GB Mac is comfortable):
`qwen2.5:14b` (~9 GB) picks tools more reliably; `llama3.1:8b` (~4.9 GB)
handles English-only requests more consistently.

### Config

Generate the config with the correct path (same trick as step 6):

```bash
python -c "import shutil, json; print(json.dumps({'mcpServers': {'mdm-log-analyzer': {'command': shutil.which('mcp-mdm-log-analyzer')}}}, indent=2))" \
  > ~/.mcp.json
cat ~/.mcp.json
```

Verify the printed `"command"` shows your real path (not `null`). If it's
`null`, your venv isn't activated — run `source ~/mdm-analyzer/bin/activate`.

### Run

```bash
mcphost -m "ollama:qwen2.5:7b" --config ~/.mcp.json \
  -p "Is this Mac enrolled in MDM? Which server?"
```

You should see mcphost log **"Loaded 7 tools from MCP servers"**, then the
model's answer. Answers may take 30–60 seconds cold; subsequent calls are
faster.

For an interactive REPL, drop `-p "..."`:

```bash
mcphost -m "ollama:qwen2.5:7b" --config ~/.mcp.json
```

### Model choice matters

- **7B models sometimes fabricate** instead of calling the tool — phrase
  questions like an admin ("*is this Mac enrolled?*"), not like an instruction
  ("*call get_device_context and show me the result*").
- **Some models drift language** to Chinese (qwen family). Add
  `"Answer in English."` to prompts if needed.
- **14B+ picks tools more reliably** and is worth the extra download if you
  care about consistency.

---

## 8. Test against live logs (this Mac)

**Live mode** is the default when you launch the server with no env vars. It
reads this Mac's unified log via `log show`.

### Prompts that exercise different tools

Copy any of these into Claude Desktop or `mcphost -p "..."`:

```
1) "Use get_device_context to describe this Mac's MDM state — enrollment,
    server, profile counts, last check-in."

2) "Any MDM command failures on this Mac in the last 24 hours? Summarize
    what happened."

3) "Show DDM declaration status and cadence of status reports."

4) "Build an incident bundle for install_failure symptoms in the last 12
    hours and tell me the top issue."

5) "Correlate the InstallProfile command around <timestamp> and tell me
    the outcome."
```

### What to expect

- **Every identifier is redacted** — device serials, UDIDs, usernames, tokens,
  MDM server hostnames are hashed (`h:abc123…`) or scrubbed before leaving
  the server. Different sessions produce different hashes for the same real
  value; the model can correlate within a session but nothing tracks across.
- **Command detail on managed Macs may be `<private>`** without the profile
  in step 5. The analyzer will still show what it can.
- **Sudo is not required at default log level.** Full `--info`/`--debug`
  detail (helps DDM analysis specifically) needs the server to run with
  elevated privileges — usually not necessary.

---

## 8a. No MCP client? Render a report instead

If your assistant can't launch a local MCP server — ChatGPT, a browser, or
anything else — produce the report and paste it in:

```bash
mcp-mdm-log-analyzer --report --symptom install_failure --last 1h \
  --source ~/Downloads/mdm-logs-mac1.tar.gz
```

Redacted and compact (~1–2 KB for a 1-hour capture). Add `-o report.md` to write
it to a file, or `--format json` for the raw bundle. Run `--help` for all options.

---

## 8b. Never attach the logs — give the analyzer a path

The single most common mistake. Attachments and MCP tools are separate channels,
and only one goes through this server:

- **Dragging a bundle into the chat** uploads the raw bytes. The server never
  sees it, so nothing is redacted, and a 1-hour capture is ~1,000,000 tokens —
  it gets truncated, and the model answers from an arbitrary fragment.
- **`open_archive("/path")`** sends only the path. The server reads the file
  locally and returns ~135–1,800 structured, redacted tokens.

```
✅  "open_archive on ~/Downloads/mdm-logs-mac1.tar.gz, then build an incident
     bundle for install_failure over the last hour"
❌  drag mdm-logs-mac1.tar.gz into the message box
```

No need to unpack first — `open_archive` accepts `.tar.gz`, `.tgz`, `.zip`, a
`.logarchive`, an extracted bundle directory, or a captured `.ndjson`.

---

## 9. Test against a collected log bundle (another Mac)

The common real workflow: a user on another Mac has an MDM issue, they run
one command, hand you a tarball or `.logarchive`, and you analyze on **your**
machine.

### Ask the source Mac's admin to collect logs

Three formats, pick one (in order of preference):

**Best — Apple-native `.logarchive`** (one command every Mac admin trusts):

```bash
sudo log collect --last 3h --output ~/Desktop/device.logarchive
# optionally also for get_install_log:
sudo cp /var/log/install.log ~/Desktop/
sw_vers > ~/Desktop/os.txt
```

Zip it and send.

**Alternative — a full sysdiagnose** (contains everything, larger):

```bash
sudo sysdiagnose -f ~/Desktop     # or press ⌃⌥⇧⌘.
```

Extract the `.logarchive` from inside the tarball and use it as above.

**Or use our targeted collection script** (smaller bundles, pre-filtered):

```bash
# script is at tools/collect-mdm-logs.sh in the repo (or ship it separately)
./collect-mdm-logs.sh 3h
# → mdm-logs-<host>.tar.gz — analyzer opens this directly
```

### Point the analyzer at the bundle

Two ways — either edit the client config to preselect the archive, or
open it at runtime via the `open_archive` tool.

**Config-based (simpler for one-off analysis):** add an `env` block with the
absolute path to the archive. Take the config you generated in step 6, and
add the `env` alongside `command`:

```json
{
  "mcpServers": {
    "mdm-log-analyzer": {
      "command": "<the path from step 6 — DO NOT paste /Users/YOU>",
      "env": {
        "MDM_LOG_ARCHIVE": "/absolute/path/to/device.logarchive"
      }
    }
  }
}
```

Restart the client. Every query now runs against that archive instead of live.
Change or remove the `env` block to switch archives / go back to live.

**Runtime `open_archive` (better when jumping between archives):**

Leave the config in default (live) mode. Then in chat:

```
"Open the archive at ~/Downloads/device.logarchive, then build an incident
 bundle for install_failure over its whole time window."
```

The model calls `open_archive` first, gets back an `archive_id`, and passes
that as the `source` argument to the other tools automatically.

Supported at `open_archive`:
- `*.logarchive` (from `log collect` or extracted from sysdiagnose)
- `*.ndjson` — a captured NDJSON export
- `*.tar.gz` from our `collect-mdm-logs.sh`
- **Not yet:** a raw sysdiagnose tarball. Extract the `.logarchive` out of
  it first.

---

## 10. Troubleshooting

### `pip install mdm-log-analyzer` says "No matching distribution found"

Two likely causes, both about **Python versions on stock macOS**:

1. **Your Python is older than 3.11.** macOS ships `python3` at 3.9 by default,
   and old pip (~21.x) misreports the version mismatch as
   *"No matching distribution found"* instead of a clear error. Check with
   `python --version` inside your activated venv.
2. **You created the venv with the wrong Python binary.** Even after you
   install Python 3.12+ (via Homebrew or the [python.org installer](https://www.python.org/downloads/)),
   `python3` on PATH may still point at the stock 3.9. **A venv is locked to
   whatever Python created it — you can't upgrade it in-place.** Delete it and
   recreate with the specific new binary:
   ```bash
   deactivate
   rm -rf ~/mdm-analyzer

   # find where the new Python actually lives
   ls /Library/Frameworks/Python.framework/Versions/       # python.org installer
   #   → e.g. "3.12   Current"
   # or:
   ls /opt/homebrew/bin/python3.*                          # Homebrew

   # recreate the venv with that specific binary
   /Library/Frameworks/Python.framework/Versions/3.12/bin/python3.12 \
     -m venv ~/mdm-analyzer
   source ~/mdm-analyzer/bin/activate
   python --version                     # should now say 3.12.x
   pip install --upgrade pip
   # retry the pip install from step 3.
   ```

Also note: **stock macOS has `python3` but not bare `python`.** Inside an
activated venv, `python` becomes an alias for the venv's binary. Outside,
always use `python3`.

### `ModuleNotFoundError: No module named 'mcp.server.fastmcp'` (or `...mcpserver`)

Your analyzer version and your `mcp` SDK version disagree. The SDK renamed its
server class in 2.0 (`fastmcp.FastMCP` → `mcpserver.MCPServer`), and the
analyzer follows the SDK, so the two must be on the same side of that line:

| Analyzer | Needs | Missing-module error you'd see |
|----------|-------|--------------------------------|
| 0.2.0 and later | `mcp` 2.x | `No module named 'mcp.server.mcpserver'` — SDK too old |
| 0.1.x and earlier | `mcp` 1.x | `No module named 'mcp.server.fastmcp'` — SDK too new |

Check both versions:

```bash
python -c "import importlib.metadata as m; print('analyzer', m.version('mdm-log-analyzer'), '| mcp', m.version('mcp'))"
```

**The fix is almost always to upgrade the analyzer**, since 0.1.1 and later
declare a bounded SDK range and pip resolves a working combination by itself:

```bash
pip install --upgrade mdm-log-analyzer
```

Only if you are pinned to an old analyzer on purpose should you move the SDK
instead — `pip install 'mcp<2'` for 0.1.x, `pip install 'mcp>=2,<3'` for 0.2.0+.

(Analyzer 0.1.0 shipped with no upper bound at all, which is how a fresh install
could pull an incompatible 2.x SDK and fail at import. Later versions can't.)

A `pydantic_settings` `IncompleteFieldDefinitionWarning` on startup is
unrelated and harmless — it comes from a transitive dependency, goes to stderr,
and does not affect the server.

### The tools don't appear in Claude Desktop

- Check the MCP log:
  `tail ~/Library/Logs/Claude/mcp-server-mdm-log-analyzer.log`
- Common causes: the `command` path in `claude_desktop_config.json` doesn't
  exist, or points at the wrong venv. Run
  `which mcp-mdm-log-analyzer` (with the venv activated) and copy that exact
  path.

### `mcphost` says "connect: connection refused"

Ollama isn't running. Start it:

```bash
brew services start ollama
# or open /Applications/Ollama.app
# quick check:
curl -s http://localhost:11434/api/tags
```

### The model answers with fabricated data

Small local models (7B and below) occasionally hallucinate tool calls
instead of actually invoking them. Two fixes:

- Phrase the question as an admin question, not a tool instruction:
  ✅ *"Is this Mac enrolled?"* — will call the tool
  ❌ *"Call `get_device_context` and show the result"* — often triggers roleplay
- Use a bigger model: `ollama pull qwen2.5:14b` (~9 GB).

### Every event message is `<private>`

The MDM private-data logging profile isn't installed on the source Mac.
See step 5. Without it you'll still get command types and outcomes (they're
not private-flagged), but not payloads or some DDM failure detail.

### `log show` returns nothing on macOS 27 at default level

macOS 27 tightened default-level logging. Pass `--info --debug` and, if you
still need more, capture with sudo and analyze the *bundle* rather than running
the server itself as root:

```bash
sudo ./tools/collect-mdm-logs.sh 20m        # sudo here, for the capture only
```

Then point the server at the resulting `.tar.gz`. The server stays unprivileged.

> ⚠️ **Do not run the MCP server as root.** It reads a path chosen by a *model*,
> from arguments the model derived from untrusted log text, so a crafted log line
> that suggests a path becomes an arbitrary file read — as root, that is the whole
> disk. A `.json`/`.ndjson` must now look like `log show` output before it is
> read, which blocks the obvious version of this, but the capture-then-analyze
> split removes the privilege from the equation entirely. Earlier revisions of
> this guide recommended `sudo "$(which mcp-mdm-log-analyzer)"`; they should not
> have.

### Where do I look for what the tools actually returned?

`query_events` and `build_incident_bundle` return structured JSON. In Claude
Desktop, expand the tool-use card in the chat to see the raw (already-redacted)
output the model saw. In `mcphost`, add `--debug` for verbose logging.

---

## Related docs

- **[README.md](./README.md)** — quick overview + one-off install snippets.
- **[ARCHITECTURE.md](./ARCHITECTURE.md)** — module-by-module component reference.
- **[mdm-log-analyzer-mcp-spec.md](./mdm-log-analyzer-mcp-spec.md)** — the formal specification.
