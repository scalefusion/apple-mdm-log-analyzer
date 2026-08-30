"""End-to-end smoke test for the MCP server surface (spec §7).

Why this exists: the engine suite in test_engine.py is deliberately zero-dep and
never imports server.py, so nothing exercised the MCP layer. When the mcp SDK's
2.0 major removed `mcp.server.fastmcp`, the resulting ImportError was found by a
tester on their Mac rather than by CI. This test drives the real server the way
a real client does — spawn it, speak JSON-RPC over stdio, call a tool — so an
SDK break fails the build instead of a person.

It is a separate file because it needs `mcp` installed. When the SDK is absent
it SKIPS rather than fails, keeping `python3 tests/test_engine.py` usable with
no dependencies at all.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "mdm_sample.ndjson"

PROTOCOL_VERSION = "2025-06-18"
TIMEOUT_S = 60


def _mcp_installed() -> bool:
    """True if the SDK is present at all.

    Deliberately probes the top-level `mcp` package, NOT `mcp.server.fastmcp`.
    Testing for the submodule server.py imports would make this test SKIP on
    exactly the SDK version that breaks the server — turning the regression it
    exists to catch into a silent pass.
    """
    try:
        import mcp  # noqa: F401
    except ImportError:
        return False
    return True


def _rpc(*messages: dict) -> dict[int, dict]:
    """Run the server, send `messages` in order, return responses keyed by id.

    stdin is held open and each response read before the next request goes out,
    which is how a real MCP client behaves. Writing everything up front and
    closing stdin instead races the server's EOF shutdown against its last
    reply, and the final response is silently lost.

    A watchdog kills the process so an unresponsive server fails the test rather
    than hanging CI. stderr goes to a file, not a pipe, so SDK warnings can
    never fill a pipe buffer and deadlock the child.
    """
    env = {
        **os.environ,
        "MDM_LOG_FIXTURE": str(FIXTURE),
        "MDM_LOG_OS_MAJOR": "15",
        "PYTHONPATH": str(ROOT / "src"),
    }
    responses: dict[int, dict] = {}
    with tempfile.TemporaryFile(mode="w+") as errfile:
        proc = subprocess.Popen(
            [sys.executable, "-m", "mdm_log_analyzer.server"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=errfile,
            text=True,
            bufsize=1,
            env=env,
        )
        watchdog = threading.Timer(TIMEOUT_S, proc.kill)
        watchdog.start()

        def _stderr_tail() -> str:
            errfile.seek(0)
            return errfile.read()[-2000:]

        try:
            for message in messages:
                proc.stdin.write(json.dumps(message) + "\n")
                proc.stdin.flush()
                if "id" not in message:
                    continue  # notification: no reply expected
                while True:
                    line = proc.stdout.readline()
                    if not line:
                        raise AssertionError(
                            f"server closed stdout waiting for id {message['id']}.\n"
                            f"stderr:\n{_stderr_tail()}"
                        )
                    line = line.strip()
                    if not line.startswith("{"):
                        continue
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(obj, dict) and "id" in obj:
                        responses[obj["id"]] = obj
                        if obj["id"] == message["id"]:
                            break
        finally:
            watchdog.cancel()
            try:
                proc.stdin.close()
            except OSError:
                pass
            proc.terminate()
            proc.wait(timeout=10)
    return responses


def _tool_payload(result: dict) -> dict:
    """Tool results arrive as structured content, or as JSON in a text block."""
    if "structuredContent" in result:
        return result["structuredContent"]
    return json.loads(result["content"][0]["text"])


def test_server_initializes_lists_and_calls_tools():
    if not _mcp_installed():
        print("SKIP test_server_initializes_lists_and_calls_tools (mcp not installed)")
        return

    responses = _rpc(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "smoke-test", "version": "0"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "query_events",
                "arguments": {"category": "mdm_command", "last": "1h"},
            },
        },
    )

    # 1. Handshake.
    init = responses[1]["result"]
    assert init["serverInfo"]["name"] == "mdm-log-analyzer", init["serverInfo"]

    # 2. Every tool in the spec is advertised.
    names = {t["name"] for t in responses[2]["result"]["tools"]}
    assert names == {
        "query_events",
        "correlate_command",
        "get_install_log",
        "get_ddm_status",
        "get_device_context",
        "build_incident_bundle",
        "open_archive",
    }, sorted(names)

    # 3. A tool actually runs and returns normalized events, not raw log text.
    payload = _tool_payload(responses[3]["result"])
    assert payload["count"] > 0, payload
    assert payload["events"][0]["command_type"] == "InstallApplication", payload["events"][0]
    assert "eventMessage" not in payload["events"][0], "raw log field leaked into a tool result"


def test_server_reports_bad_input_as_structured_error():
    # Bad input must come back as a normal result the model can read, not as a
    # transport-level crash.
    if not _mcp_installed():
        print("SKIP test_server_reports_bad_input_as_structured_error (mcp not installed)")
        return

    responses = _rpc(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "smoke-test", "version": "0"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "query_events",
                "arguments": {"category": "not_a_real_category"},
            },
        },
    )
    payload = _tool_payload(responses[2]["result"])
    assert "error" in payload, payload
    assert "not_a_real_category" in payload["error"], payload


def main() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for fn in tests:
        try:
            fn()
        except Exception as e:  # noqa: BLE001 - test runner reports everything
            failed += 1
            print(f"FAIL {fn.__name__}: {type(e).__name__}: {e}")
        else:
            print(f"PASS {fn.__name__}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
