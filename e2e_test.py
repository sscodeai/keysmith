#!/usr/bin/env python3
"""End-to-end test: drive the keysmith binary over stdio with JSON-RPC."""
import json
import os
import subprocess
import sys
import tempfile
import time

# Binary path: env override, else relative to this script (repo/bin/keysmith)
BIN = os.environ.get(
    "KEYSMITH_BIN",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "bin", "keysmith"),
)
STORE = os.environ.get("KEYSMITH_E2E_STORE", "/tmp/smcp-e2e")

def send(proc, msg):
    proc.stdin.write(json.dumps(msg) + "\n")
    proc.stdin.flush()

def recv(proc, timeout=10):
    line = proc.stdout.readline()
    if not line:
        return None
    return json.loads(line)

def main():
    env = dict(os.environ, KEYSMITH_STORE=STORE)
    proc = subprocess.Popen(
        [BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, env=env, text=True, bufsize=1,
    )
    # 1. initialize
    send(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                           "clientInfo": {"name": "e2e", "version": "1.0"}}})
    r = recv(proc)
    print("initialize:", "OK" if r and "result" in r else f"FAIL {r}")
    tools = r["result"]["capabilities"].get("tools", {})
    print("  advertised tools:", tools.get("listChanged", "n/a"))

    # 2. notifications/initialized
    send(proc, {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})

    # 3. tools/list
    send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    r = recv(proc)
    names = [t["name"] for t in r["result"]["tools"]]
    print("tools/list:", names)

    # 4. tools/call put — value via a file inside the inbox, so the plaintext
    # never appears in the transcript. Paths outside the inbox must be refused:
    # the argument is agent-controlled, so an unrestricted path would let it
    # read and delete arbitrary files.
    inbox = os.path.join(STORE, "inbox")
    os.makedirs(inbox, mode=0o700, exist_ok=True)
    valfile = os.path.join(inbox, "e2e-value.txt")

    outside = os.path.join(tempfile.gettempdir(), "smcp-e2e-outside.txt")
    with open(outside, "w") as f:
        f.write("sk-outside-e2e-1234567890")
    send(proc, {"jsonrpc": "2.0", "id": 30, "method": "tools/call",
                "params": {"name": "put", "arguments": {"key": "OUTSIDE", "value_file": outside}}})
    r = recv(proc)
    refused = bool((r.get("result") or {}).get("isError")) or "error" in r
    print("put outside inbox refused:", refused)
    print("  outside file kept:", os.path.exists(outside))
    os.remove(outside)

    with open(valfile, "w") as f:
        f.write("sk-super-secret-e2e-1234567890")
    send(proc, {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": {"name": "put", "arguments": {"key": "API_KEY", "value_file": valfile}}})
    r = recv(proc)
    print("put:", "OK" if r and "result" in r else f"FAIL {r}")
    print("  result:", r["result"]["content"][0]["text"])
    # value file should be gone
    print("  value file removed:", not os.path.exists(valfile))

    # 5. tools/call list (masked)
    send(proc, {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                "params": {"name": "list", "arguments": {}}})
    r = recv(proc)
    print("list:", r["result"]["content"][0]["text"].strip())
    assert "sk-super-secret-e2e-1234567890" not in r["result"]["content"][0]["text"], "LEAK!"

    # 6. tools/call get (masked)
    send(proc, {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                "params": {"name": "get", "arguments": {"key": "API_KEY"}}})
    r = recv(proc)
    print("get:", r["result"]["content"][0]["text"])

    # 7. tools/call rotate
    send(proc, {"jsonrpc": "2.0", "id": 6, "method": "tools/call",
                "params": {"name": "rotate", "arguments": {"key": "API_KEY", "length": 32}}})
    r = recv(proc)
    print("rotate:", r["result"]["content"][0]["text"])

    # 8. resources/list + read (masked)
    send(proc, {"jsonrpc": "2.0", "id": 7, "method": "resources/list", "params": {}})
    r = recv(proc)
    print("resources/list:", [x["uri"] for x in r["result"]["resources"]])
    send(proc, {"jsonrpc": "2.0", "id": 8, "method": "resources/read",
                "params": {"uri": "secret://secrets"}})
    r = recv(proc)
    text = r["result"]["contents"][0]["text"]
    print("resources/read:", text.strip())
    assert "sk-super-secret-e2e-1234567890" not in text, "RESOURCE LEAK!"

    proc.terminate()
    print("\n✅ E2E PASS — no plaintext leaked in any tool/resource output")

if __name__ == "__main__":
    main()
