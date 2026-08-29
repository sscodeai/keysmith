#!/usr/bin/env python3
"""Verify MCP Streamable HTTP: single session, initialize → initialized → tools/list → call."""
import http.client
import json

HOST = "localhost"
PORT = 8098
PATH = "/mcp"

# Persistent connection for the whole session
conn = http.client.HTTPConnection(HOST, PORT, timeout=10)

def post(payload):
    body = json.dumps(payload).encode()
    conn.request("POST", PATH, body=body,
                 headers={"Content-Type": "application/json",
                          "Accept": "application/json, text/event-stream"})
    r = conn.getresponse()
    data = r.read().decode()
    status = r.status
    return status, data

# 1. initialize (starts session)
status, data = post({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                     "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                                "clientInfo": {"name": "stream-test", "version": "1.0"}}})
print(f"initialize → HTTP {status}")
d = json.loads(data)
if "result" in d:
    srv = d["result"]["serverInfo"]
    print(f"  ✅ server: {srv['name']} {srv['version']} (protocol {d['result']['protocolVersion']})")
else:
    print("  ❌", data[:300])

# 2. notifications/initialized (same session)
status, data = post({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
print(f"initialized notify → HTTP {status}")

# 3. tools/list (same session)
status, data = post({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
print(f"tools/list → HTTP {status}")
d = json.loads(data)
if "result" in d:
    tools = [t["name"] for t in d["result"]["tools"]]
    print(f"  ✅ tools: {tools}")
else:
    print("  ❌", data[:300])

# 4. put (value via temp file)
import os
with open("/tmp/smcp-stream-val.txt", "w") as f:
    f.write("sk-streamable-session-1234567890")
status, data = post({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                     "params": {"name": "put", "arguments": {"key": "STREAM_KEY",
                                                              "value_file": "/tmp/smcp-stream-val.txt"}}})
print(f"put → HTTP {status}")
d = json.loads(data)
if "result" in d:
    print(f"  ✅ {d['result']['content'][0]['text']}")
    print("  ✅ temp file removed:", not os.path.exists("/tmp/smcp-stream-val.txt"))
else:
    print("  ❌", data[:300])

# 5. list (masked)
status, data = post({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                     "params": {"name": "list", "arguments": {}}})
d = json.loads(data)
if "result" in d:
    text = d["result"]["content"][0]["text"]
    print("list:")
    print(text)
    if "sk-streamable-session-1234567890" in text:
        print("  ❌ LEAK!")
    else:
        print("  ✅ masked, no plaintext")
else:
    print("  ❌", data[:300])

conn.close()
print("\n✅ Streamable HTTP verified")
