#!/usr/bin/env python3
"""Verify MCP over SSE: GET stream open, POST messages, read responses from the SSE stream."""
import http.client
import json
import threading
import time

HOST = "localhost"
PORT = 8099

# --- Step 1: GET /sse synchronously to grab the endpoint (sessionid) ---
c = http.client.HTTPConnection(HOST, PORT, timeout=10)
c.request("GET", "/sse")
resp = c.getresponse()
endpoint = None
while True:
    line = resp.readline()
    if not line:
        break
    text = line.decode().strip()
    if text.startswith("data:"):
        endpoint = text.split(":", 1)[1].strip()
        break
print("SSE endpoint:", endpoint)
assert endpoint, "no endpoint event"

# --- Step 2: reader thread consumes remaining SSE stream for responses ---
sse_responses = {}
sse_lock = threading.Lock()
def sse_reader():
    while True:
        line = resp.readline()
        if not line:
            break
        text = line.decode().strip()
        if text.startswith("data:"):
            try:
                msg = json.loads(text.split(":", 1)[1].strip())
                if "id" in msg:
                    with sse_lock:
                        sse_responses[msg["id"]] = msg
            except json.JSONDecodeError:
                pass
threading.Thread(target=sse_reader, daemon=True).start()

# --- Step 3: POST helper (same endpoint with sessionid) ---
def post(payload):
    pc = http.client.HTTPConnection(HOST, PORT, timeout=10)
    body = json.dumps(payload).encode()
    pc.request("POST", endpoint, body=body,
               headers={"Content-Type": "application/json",
                        "Accept": "application/json, text/event-stream"})
    r = pc.getresponse()
    status = r.status
    r.read()
    pc.close()
    return status

def wait_response(msg_id, label):
    for _ in range(30):
        with sse_lock:
            if msg_id in sse_responses:
                d = sse_responses[msg_id]
                if "result" in d:
                    print(f"  ✅ {label} OK")
                    return d["result"]
                print(f"  response: {json.dumps(d)[:300]}")
                return None
        time.sleep(0.2)
    print(f"  ⏱️ timeout waiting for {label}")
    return None

# --- Step 4: initialize ---
status = post({"jsonrpc": "2.0", "id": 1, "method": "initialize",
               "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                          "clientInfo": {"name": "sse-test", "version": "1.0"}}})
print(f"initialize POST → HTTP {status}")
res = wait_response(1, "initialize")
if res:
    srv = res.get("serverInfo", {})
    print("  server:", srv.get("name"), srv.get("version"))

# --- Step 5: tools/list ---
status = post({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
print(f"tools/list POST → HTTP {status}")
res = wait_response(2, "tools/list")
if res:
    tools = [t["name"] for t in res.get("tools", [])]
    print("  tools:", tools)

print("\n✅ MCP over SSE verified (initialize + tools/list)")
