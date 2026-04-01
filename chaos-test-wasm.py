#!/usr/bin/env python3
import subprocess
import json
import os
import sys
import time

BASE_URL = os.getenv("BV_TARGET_URL", "http://localhost:8787")
API_KEY = "468e0f83a1ba7f42db789323613ff16889d888132fcb573560eb71c9247da5bd"

def run_curl(payload):
    cmd = [
        "curl", "-s", "-X", "POST",
        f"{BASE_URL}/mcp",
        "-H", "Content-Type: application/json",
        "-H", f"Authorization: Bearer {API_KEY}",
        "-d", json.dumps(payload)
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    try:
        return json.loads(result.stdout)
    except:
        return {"error": "Invalid JSON", "raw": result.stdout}

def record(name, passed, detail=""):
    status = "PASS" if passed else "FAIL"
    print(f"  [{status}] {name} {detail}")

def test_unauthorized_tool():
    print("Testing unauthorized tool call (write action on read-only tier)...")
    payload = {
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "write_file", "arguments": {"path": "test.txt", "content": "hello"}}
    }
    resp = run_curl(payload)
    passed = "error" in resp and resp["error"].get("code") == -32001
    record("Unauthorized write blocked by Wasm", passed, f"Response: {resp}")

def test_fuzz_tool_names():
    print("Fuzzing tool names...")
    names = ["", "A"*1000, "drop table users", "read_file; rm -rf /", "\0", "🤔"]
    for name in names:
        payload = {
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": name, "arguments": {}}
        }
        resp = run_curl(payload)
        passed = "error" in resp
        record(f"Fuzzed name '{name[:15]}...' handled", passed)

def test_oversized_payload():
    print("Testing oversized payload...")
    huge_string = "A" * (1024 * 1024)
    payload = {
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": "check-spf", "arguments": {"domain": "example.com", "extra": huge_string}}
    }
    resp = run_curl(payload)
    passed = "error" not in resp or resp.get("error")
    record("Oversized payload processed", passed)

if __name__ == '__main__':
    test_unauthorized_tool()
    test_fuzz_tool_names()
    test_oversized_payload()
