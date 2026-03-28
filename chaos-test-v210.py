#!/usr/bin/env python3
"""
Chaos test for bv-mcp v2.0.10 production.
Tests edge cases across all transports, protocol compliance, and adversarial inputs.

Covers:
  1.  Streamable HTTP full lifecycle
  2.  Legacy SSE transport
  3.  GET /mcp SSE notification stream
  4.  Endpoint routing & method guards
  5.  Valid domain edge cases
  6.  Blocked domains (SSRF)
  7.  Argument edge cases
  8.  Content-Type validation
  9.  No-send domain DKIM scoring
  10. Rate limit envelope & quota headers
  11. Batch JSON-RPC (new)
  12. Body size limits (new)
  13. Session lifecycle abuse (new)
  14. JSON-RPC protocol edge cases (new)
  15. Origin validation (new)
  16. resources/read edge cases (new)
  17. prompts/get edge cases (new)
  18. Concurrent tool execution (new)
  19. Format parameter validation (new)
"""

import subprocess
import json
import sys
import re
import os
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE = "https://dns-mcp.blackveilsecurity.com"
_RAW_API_KEY = os.getenv("BV_API_KEY")
API_KEY = None  # Set after validation


def _validate_api_key():
    """Quick check: does the API key actually work?"""
    global API_KEY
    if not _RAW_API_KEY:
        return
    cmd = ["curl", "-s", "-w", "\n%{http_code}", "-X", "POST",
           f"{BASE}/mcp",
           "-H", "Content-Type: application/json",
           "-H", f"Authorization: Bearer {_RAW_API_KEY}",
           "-d", json.dumps({"jsonrpc": "2.0", "method": "ping", "id": 1})]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        lines = r.stdout.strip().split("\n")
        status = int(lines[-1])
        if status != 401:
            API_KEY = _RAW_API_KEY
    except Exception:
        pass

results = []


def record(name, passed, detail=""):
    status = "PASS" if passed else "FAIL"
    results.append((name, passed))
    msg = f"  [{status}] {name}"
    if detail and not passed:
        msg += f"  -- {detail}"
    print(msg)


def curl_json(method, path, body=None, headers=None, extra_args=None, include_headers=False):
    """Run curl and return (status_code, response_body, raw_output)."""
    cmd = ["curl", "-s", "-w", "\n%{http_code}"]
    if include_headers:
        cmd.append("-D-")
    if method != "GET":
        cmd += ["-X", method]

    if headers:
        for h in headers:
            cmd += ["-H", h]

    if body is not None:
        if isinstance(body, (dict, list)):
            cmd += ["-d", json.dumps(body)]
        else:
            cmd += ["-d", body]

    if extra_args:
        cmd += extra_args

    cmd.append(f"{BASE}{path}")

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        output = r.stdout.strip()
        lines = output.split("\n")
        status_code = int(lines[-1])
        body_text = "\n".join(lines[:-1])
        return status_code, body_text, r.stdout
    except subprocess.TimeoutExpired:
        return 0, "TIMEOUT", ""
    except Exception as e:
        return 0, str(e), ""


def curl_with_response_headers(method, path, body=None, headers=None):
    """Run curl and return (status_code, body, response_headers_dict)."""
    header_file = tempfile.mktemp(suffix=".headers")
    cmd = ["curl", "-s", "-D", header_file, "-w", "\n__STATUS__%{http_code}"]
    if method != "GET":
        cmd += ["-X", method]
    if headers:
        for h in headers:
            cmd += ["-H", h]
    if body is not None:
        if isinstance(body, (dict, list)):
            cmd += ["-d", json.dumps(body)]
        else:
            cmd += ["-d", body]
    cmd.append(f"{BASE}{path}")

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        output = r.stdout
        status_match = re.search(r"__STATUS__(\d+)", output)
        status_code = int(status_match.group(1)) if status_match else 0
        body_text = re.sub(r"\n?__STATUS__\d+\s*$", "", output).strip()

        resp_headers = {}
        try:
            with open(header_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if ":" in line and not line.startswith("HTTP/"):
                        k, v = line.split(":", 1)
                        resp_headers[k.strip().lower()] = v.strip()
        except FileNotFoundError:
            pass
        finally:
            try:
                os.unlink(header_file)
            except OSError:
                pass

        return status_code, body_text, resp_headers
    except subprocess.TimeoutExpired:
        try:
            os.unlink(header_file)
        except OSError:
            pass
        return 0, "TIMEOUT", {}
    except Exception as e:
        try:
            os.unlink(header_file)
        except OSError:
            pass
        return 0, str(e), {}


def mcp_headers(session_id=None, content_type="application/json", auth=False):
    """Build MCP request headers. Auth is off by default (free tier)."""
    h = []
    if auth and API_KEY:
        h.append(f"Authorization: Bearer {API_KEY}")
    if content_type:
        h.append(f"Content-Type: {content_type}")
    if session_id:
        h.append(f"Mcp-Session-Id: {session_id}")
    return h


def jsonrpc(method, params=None, req_id=1):
    body = {"jsonrpc": "2.0", "method": method, "id": req_id}
    if params is not None:
        body["params"] = params
    return body


def create_session(client_name="chaos-test"):
    """Helper: create a session and return session_id or None."""
    status, body, raw = curl_json(
        "POST", "/mcp",
        body=jsonrpc("initialize", {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": client_name, "version": "2.0.10"}
        }),
        headers=mcp_headers(),
        include_headers=True,
    )
    session_id = None
    for line in raw.split("\n"):
        if line.lower().startswith("mcp-session-id:"):
            session_id = line.split(":", 1)[1].strip()
            break

    if session_id:
        # Send required initialized notification
        curl_json("POST", "/mcp",
                  body={"jsonrpc": "2.0", "method": "notifications/initialized"},
                  headers=mcp_headers(session_id))
    return session_id


def delete_session(session_id):
    """Helper: clean up a session."""
    if session_id:
        curl_json("DELETE", "/mcp", headers=mcp_headers(session_id))


# ──────────────────────────────────────────────────────────────────────
# 1. Streamable HTTP full lifecycle
# ──────────────────────────────────────────────────────────────────────
def test_streamable_http():
    print("\n=== 1. Streamable HTTP Full Lifecycle ===")

    # Initialize
    status, body, raw = curl_json(
        "POST", "/mcp",
        body=jsonrpc("initialize", {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "chaos-test-v210", "version": "2.0.10"}
        }),
        headers=mcp_headers(),
        include_headers=True,
    )
    record("1a. Initialize → 200", status == 200, f"got {status}")

    session_id = None
    for line in raw.split("\n"):
        if line.lower().startswith("mcp-session-id:"):
            session_id = line.split(":", 1)[1].strip()
            break
    record("1b. Session ID returned", session_id is not None, f"sid={session_id}")

    if not session_id:
        print("  SKIP remaining lifecycle tests (no session)")
        return None

    # Validate session ID format: 64 lowercase hex chars
    is_valid_format = bool(re.match(r'^[0-9a-f]{64}$', session_id))
    record("1c. Session ID is 64 hex chars", is_valid_format, f"len={len(session_id)}")

    # Verify initialize response contains server capabilities
    # When include_headers=True, body includes HTTP headers; extract JSON part
    try:
        json_start = body.find("{")
        json_body = body[json_start:] if json_start >= 0 else body
        data = json.loads(json_body)
        has_server_info = "serverInfo" in data.get("result", {})
        has_capabilities = "capabilities" in data.get("result", {})
        record("1d. Initialize has serverInfo + capabilities",
               has_server_info and has_capabilities,
               f"serverInfo={has_server_info}, capabilities={has_capabilities}")
    except Exception as e:
        record("1d. Initialize has serverInfo + capabilities", False, str(e))

    # Initialized notification
    curl_json("POST", "/mcp",
              body={"jsonrpc": "2.0", "method": "notifications/initialized"},
              headers=mcp_headers(session_id))

    # tools/list
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=jsonrpc("tools/list", {}, 2),
        headers=mcp_headers(session_id),
    )
    record("1e. tools/list → 200", status == 200, f"got {status}")
    try:
        data = json.loads(body)
        tool_count = len(data.get("result", {}).get("tools", []))
        record("1f. 33 tools returned", tool_count == 33, f"got {tool_count}")
    except Exception as e:
        record("1f. 33 tools returned", False, str(e))

    # resources/list
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=jsonrpc("resources/list", {}, 3),
        headers=mcp_headers(session_id),
    )
    try:
        data = json.loads(body)
        res_count = len(data.get("result", {}).get("resources", []))
        record("1g. resources/list → 6 resources", res_count == 6, f"got {res_count}")
    except Exception as e:
        record("1g. resources/list → 6 resources", False, str(e))

    # prompts/list
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=jsonrpc("prompts/list", {}, 4),
        headers=mcp_headers(session_id),
    )
    try:
        data = json.loads(body)
        prompt_count = len(data.get("result", {}).get("prompts", []))
        record("1h. prompts/list → 7 prompts", prompt_count == 7, f"got {prompt_count}")
    except Exception as e:
        record("1h. prompts/list → 7 prompts", False, str(e))

    # ping
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=jsonrpc("ping", {}, 5),
        headers=mcp_headers(session_id),
    )
    record("1i. ping → 200", status == 200, f"got {status}")
    try:
        data = json.loads(body)
        record("1j. ping result is empty object", data.get("result") == {}, f"got {data.get('result')}")
    except Exception as e:
        record("1j. ping result is empty object", False, str(e))

    # tools/call check_spf
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=jsonrpc("tools/call", {
            "name": "check_spf",
            "arguments": {"domain": "google.com"}
        }, 6),
        headers=mcp_headers(session_id),
    )
    record("1k. tools/call check_spf → 200", status == 200, f"got {status}")
    try:
        data = json.loads(body)
        content = data.get("result", {}).get("content", [])
        has_text = any(c.get("type") == "text" for c in content)
        record("1l. check_spf has text content", has_text,
               f"content={str(content)[:100] if content else 'empty'}")
    except Exception as e:
        record("1l. check_spf has text content", False, str(e))

    # DELETE session
    status, body, _ = curl_json("DELETE", "/mcp", headers=mcp_headers(session_id))
    record("1m. DELETE session → 204", status == 204, f"got {status}")

    # ping with deleted session → 404
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=jsonrpc("ping", {}, 7),
        headers=mcp_headers(session_id),
    )
    record("1n. ping deleted session → 404", status == 404, f"got {status}")

    return session_id


# ──────────────────────────────────────────────────────────────────────
# 2. Legacy SSE
# ──────────────────────────────────────────────────────────────────────
def test_legacy_sse():
    print("\n=== 2. Legacy SSE Transport ===")

    # Legacy SSE endpoint requires authentication
    if not API_KEY:
        print("  SKIP: legacy SSE requires BV_API_KEY")
        record("2a. GET /mcp/sse → SSE stream (skipped, no key)", True, "no API key")
        record("2b. GET /mcp/sse no Accept (skipped, no key)", True, "no API key")
    else:
        # GET /mcp/sse with Accept: text/event-stream
        cmd = [
            "perl", "-e", "alarm 4; exec @ARGV", "--",
            "curl", "-s", "-N",
            f"{BASE}/mcp/sse",
            "-H", "Accept: text/event-stream",
            "-H", f"Authorization: Bearer {API_KEY}",
        ]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            output = r.stdout
            has_event = "event:" in output or "data:" in output
            has_endpoint = "/mcp/messages?sessionId=" in output
            record("2a. GET /mcp/sse → SSE stream with endpoint", has_event and has_endpoint,
                   f"has_event={has_event}, has_endpoint={has_endpoint}, out={output[:200]}")
        except subprocess.TimeoutExpired:
            record("2a. GET /mcp/sse → SSE stream with endpoint", False, "timeout")
        except Exception as e:
            record("2a. GET /mcp/sse → SSE stream with endpoint", False, str(e))

        # GET /mcp/sse without Accept → 406
        status, body, _ = curl_json("GET", "/mcp/sse",
                                    headers=[f"Authorization: Bearer {API_KEY}"])
        record("2b. GET /mcp/sse no Accept → 406", status == 406, f"got {status}")

    # POST /mcp/messages without sessionId → 400
    status, body, _ = curl_json(
        "POST", "/mcp/messages",
        body=jsonrpc("ping", {}, 1),
        headers=mcp_headers(),
    )
    record("2c. POST /mcp/messages no sessionId → 400", status == 400, f"got {status}")

    # POST /mcp/messages with invalid sessionId → 404
    status, body, _ = curl_json(
        "POST", "/mcp/messages?sessionId=bogus-session-12345",
        body=jsonrpc("ping", {}, 1),
        headers=mcp_headers(),
    )
    record("2d. POST /mcp/messages invalid session → 404", status == 404, f"got {status}")


# ──────────────────────────────────────────────────────────────────────
# 3. GET /mcp SSE notification stream
# ──────────────────────────────────────────────────────────────────────
def test_notification_stream():
    print("\n=== 3. GET /mcp SSE Notification Stream ===")

    session_id = create_session("chaos-sse-test")
    if not session_id:
        record("3a. Create session for SSE stream", False, "no session")
        return

    record("3a. Create session for SSE stream", True)

    # GET /mcp with Accept: text/event-stream + session
    cmd = [
        "perl", "-e", "alarm 4; exec @ARGV", "--",
        "curl", "-s", "-N", "-o", "/dev/null", "-w", "%{http_code}",
        f"{BASE}/mcp",
        "-H", "Accept: text/event-stream",
        "-H", f"Mcp-Session-Id: {session_id}",
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        output = r.stdout.strip()
        stream_opened = r.returncode != 0 or output == "200"
        record("3b. GET /mcp SSE stream opens", stream_opened,
               f"returncode={r.returncode}, output={output}")
    except subprocess.TimeoutExpired:
        record("3b. GET /mcp SSE stream opens", True, "timed out (stream stayed open)")

    # GET /mcp without Accept header → 406
    status, body, _ = curl_json(
        "GET", "/mcp",
        headers=[f"Mcp-Session-Id: {session_id}"],
    )
    record("3c. GET /mcp no Accept → 406", status == 406, f"got {status}")

    # GET /mcp without session → 400
    status, body, _ = curl_json(
        "GET", "/mcp",
        headers=["Accept: text/event-stream"],
    )
    record("3d. GET /mcp no session → 400", status == 400, f"got {status}")

    delete_session(session_id)


# ──────────────────────────────────────────────────────────────────────
# 4. Endpoint routing & method guards
# ──────────────────────────────────────────────────────────────────────
def test_endpoints():
    print("\n=== 4. Endpoint Tests ===")

    # GET /health
    status, body, _ = curl_json("GET", "/health")
    record("4a. GET /health → 200", status == 200, f"got {status}")
    try:
        data = json.loads(body)
        record("4b. /health returns JSON with status", "status" in data, f"keys={list(data.keys())}")
        # Verify version matches
        has_service = "service" in data
        record("4c. /health has service field", has_service, f"got {data.get('service')}")
    except Exception as e:
        record("4b. /health returns JSON with status", False, str(e))

    # GET /badge/google.com
    status, body, _ = curl_json("GET", "/badge/google.com")
    is_ok = status == 200 or status == 429
    record("4d. GET /badge/google.com → 200 or 429", is_ok, f"got {status}")
    if status == 200:
        record("4e. Badge is SVG", "<svg" in body.lower(), f"body[:100]={body[:100]}")
    else:
        record("4e. Badge is SVG (skipped, rate limited)", True, "429")

    # Internal routes blocked publicly
    status, body, _ = curl_json(
        "POST", "/internal/tools/call",
        body={"name": "check_spf", "arguments": {"domain": "google.com"}},
        headers=["Content-Type: application/json"],
    )
    record("4f. POST /internal/tools/call → 404", status == 404, f"got {status}")

    status, body, _ = curl_json(
        "POST", "/internal/tools/batch",
        body={"domains": ["google.com"], "tool": "check_spf"},
        headers=["Content-Type: application/json"],
    )
    record("4g. POST /internal/tools/batch → 404", status == 404, f"got {status}")

    # Nonexistent route
    status, body, _ = curl_json("GET", "/nonexistent")
    record("4h. GET /nonexistent → 404", status == 404, f"got {status}")

    # Disallowed methods on /mcp
    status, body, _ = curl_json("PUT", "/mcp", headers=mcp_headers())
    record("4i. PUT /mcp → 404 or 405", status in (404, 405), f"got {status}")

    status, body, _ = curl_json("PATCH", "/mcp", headers=mcp_headers())
    record("4j. PATCH /mcp → 404 or 405", status in (404, 405), f"got {status}")

    # OPTIONS /mcp → 204
    status, body, _ = curl_json("OPTIONS", "/mcp", headers=mcp_headers())
    record("4k. OPTIONS /mcp → 204", status == 204, f"got {status}")


# ──────────────────────────────────────────────────────────────────────
# 5. Valid domain edge cases
# ──────────────────────────────────────────────────────────────────────
def test_valid_domains():
    print("\n=== 5. Valid Domain Edge Cases ===")

    session_id = create_session("chaos-domain-test")
    if not session_id:
        print("  SKIP: no session")
        return

    valid_domains = [
        ("google.com", "standard"),
        ("mail.google.com", "subdomain"),
        ("example.co.uk", "ccTLD"),
        ("GOOGLE.COM", "uppercase"),
        ("example.com.", "trailing dot"),
        ("xn--mnchen-3ya.de", "punycode IDN"),
    ]

    for domain, label in valid_domains:
        status, body, _ = curl_json(
            "POST", "/mcp",
            body=jsonrpc("tools/call", {
                "name": "check_spf",
                "arguments": {"domain": domain}
            }),
            headers=mcp_headers(session_id),
        )
        try:
            data = json.loads(body)
            has_result = "result" in data
            is_error = data.get("result", {}).get("isError", False)
            record(f"5. check_spf {label} ({domain}) → result",
                   has_result and not is_error,
                   f"status={status}, isError={is_error}, body={body[:200]}")
        except Exception as e:
            record(f"5. check_spf {label} ({domain}) → result", False, str(e))

    delete_session(session_id)


# ──────────────────────────────────────────────────────────────────────
# 6. Blocked domains (SSRF)
# ──────────────────────────────────────────────────────────────────────
def test_blocked_domains():
    print("\n=== 6. Blocked Domain Edge Cases ===")

    session_id = create_session("chaos-blocked-test")
    if not session_id:
        print("  SKIP: no session")
        return

    blocked_domains = [
        ("localhost", "localhost"),
        ("127.0.0.1", "loopback IP"),
        ("169.254.169.254", "metadata IP"),
        ("10.0.0.1", "private IP"),
        ("192.168.1.1", "private IP class C"),
        ("example.test", "test TLD"),
        ("example.onion", "onion TLD"),
        ("example.local", "local TLD"),
        ("127.0.0.1.nip.io", "rebind service"),
        ("", "empty string"),
        ("*.example.com", "wildcard"),
        ("../../../etc/passwd", "path traversal"),
        (".leading-dot.com", "leading dot"),
        ("a" * 300 + ".com", "oversized label"),
        ("example..com", "double dot"),
        ("[::1]", "IPv6 loopback"),
        ("0x7f000001", "hex IP"),
    ]

    for domain, label in blocked_domains:
        status, body, _ = curl_json(
            "POST", "/mcp",
            body=jsonrpc("tools/call", {
                "name": "check_spf",
                "arguments": {"domain": domain}
            }),
            headers=mcp_headers(session_id),
        )
        try:
            data = json.loads(body)
            is_error = data.get("result", {}).get("isError", True)
            has_error_in_rpc = "error" in data
            blocked = is_error or has_error_in_rpc
            record(f"6. Blocked: {label} ({domain[:50]})", blocked,
                   f"isError={is_error}, rpc_error={has_error_in_rpc}")
        except json.JSONDecodeError:
            blocked = status != 200 or "error" in body.lower() or "invalid" in body.lower()
            record(f"6. Blocked: {label} ({domain[:50]})", blocked,
                   f"status={status}, non-JSON response")
        except Exception as e:
            record(f"6. Blocked: {label} ({domain[:50]})", False, str(e))

    delete_session(session_id)


# ──────────────────────────────────────────────────────────────────────
# 7. Argument edge cases
# ──────────────────────────────────────────────────────────────────────
def test_argument_edges():
    print("\n=== 7. Argument Edge Cases ===")

    session_id = create_session("chaos-args-test")
    if not session_id:
        print("  SKIP: no session")
        return

    # Missing domain
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=jsonrpc("tools/call", {"name": "check_spf", "arguments": {}}, 10),
        headers=mcp_headers(session_id),
    )
    try:
        data = json.loads(body)
        is_error = data.get("result", {}).get("isError", False) or "error" in data
        record("7a. Missing domain → error", is_error, f"body={body[:200]}")
    except Exception as e:
        record("7a. Missing domain → error", False, str(e))

    # Extra unknown param (should be ignored)
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=jsonrpc("tools/call", {
            "name": "check_spf",
            "arguments": {"domain": "google.com", "bogus_param": "whatever", "foo": 123}
        }, 11),
        headers=mcp_headers(session_id),
    )
    try:
        data = json.loads(body)
        has_result = "result" in data
        is_error = data.get("result", {}).get("isError", False)
        record("7b. Extra params ignored, tool runs", has_result and not is_error,
               f"body={body[:200]}")
    except Exception as e:
        record("7b. Extra params ignored, tool runs", False, str(e))

    # Unknown tool name
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=jsonrpc("tools/call", {"name": "nonexistent_tool", "arguments": {"domain": "google.com"}}, 12),
        headers=mcp_headers(session_id),
    )
    try:
        data = json.loads(body)
        is_error = data.get("result", {}).get("isError", True) or "error" in data
        record("7c. Unknown tool → error", is_error, f"body={body[:200]}")
    except Exception as e:
        record("7c. Unknown tool → error", False, str(e))

    # "scan" alias for scan_domain
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=jsonrpc("tools/call", {"name": "scan", "arguments": {"domain": "example.com"}}, 13),
        headers=mcp_headers(session_id),
    )
    try:
        data = json.loads(body)
        has_result = "result" in data
        is_error = data.get("result", {}).get("isError", False)
        content = data.get("result", {}).get("content", [])
        has_text = any(c.get("type") == "text" for c in content)
        record("7d. 'scan' alias works", has_result and not is_error and has_text,
               f"has_result={has_result}, isError={is_error}, has_text={has_text}")
    except Exception as e:
        record("7d. 'scan' alias works", False, str(e))

    # Invalid format value
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=jsonrpc("tools/call", {
            "name": "check_spf",
            "arguments": {"domain": "google.com", "format": "banana"}
        }, 14),
        headers=mcp_headers(session_id),
    )
    try:
        data = json.loads(body)
        is_error = data.get("result", {}).get("isError", False) or "error" in data
        record("7e. Invalid format → error", is_error, f"body={body[:200]}")
    except Exception as e:
        record("7e. Invalid format → error", False, str(e))

    # Domain as integer (type coercion)
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=jsonrpc("tools/call", {"name": "check_spf", "arguments": {"domain": 12345}}, 15),
        headers=mcp_headers(session_id),
    )
    try:
        data = json.loads(body)
        is_error = data.get("result", {}).get("isError", True) or "error" in data
        record("7f. Domain as integer → error", is_error, f"body={body[:200]}")
    except Exception as e:
        record("7f. Domain as integer → error", False, str(e))

    # Domain as null
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=jsonrpc("tools/call", {"name": "check_spf", "arguments": {"domain": None}}, 16),
        headers=mcp_headers(session_id),
    )
    try:
        data = json.loads(body)
        is_error = data.get("result", {}).get("isError", True) or "error" in data
        record("7g. Domain as null → error", is_error, f"body={body[:200]}")
    except Exception as e:
        record("7g. Domain as null → error", False, str(e))

    # Arguments as null instead of object
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=jsonrpc("tools/call", {"name": "check_spf", "arguments": None}, 17),
        headers=mcp_headers(session_id),
    )
    try:
        data = json.loads(body)
        is_error = data.get("result", {}).get("isError", True) or "error" in data
        record("7h. Arguments as null → error", is_error, f"body={body[:200]}")
    except Exception as e:
        record("7h. Arguments as null → error", False, str(e))

    # Missing arguments key entirely
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=jsonrpc("tools/call", {"name": "check_spf"}, 18),
        headers=mcp_headers(session_id),
    )
    try:
        data = json.loads(body)
        is_error = data.get("result", {}).get("isError", True) or "error" in data
        record("7i. Missing arguments key → error", is_error, f"body={body[:200]}")
    except Exception as e:
        record("7i. Missing arguments key → error", False, str(e))

    # XSS in domain argument
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=jsonrpc("tools/call", {
            "name": "check_spf",
            "arguments": {"domain": "<script>alert(1)</script>.com"}
        }, 19),
        headers=mcp_headers(session_id),
    )
    try:
        data = json.loads(body)
        is_error = data.get("result", {}).get("isError", True) or "error" in data
        # Also verify the script tag is not reflected back unsanitized
        no_xss = "<script>" not in body
        record("7j. XSS domain → error + sanitized", is_error and no_xss,
               f"isError={is_error}, sanitized={no_xss}")
    except Exception as e:
        record("7j. XSS domain → error + sanitized", False, str(e))

    delete_session(session_id)


# ──────────────────────────────────────────────────────────────────────
# 8. Content-Type validation
# ──────────────────────────────────────────────────────────────────────
def test_content_type():
    print("\n=== 8. Content-Type Validation ===")

    body_str = json.dumps(jsonrpc("ping", {}, 1))

    # Should be rejected (415)
    bad_types = [
        ("text/plain", "text/plain"),
        ("application/xml", "application/xml"),
        ("text/html", "text/html"),
        ("application/x-www-form-urlencoded", "form-urlencoded"),
        ("multipart/form-data", "multipart/form-data"),
    ]

    for ct, label in bad_types:
        status, body, _ = curl_json(
            "POST", "/mcp",
            body=body_str,
            headers=[f"Content-Type: {ct}"],
        )
        record(f"8a. Content-Type {label} → 415", status == 415, f"got {status}")

    # Should be accepted (not 415)
    good_types = [
        ("application/json", "application/json"),
        ("application/json;charset=utf-8", "json+charset"),
        ("application/json; charset=utf-8", "json+charset+space"),
        ("APPLICATION/JSON", "uppercase"),
    ]

    for ct, label in good_types:
        status, body, _ = curl_json(
            "POST", "/mcp",
            body=body_str,
            headers=[f"Content-Type: {ct}"],
        )
        not_415 = status != 415
        record(f"8b. Content-Type {label} → not 415", not_415, f"got {status}")

    # curl default (application/x-www-form-urlencoded with -d) → 415
    cmd = ["curl", "-s", "-w", "\n%{http_code}", "-X", "POST",
           "-d", body_str, f"{BASE}/mcp"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        lines = r.stdout.strip().split("\n")
        status = int(lines[-1])
        record("8c. No explicit Content-Type (curl default) → 415", status == 415, f"got {status}")
    except Exception as e:
        record("8c. No explicit Content-Type (curl default) → 415", False, str(e))


# ──────────────────────────────────────────────────────────────────────
# 9. No-send domain DKIM scoring
# ──────────────────────────────────────────────────────────────────────
def test_nosend_dkim():
    print("\n=== 9. No-Send Domain DKIM Scoring ===")

    session_id = create_session("chaos-nosend-test")
    if not session_id:
        print("  SKIP: no session")
        return

    def extract_dkim_score(scan_body):
        """Extract DKIM score from scan_domain result."""
        try:
            data = json.loads(scan_body)
            content = data.get("result", {}).get("content", [])
            for block in content:
                text = block.get("text", "")
                match = re.search(r"<!-- STRUCTURED_RESULT (.*?) STRUCTURED_RESULT -->", text, re.DOTALL)
                if match:
                    structured = json.loads(match.group(1))
                    return structured.get("checks", {}).get("dkim", {}).get("score")
                dkim_match = re.search(r"DKIM\s*\|\s*(\d+)", text)
                if dkim_match:
                    return int(dkim_match.group(1))
                dkim_match2 = re.search(r"DKIM[^\n]*?(\d+)/100", text)
                if dkim_match2:
                    return int(dkim_match2.group(1))
                dkim_match3 = re.search(r"(?i)dkim[^|]*\|\s*(\d+)", text)
                if dkim_match3:
                    return int(dkim_match3.group(1))
        except Exception:
            pass
        return None

    # Scan cscdbs.com (no-send domain → DKIM=100)
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=jsonrpc("tools/call", {"name": "scan_domain", "arguments": {"domain": "cscdbs.com"}}, 20),
        headers=mcp_headers(session_id),
    )
    cscdbs_dkim = extract_dkim_score(body)
    if cscdbs_dkim is None:
        try:
            data = json.loads(body)
            content = data.get("result", {}).get("content", [])
            snippet = ""
            for block in content:
                t = block.get("text", "")
                for line in t.split("\n"):
                    if "dkim" in line.lower():
                        snippet += line + " | "
            record("9a. cscdbs.com DKIM score = 100", False,
                   f"could not extract. DKIM lines: {snippet[:300]}")
        except Exception as e:
            record("9a. cscdbs.com DKIM score = 100", False, f"parse error: {e}")
    else:
        record("9a. cscdbs.com DKIM score = 100", cscdbs_dkim == 100,
               f"got DKIM score={cscdbs_dkim}")

    # Scan google.com (should NOT have DKIM=100)
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=jsonrpc("tools/call", {"name": "scan_domain", "arguments": {"domain": "google.com"}}, 21),
        headers=mcp_headers(session_id),
    )
    google_dkim = extract_dkim_score(body)
    if google_dkim is None:
        record("9b. google.com DKIM score != 100", False, "could not extract score")
    else:
        record("9b. google.com DKIM score != 100", google_dkim != 100,
               f"got DKIM score={google_dkim}")

    delete_session(session_id)


# ──────────────────────────────────────────────────────────────────────
# 10. Rate limit envelope & quota headers
# ──────────────────────────────────────────────────────────────────────
def test_rate_limit_envelope():
    print("\n=== 10. Rate Limit Envelope ===")

    # Unauthenticated call
    status, body, raw = curl_json(
        "POST", "/mcp",
        body=jsonrpc("initialize", {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "chaos-ratelimit-test", "version": "1.0"}
        }),
        headers=["Content-Type: application/json"],
        include_headers=True,
    )

    session_id = None
    for line in raw.split("\n"):
        if line.lower().startswith("mcp-session-id:"):
            session_id = line.split(":", 1)[1].strip()
            break

    if not session_id:
        record("10a. Unauth session created", False, f"status={status}")
        return

    record("10a. Unauth session created", True)

    curl_json("POST", "/mcp",
              body={"jsonrpc": "2.0", "method": "notifications/initialized"},
              headers=["Content-Type: application/json", f"Mcp-Session-Id: {session_id}"])

    # Make a tool call and check for quota headers
    status, body_text, resp_headers = curl_with_response_headers(
        "POST", "/mcp",
        body=jsonrpc("tools/call", {"name": "check_spf", "arguments": {"domain": "example.com"}}, 30),
        headers=["Content-Type: application/json", f"Mcp-Session-Id: {session_id}"],
    )

    record("10b. Unauth tool call → 200 (not 429)", status == 200, f"got {status}")

    has_quota_limit = "x-quota-limit" in resp_headers
    has_quota_remaining = "x-quota-remaining" in resp_headers
    record("10c. x-quota-limit header present", has_quota_limit,
           f"headers={list(resp_headers.keys())}")
    record("10d. x-quota-remaining header present", has_quota_remaining,
           f"headers={list(resp_headers.keys())}")

    has_rl_limit = "x-ratelimit-limit" in resp_headers
    has_rl_remaining = "x-ratelimit-remaining" in resp_headers
    record("10e. x-ratelimit-limit header present", has_rl_limit,
           f"headers={list(resp_headers.keys())}")
    record("10f. x-ratelimit-remaining header present", has_rl_remaining,
           f"headers={list(resp_headers.keys())}")

    curl_json("DELETE", "/mcp",
              headers=["Content-Type: application/json", f"Mcp-Session-Id: {session_id}"])


# ──────────────────────────────────────────────────────────────────────
# 11. Batch JSON-RPC
# ──────────────────────────────────────────────────────────────────────
def test_batch_jsonrpc():
    print("\n=== 11. Batch JSON-RPC ===")

    session_id = create_session("chaos-batch-test")
    if not session_id:
        print("  SKIP: no session")
        return

    # 11a. Valid batch: ping + tools/list
    batch = [
        jsonrpc("ping", {}, 100),
        jsonrpc("tools/list", {}, 101),
    ]
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=batch,
        headers=mcp_headers(session_id),
    )
    record("11a. Valid batch → 200", status == 200, f"got {status}")
    try:
        data = json.loads(body)
        is_array = isinstance(data, list)
        record("11b. Batch response is array", is_array, f"type={type(data).__name__}")
        if is_array:
            record("11c. Batch has 2 responses", len(data) == 2, f"got {len(data)}")
            ids = sorted([r.get("id") for r in data if "id" in r])
            record("11d. Response IDs match requests", ids == [100, 101], f"got {ids}")
    except Exception as e:
        record("11b. Batch response is array", False, str(e))

    # 11e. Empty batch → 400
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=[],
        headers=mcp_headers(session_id),
    )
    record("11e. Empty batch → 400", status == 400, f"got {status}")

    # 11f. Oversized batch (21 items, max is 20) → 400
    oversized_batch = [jsonrpc("ping", {}, i) for i in range(21)]
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=oversized_batch,
        headers=mcp_headers(session_id),
    )
    record("11f. Batch size 21 → 400", status == 400, f"got {status}")

    # 11g. Batch at max size (20 items) → 200
    max_batch = [jsonrpc("ping", {}, i) for i in range(20)]
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=max_batch,
        headers=mcp_headers(session_id),
    )
    record("11g. Batch size 20 → 200", status == 200, f"got {status}")
    try:
        data = json.loads(body)
        if isinstance(data, list):
            record("11h. 20 responses returned", len(data) == 20, f"got {len(data)}")
    except Exception as e:
        record("11h. 20 responses returned", False, str(e))

    # 11i. Batch with non-object entry
    bad_batch = [jsonrpc("ping", {}, 200), "not an object", jsonrpc("ping", {}, 201)]
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=bad_batch,
        headers=mcp_headers(session_id),
    )
    record("11i. Batch with non-object → 200 (per-item errors)", status == 200, f"got {status}")
    try:
        data = json.loads(body)
        if isinstance(data, list):
            # Should have error entries for the bad item
            has_errors = any("error" in r for r in data if isinstance(r, dict))
            has_successes = any("result" in r for r in data if isinstance(r, dict))
            record("11j. Mix of errors and successes", has_errors and has_successes,
                   f"errors={has_errors}, successes={has_successes}")
    except Exception as e:
        record("11j. Mix of errors and successes", False, str(e))

    # 11k. Batch with null entry
    null_batch = [jsonrpc("ping", {}, 300), None]
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=null_batch,
        headers=mcp_headers(session_id),
    )
    record("11k. Batch with null entry → 200", status == 200, f"got {status}")

    # 11l. All-notification batch → 202
    notif_batch = [
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
    ]
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=notif_batch,
        headers=mcp_headers(session_id),
    )
    record("11l. All-notification batch → 202", status == 202, f"got {status}")

    # 11m. Mixed notifications + requests
    mixed_batch = [
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        jsonrpc("ping", {}, 400),
    ]
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=mixed_batch,
        headers=mcp_headers(session_id),
    )
    record("11m. Mixed notif+request → 200", status == 200, f"got {status}")
    try:
        data = json.loads(body)
        if isinstance(data, list):
            # Only the ping response should be in the array (notification omitted)
            record("11n. Only request responses returned", len(data) == 1,
                   f"got {len(data)} responses")
        else:
            # Single response (not array) is also acceptable
            record("11n. Only request responses returned",
                   "result" in data and data.get("id") == 400,
                   f"single response id={data.get('id')}")
    except Exception as e:
        record("11n. Only request responses returned", False, str(e))

    # 11o. initialize cannot be batched — returns per-item errors
    init_batch = [
        jsonrpc("initialize", {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "batch-init", "version": "1.0"}
        }, 500),
        jsonrpc("ping", {}, 501),
    ]
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=init_batch,
        headers=mcp_headers(session_id),
    )
    record("11o. initialize in batch → rejected", status in (200, 400), f"got {status}")
    try:
        data = json.loads(body)
        if isinstance(data, list):
            has_init_error = any(
                "initialize cannot be batched" in r.get("error", {}).get("message", "")
                for r in data if isinstance(r, dict)
            )
            record("11p. Batch init error message present", has_init_error,
                   f"responses={[r.get('error', {}).get('message', '')[:60] for r in data if isinstance(r, dict)]}")
        else:
            has_init_error = "initialize" in data.get("error", {}).get("message", "")
            record("11p. Batch init error message present", has_init_error, f"body={body[:200]}")
    except Exception as e:
        record("11p. Batch init error message present", False, str(e))

    delete_session(session_id)


# ──────────────────────────────────────────────────────────────────────
# 12. Body size limits
# ──────────────────────────────────────────────────────────────────────
def test_body_limits():
    print("\n=== 12. Body Size Limits ===")

    session_id = create_session("chaos-body-test")
    if not session_id:
        print("  SKIP: no session")
        return

    # 12a. Normal-sized body works
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=jsonrpc("ping", {}, 1),
        headers=mcp_headers(session_id),
    )
    record("12a. Normal body → 200", status == 200, f"got {status}")

    # 12b. Body just under 10KB limit
    padding = "x" * 9000  # ~9KB with JSON overhead
    under_limit = jsonrpc("tools/call", {
        "name": "check_spf",
        "arguments": {"domain": "google.com", "padding": padding}
    }, 2)
    body_str = json.dumps(under_limit)
    record(f"12b. Body size: {len(body_str)} bytes (under 10240)", len(body_str) < 10240,
           f"actual={len(body_str)}")
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=under_limit,
        headers=mcp_headers(session_id),
    )
    record("12c. Under-limit body → not 413", status != 413, f"got {status}")

    # 12d. Body over 10KB limit → 413
    big_padding = "x" * 11000
    over_limit = jsonrpc("tools/call", {
        "name": "check_spf",
        "arguments": {"domain": "google.com", "padding": big_padding}
    }, 3)
    body_str = json.dumps(over_limit)
    record(f"12d. Body size: {len(body_str)} bytes (over 10240)", len(body_str) > 10240,
           f"actual={len(body_str)}")
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=over_limit,
        headers=mcp_headers(session_id),
    )
    record("12e. Over-limit body → 413", status == 413, f"got {status}")

    # 12f. Way oversized body (100KB)
    huge_padding = "x" * 100000
    huge_body = jsonrpc("ping", {"padding": huge_padding}, 4)
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=huge_body,
        headers=mcp_headers(session_id),
    )
    record("12f. 100KB body → 413", status == 413, f"got {status}")

    # 12g. Empty body (no -d flag at all)
    cmd = ["curl", "-s", "-w", "\n%{http_code}", "-X", "POST",
           f"{BASE}/mcp"]
    for h in mcp_headers(session_id):
        cmd += ["-H", h]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        lines = r.stdout.strip().split("\n")
        status = int(lines[-1])
        # Empty body should fail JSON parsing → 400
        record("12g. Empty body → 400", status == 400, f"got {status}")
    except Exception as e:
        record("12g. Empty body → 400", False, str(e))

    delete_session(session_id)


# ──────────────────────────────────────────────────────────────────────
# 13. Session lifecycle abuse
# ──────────────────────────────────────────────────────────────────────
def test_session_abuse():
    print("\n=== 13. Session Lifecycle Abuse ===")

    # 13a. POST /mcp without session header → 400
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=jsonrpc("ping", {}, 1),
        headers=mcp_headers(),  # no session_id
    )
    record("13a. POST /mcp no session (non-init) → 400", status == 400, f"got {status}")

    # 13b. Malformed session IDs → rejected (400 or 404)
    format_malformed = [
        ("too-short", "too short"),
        ("A" * 64, "uppercase hex"),
        ("g" * 64, "non-hex chars"),
        ("0" * 63, "63 chars"),
        ("0" * 65, "65 chars"),
        ("0" * 64 + " ", "trailing space"),
    ]

    for sid, label in format_malformed:
        status, body, _ = curl_json(
            "POST", "/mcp",
            body=jsonrpc("ping", {}, 1),
            headers=mcp_headers(sid),
        )
        record(f"13b. Malformed session ({label}) → rejected", status in (400, 404),
               f"got {status}")

    # 13b-waf. Injection attempts — blocked by WAF (403) or app (400)
    injection_ids = [
        ("' OR 1=1 --" + "0" * 52, "SQL injection"),
        ("<script>alert(1)</script>" + "0" * 39, "XSS attempt"),
    ]

    for sid, label in injection_ids:
        status, body, _ = curl_json(
            "POST", "/mcp",
            body=jsonrpc("ping", {}, 1),
            headers=mcp_headers(sid),
        )
        record(f"13b. Injection session ({label}) → blocked", status in (400, 403),
               f"got {status}")

    # 13c. Valid-format but nonexistent session → 404
    fake_session = "0" * 64
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=jsonrpc("ping", {}, 1),
        headers=mcp_headers(fake_session),
    )
    record("13c. Nonexistent session → 404", status == 404, f"got {status}")

    # 13d. DELETE with malformed session → rejected (400 or 404)
    status, body, _ = curl_json(
        "DELETE", "/mcp",
        headers=mcp_headers("not-a-valid-session"),
    )
    record("13d. DELETE malformed session → rejected", status in (400, 404), f"got {status}")

    # 13e. DELETE without session header → 400
    status, body, _ = curl_json(
        "DELETE", "/mcp",
        headers=mcp_headers(),
    )
    record("13e. DELETE no session header → 400", status == 400, f"got {status}")

    # 13f. Double-delete: create session, delete, delete again
    session_id = create_session("chaos-double-delete")
    if session_id:
        status1, _, _ = curl_json("DELETE", "/mcp", headers=mcp_headers(session_id))
        record("13f. First DELETE → 204", status1 == 204, f"got {status1}")
        status2, _, _ = curl_json("DELETE", "/mcp", headers=mcp_headers(session_id))
        record("13g. Second DELETE → 404", status2 == 404, f"got {status2}")

    # 13h. Use session after DELETE
    session_id = create_session("chaos-use-after-delete")
    if session_id:
        curl_json("DELETE", "/mcp", headers=mcp_headers(session_id))
        status, body, _ = curl_json(
            "POST", "/mcp",
            body=jsonrpc("tools/list", {}, 1),
            headers=mcp_headers(session_id),
        )
        record("13h. Use session after DELETE → 404", status == 404, f"got {status}")

    # 13i. Create multiple sessions rapidly (should all succeed for auth'd user)
    session_ids = []
    for i in range(5):
        sid = create_session(f"chaos-rapid-{i}")
        if sid:
            session_ids.append(sid)
    record("13i. 5 rapid session creates succeed", len(session_ids) == 5,
           f"created {len(session_ids)}")

    # Clean up
    for sid in session_ids:
        delete_session(sid)


# ──────────────────────────────────────────────────────────────────────
# 14. JSON-RPC protocol edge cases
# ──────────────────────────────────────────────────────────────────────
def test_jsonrpc_protocol():
    print("\n=== 14. JSON-RPC Protocol Edge Cases ===")

    session_id = create_session("chaos-jsonrpc-test")
    if not session_id:
        print("  SKIP: no session")
        return

    # 14a. Invalid JSON
    status, body, _ = curl_json(
        "POST", "/mcp",
        body="{not valid json!!!",
        headers=mcp_headers(session_id),
    )
    record("14a. Invalid JSON → 400", status == 400, f"got {status}")
    try:
        data = json.loads(body)
        error_code = data.get("error", {}).get("code")
        record("14b. Parse error code -32700", error_code == -32700, f"got {error_code}")
    except Exception:
        record("14b. Parse error code -32700", False, f"body={body[:200]}")

    # 14c. Missing jsonrpc field
    status, body, _ = curl_json(
        "POST", "/mcp",
        body={"method": "ping", "id": 1},
        headers=mcp_headers(session_id),
    )
    record("14c. Missing jsonrpc field → 400", status == 400, f"got {status}")

    # 14d. Wrong jsonrpc version
    status, body, _ = curl_json(
        "POST", "/mcp",
        body={"jsonrpc": "1.0", "method": "ping", "id": 1},
        headers=mcp_headers(session_id),
    )
    record("14d. jsonrpc '1.0' → 400", status == 400, f"got {status}")

    # 14e. Missing method field
    status, body, _ = curl_json(
        "POST", "/mcp",
        body={"jsonrpc": "2.0", "id": 1},
        headers=mcp_headers(session_id),
    )
    record("14e. Missing method → 400", status == 400, f"got {status}")

    # 14f. Method as number (not string)
    status, body, _ = curl_json(
        "POST", "/mcp",
        body={"jsonrpc": "2.0", "method": 42, "id": 1},
        headers=mcp_headers(session_id),
    )
    record("14f. Method as number → 400", status == 400, f"got {status}")

    # 14g. Unknown method → error code -32601
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=jsonrpc("completions/complete", {}, 1),
        headers=mcp_headers(session_id),
    )
    try:
        data = json.loads(body)
        error_code = data.get("error", {}).get("code")
        record("14g. Unknown method → -32601", error_code == -32601, f"got {error_code}")
    except Exception as e:
        record("14g. Unknown method → -32601", False, str(e))

    # 14h. id as object (invalid)
    status, body, _ = curl_json(
        "POST", "/mcp",
        body={"jsonrpc": "2.0", "method": "ping", "id": {"nested": True}},
        headers=mcp_headers(session_id),
    )
    record("14h. id as object → 400", status == 400, f"got {status}")

    # 14i. id as array (invalid)
    status, body, _ = curl_json(
        "POST", "/mcp",
        body={"jsonrpc": "2.0", "method": "ping", "id": [1, 2]},
        headers=mcp_headers(session_id),
    )
    record("14i. id as array → 400", status == 400, f"got {status}")

    # 14j. id as null — MCP treats as notification (no response expected) → 202
    status, body, _ = curl_json(
        "POST", "/mcp",
        body={"jsonrpc": "2.0", "method": "ping", "id": None},
        headers=mcp_headers(session_id),
    )
    record("14j. id as null → 202 (notification)", status == 202, f"got {status}")

    # 14l. id as string
    status, body, _ = curl_json(
        "POST", "/mcp",
        body={"jsonrpc": "2.0", "method": "ping", "id": "my-string-id"},
        headers=mcp_headers(session_id),
    )
    try:
        data = json.loads(body)
        record("14l. String id echoed back", data.get("id") == "my-string-id",
               f"got id={data.get('id')}")
    except Exception as e:
        record("14l. String id echoed back", False, str(e))

    # 14m. Notification (no id) → 202
    status, body, _ = curl_json(
        "POST", "/mcp",
        body={"jsonrpc": "2.0", "method": "notifications/initialized"},
        headers=mcp_headers(session_id),
    )
    record("14m. Notification (no id) → 202", status == 202, f"got {status}")

    # 14n. Extra fields in JSON-RPC (should be tolerated)
    status, body, _ = curl_json(
        "POST", "/mcp",
        body={"jsonrpc": "2.0", "method": "ping", "id": 1, "extra": "field", "another": 42},
        headers=mcp_headers(session_id),
    )
    record("14n. Extra fields tolerated → 200", status == 200, f"got {status}")

    # 14o. Deeply nested params (no crash)
    nested = {"a": {"b": {"c": {"d": {"e": "deep"}}}}}
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=jsonrpc("tools/call", {
            "name": "check_spf",
            "arguments": {"domain": "google.com", "nested": nested}
        }, 99),
        headers=mcp_headers(session_id),
    )
    record("14o. Deeply nested params → no crash", status in (200, 400), f"got {status}")

    delete_session(session_id)


# ──────────────────────────────────────────────────────────────────────
# 15. Origin validation
# ──────────────────────────────────────────────────────────────────────
def test_origin_validation():
    print("\n=== 15. Origin Validation ===")

    # 15a. No Origin header → allowed (non-browser clients)
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=jsonrpc("initialize", {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "no-origin", "version": "1.0"}
        }),
        headers=mcp_headers(),
        include_headers=True,
    )
    record("15a. No Origin header → allowed (200)", status == 200, f"got {status}")
    # Clean up session
    for line in body.split("\n"):
        if line.lower().startswith("mcp-session-id:"):
            delete_session(line.split(":", 1)[1].strip())
            break

    # 15b. Unauthorized browser origin → 403
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=json.dumps(jsonrpc("ping", {}, 1)),
        headers=[
            "Content-Type: application/json",
            "Origin: https://evil-site.example.com",
        ],
    )
    record("15b. Unauthorized Origin → 403", status == 403, f"got {status}")

    # 15c. Malformed origin → 403
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=json.dumps(jsonrpc("ping", {}, 1)),
        headers=[
            "Content-Type: application/json",
            "Origin: not-a-valid-url",
        ],
    )
    record("15c. Malformed Origin → 403", status == 403, f"got {status}")

    # 15d. Same-origin (self) → allowed
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=json.dumps(jsonrpc("initialize", {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "same-origin", "version": "1.0"}
        })),
        headers=[
            "Content-Type: application/json",
            f"Origin: {BASE}",
        ],
        include_headers=True,
    )
    record("15d. Same-origin → allowed (200)", status == 200, f"got {status}")
    for line in body.split("\n"):
        if line.lower().startswith("mcp-session-id:"):
            delete_session(line.split(":", 1)[1].strip())
            break

    # 15e. VS Code scheme → allowed
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=json.dumps(jsonrpc("initialize", {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "vscode-origin", "version": "1.0"}
        })),
        headers=[
            "Content-Type: application/json",
            "Origin: vscode-webview://extension-id",
        ],
        include_headers=True,
    )
    record("15e. vscode-webview Origin → allowed", status == 200, f"got {status}")
    for line in body.split("\n"):
        if line.lower().startswith("mcp-session-id:"):
            delete_session(line.split(":", 1)[1].strip())
            break

    # 15f. OPTIONS with bad origin still gets 204 (CORS preflight)
    status, body, _ = curl_json(
        "OPTIONS", "/mcp",
        headers=[
            "Origin: https://evil-site.example.com",
            "Access-Control-Request-Method: POST",
        ],
    )
    record("15f. OPTIONS preflight → 204", status == 204, f"got {status}")


# ──────────────────────────────────────────────────────────────────────
# 16. resources/read edge cases
# ──────────────────────────────────────────────────────────────────────
def test_resources_read():
    print("\n=== 16. resources/read Edge Cases ===")

    session_id = create_session("chaos-resources-test")
    if not session_id:
        print("  SKIP: no session")
        return

    # 16a. Read valid resource
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=jsonrpc("resources/read", {"uri": "dns-security://guides/scoring"}, 1),
        headers=mcp_headers(session_id),
    )
    try:
        data = json.loads(body)
        contents = data.get("result", {}).get("contents", [])
        has_content = len(contents) > 0 and "text" in contents[0]
        record("16a. Read scoring guide → content", has_content,
               f"contents_count={len(contents)}")
    except Exception as e:
        record("16a. Read scoring guide → content", False, str(e))

    # 16b. Read all 6 resources
    resource_uris = [
        "dns-security://guides/security-checks",
        "dns-security://guides/scoring",
        "dns-security://guides/record-types",
        "dns-security://guides/agent-workflows",
        "dns-security://guides/intelligence",
        "dns-security://guides/remediation",
    ]
    for uri in resource_uris:
        status, body, _ = curl_json(
            "POST", "/mcp",
            body=jsonrpc("resources/read", {"uri": uri}),
            headers=mcp_headers(session_id),
        )
        try:
            data = json.loads(body)
            has_result = "result" in data
            is_error = "error" in data
            short_name = uri.split("/")[-1]
            record(f"16b. Read {short_name} → success", has_result and not is_error,
                   f"status={status}")
        except Exception as e:
            record(f"16b. Read {uri.split('/')[-1]} → success", False, str(e))

    # 16c. Invalid resource URI
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=jsonrpc("resources/read", {"uri": "dns-security://guides/nonexistent"}, 2),
        headers=mcp_headers(session_id),
    )
    try:
        data = json.loads(body)
        is_error = data.get("result", {}).get("isError", False) or "error" in data
        record("16c. Nonexistent resource → error", is_error, f"body={body[:200]}")
    except Exception as e:
        record("16c. Nonexistent resource → error", False, str(e))

    # 16d. Missing uri parameter
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=jsonrpc("resources/read", {}, 3),
        headers=mcp_headers(session_id),
    )
    try:
        data = json.loads(body)
        is_error = data.get("result", {}).get("isError", False) or "error" in data
        record("16d. Missing uri param → error", is_error, f"body={body[:200]}")
    except Exception as e:
        record("16d. Missing uri param → error", False, str(e))

    # 16e. URI as non-string
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=jsonrpc("resources/read", {"uri": 12345}, 4),
        headers=mcp_headers(session_id),
    )
    try:
        data = json.loads(body)
        is_error = data.get("result", {}).get("isError", False) or "error" in data
        record("16e. URI as integer → error", is_error, f"body={body[:200]}")
    except Exception as e:
        record("16e. URI as integer → error", False, str(e))

    # 16f. Completely bogus URI scheme
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=jsonrpc("resources/read", {"uri": "file:///etc/passwd"}, 5),
        headers=mcp_headers(session_id),
    )
    try:
        data = json.loads(body)
        is_error = data.get("result", {}).get("isError", False) or "error" in data
        record("16f. file:// URI → error", is_error, f"body={body[:200]}")
    except json.JSONDecodeError:
        # Empty body or non-JSON = request was rejected
        record("16f. file:// URI → error", status != 200 or not body.strip(),
               f"status={status}, body_len={len(body)}")

    delete_session(session_id)


# ──────────────────────────────────────────────────────────────────────
# 17. prompts/get edge cases
# ──────────────────────────────────────────────────────────────────────
def test_prompts_get():
    print("\n=== 17. prompts/get Edge Cases ===")

    session_id = create_session("chaos-prompts-test")
    if not session_id:
        print("  SKIP: no session")
        return

    # 17a. Valid prompt with domain
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=jsonrpc("prompts/get", {
            "name": "full-security-audit",
            "arguments": {"domain": "google.com"}
        }, 1),
        headers=mcp_headers(session_id),
    )
    try:
        data = json.loads(body)
        messages = data.get("result", {}).get("messages", [])
        has_messages = len(messages) > 0
        record("17a. full-security-audit → has messages", has_messages,
               f"msg_count={len(messages)}")
    except Exception as e:
        record("17a. full-security-audit → has messages", False, str(e))

    # 17b. All 7 prompts
    prompts = [
        "full-security-audit",
        "email-auth-check",
        "policy-compliance-check",
        "remediation-workflow",
        "email-hardening-guide",
        "provider-benchmark",
        "attack-surface-assessment",
    ]
    for prompt_name in prompts:
        status, body, _ = curl_json(
            "POST", "/mcp",
            body=jsonrpc("prompts/get", {
                "name": prompt_name,
                "arguments": {"domain": "example.com"}
            }),
            headers=mcp_headers(session_id),
        )
        try:
            data = json.loads(body)
            has_result = "result" in data
            is_error = "error" in data
            record(f"17b. {prompt_name} → success", has_result and not is_error,
                   f"status={status}")
        except Exception as e:
            record(f"17b. {prompt_name} → success", False, str(e))

    # 17c. Invalid prompt name
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=jsonrpc("prompts/get", {"name": "nonexistent-prompt"}, 2),
        headers=mcp_headers(session_id),
    )
    try:
        data = json.loads(body)
        is_error = "error" in data
        record("17c. Nonexistent prompt → error", is_error, f"body={body[:200]}")
    except Exception as e:
        record("17c. Nonexistent prompt → error", False, str(e))

    # 17d. Missing name parameter
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=jsonrpc("prompts/get", {}, 3),
        headers=mcp_headers(session_id),
    )
    try:
        data = json.loads(body)
        is_error = "error" in data
        record("17d. Missing name param → error", is_error, f"body={body[:200]}")
    except Exception as e:
        record("17d. Missing name param → error", False, str(e))

    # 17e. prompt with optional minimum_grade arg
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=jsonrpc("prompts/get", {
            "name": "policy-compliance-check",
            "arguments": {"domain": "google.com", "minimum_grade": "A+"}
        }, 4),
        headers=mcp_headers(session_id),
    )
    try:
        data = json.loads(body)
        messages = data.get("result", {}).get("messages", [])
        # Check that A+ appears in the prompt text
        text = " ".join(m.get("content", {}).get("text", "") for m in messages)
        has_grade = "A+" in text
        record("17e. policy-compliance with minimum_grade=A+", has_grade,
               f"found A+ in text={has_grade}")
    except Exception as e:
        record("17e. policy-compliance with minimum_grade=A+", False, str(e))

    delete_session(session_id)


# ──────────────────────────────────────────────────────────────────────
# 18. Concurrent tool execution
# ──────────────────────────────────────────────────────────────────────
def test_concurrent_execution():
    print("\n=== 18. Concurrent Tool Execution ===")

    session_id = create_session("chaos-concurrent-test")
    if not session_id:
        print("  SKIP: no session")
        return

    # 18a. 5 concurrent check_spf calls on different domains
    domains = ["google.com", "microsoft.com", "apple.com", "github.com", "cloudflare.com"]

    def run_check(domain, req_id):
        status, body, _ = curl_json(
            "POST", "/mcp",
            body=jsonrpc("tools/call", {
                "name": "check_spf",
                "arguments": {"domain": domain}
            }, req_id),
            headers=mcp_headers(session_id),
        )
        return domain, status, body

    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = {pool.submit(run_check, d, i): d for i, d in enumerate(domains, 600)}
        concurrent_results = {}
        for future in as_completed(futures):
            domain, status, body = future.result()
            concurrent_results[domain] = (status, body)

    all_ok = all(s == 200 for s, _ in concurrent_results.values())
    record("18a. 5 concurrent check_spf → all 200", all_ok,
           f"statuses={[s for s, _ in concurrent_results.values()]}")

    # Verify all returned valid results
    all_valid = True
    for domain, (status, body) in concurrent_results.items():
        try:
            data = json.loads(body)
            if "result" not in data or data.get("result", {}).get("isError", False):
                all_valid = False
                break
        except Exception:
            all_valid = False
            break
    record("18b. All concurrent results valid", all_valid)

    # 18c. 3 concurrent different tools on same domain
    tools = [
        ("check_spf", {"domain": "google.com"}),
        ("check_dmarc", {"domain": "google.com"}),
        ("check_mx", {"domain": "google.com"}),
    ]

    def run_tool(tool_name, args, req_id):
        status, body, _ = curl_json(
            "POST", "/mcp",
            body=jsonrpc("tools/call", {"name": tool_name, "arguments": args}, req_id),
            headers=mcp_headers(session_id),
        )
        return tool_name, status, body

    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = {pool.submit(run_tool, t, a, i): t for i, (t, a) in enumerate(tools, 700)}
        tool_results = {}
        for future in as_completed(futures):
            name, status, body = future.result()
            tool_results[name] = (status, body)

    all_ok = all(s == 200 for s, _ in tool_results.values())
    record("18c. 3 concurrent tools same domain → all 200", all_ok,
           f"statuses={[(n, s) for n, (s, _) in tool_results.items()]}")

    # 18d. Concurrent sessions: tool call on each
    def create_and_call(idx):
        sid = create_session(f"chaos-concurrent-session-{idx}")
        if not sid:
            return idx, 0, "no session"
        status, body, _ = curl_json(
            "POST", "/mcp",
            body=jsonrpc("ping", {}, 1),
            headers=mcp_headers(sid),
        )
        delete_session(sid)
        return idx, status, body

    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(create_and_call, i) for i in range(3)]
        session_results = [f.result() for f in as_completed(futures)]

    all_ok = all(s == 200 for _, s, _ in session_results)
    record("18d. 3 concurrent session lifecycles → all 200", all_ok,
           f"statuses={[(i, s) for i, s, _ in session_results]}")

    delete_session(session_id)


# ──────────────────────────────────────────────────────────────────────
# 19. Format parameter validation
# ──────────────────────────────────────────────────────────────────────
def test_format_parameter():
    print("\n=== 19. Format Parameter Validation ===")

    session_id = create_session("chaos-format-test")
    if not session_id:
        print("  SKIP: no session")
        return

    # 19a. format=compact
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=jsonrpc("tools/call", {
            "name": "check_spf",
            "arguments": {"domain": "google.com", "format": "compact"}
        }, 1),
        headers=mcp_headers(session_id),
    )
    try:
        data = json.loads(body)
        has_result = "result" in data and not data.get("result", {}).get("isError", False)
        record("19a. format=compact → success", has_result, f"status={status}")
    except Exception as e:
        record("19a. format=compact → success", False, str(e))

    # 19b. format=full
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=jsonrpc("tools/call", {
            "name": "check_spf",
            "arguments": {"domain": "google.com", "format": "full"}
        }, 2),
        headers=mcp_headers(session_id),
    )
    try:
        data = json.loads(body)
        has_result = "result" in data and not data.get("result", {}).get("isError", False)
        record("19b. format=full → success", has_result, f"status={status}")
    except Exception as e:
        record("19b. format=full → success", False, str(e))

    # 19c. Compact output is shorter than full output
    compact_len = 0
    full_len = 0
    for fmt, req_id in [("compact", 3), ("full", 4)]:
        _, body, _ = curl_json(
            "POST", "/mcp",
            body=jsonrpc("tools/call", {
                "name": "check_spf",
                "arguments": {"domain": "google.com", "format": fmt}
            }, req_id),
            headers=mcp_headers(session_id),
        )
        try:
            data = json.loads(body)
            text = "".join(c.get("text", "") for c in data.get("result", {}).get("content", []))
            if fmt == "compact":
                compact_len = len(text)
            else:
                full_len = len(text)
        except Exception:
            pass

    if compact_len > 0 and full_len > 0:
        record("19c. Compact shorter than full", compact_len < full_len,
               f"compact={compact_len}, full={full_len}")
    else:
        record("19c. Compact shorter than full", False,
               f"compact={compact_len}, full={full_len}")

    # 19d. Case-insensitive format accepted
    for fmt in ["COMPACT", "Full", "FULL"]:
        status, body, _ = curl_json(
            "POST", "/mcp",
            body=jsonrpc("tools/call", {
                "name": "check_spf",
                "arguments": {"domain": "google.com", "format": fmt}
            }),
            headers=mcp_headers(session_id),
        )
        try:
            data = json.loads(body)
            has_result = "result" in data and not data.get("result", {}).get("isError", False)
            record(f"19d. format='{fmt}' → accepted (case-insensitive)", has_result,
                   f"status={status}")
        except Exception as e:
            record(f"19d. format='{fmt}' → accepted", False, str(e))

    # 19e. Invalid format values
    bad_formats = ["json", "xml", "", " ", "compact full"]
    for fmt in bad_formats:
        status, body, _ = curl_json(
            "POST", "/mcp",
            body=jsonrpc("tools/call", {
                "name": "check_spf",
                "arguments": {"domain": "google.com", "format": fmt}
            }),
            headers=mcp_headers(session_id),
        )
        try:
            data = json.loads(body)
            is_error = data.get("result", {}).get("isError", False) or "error" in data
            record(f"19e. format='{fmt}' → error", is_error,
                   f"status={status}, body={body[:150]}")
        except Exception as e:
            record(f"19e. format='{fmt}' → error", False, str(e))

    # 19f. format on scan_domain
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=jsonrpc("tools/call", {
            "name": "scan_domain",
            "arguments": {"domain": "example.com", "format": "compact"}
        }, 5),
        headers=mcp_headers(session_id),
    )
    try:
        data = json.loads(body)
        has_result = "result" in data and not data.get("result", {}).get("isError", False)
        record("19f. scan_domain format=compact → success", has_result, f"status={status}")
    except Exception as e:
        record("19e. scan_domain format=compact → success", False, str(e))

    delete_session(session_id)


# ──────────────────────────────────────────────────────────────────────
# Run all tests
# ──────────────────────────────────────────────────────────────────────
def main():
    _validate_api_key()

    print("=" * 70)
    print("  bv-mcp v2.0.10 Chaos Test Suite")
    print(f"  Target: {BASE}")
    print(f"  Auth:   {'API key validated' if API_KEY else 'unauthenticated (free tier)'}")
    print(f"  Time:   {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")
    print("=" * 70)

    test_streamable_http()       # 1
    test_legacy_sse()            # 2
    test_notification_stream()   # 3
    test_endpoints()             # 4
    test_valid_domains()         # 5
    test_blocked_domains()       # 6
    test_argument_edges()        # 7
    test_content_type()          # 8
    test_nosend_dkim()           # 9
    test_rate_limit_envelope()   # 10
    test_batch_jsonrpc()         # 11  NEW
    test_body_limits()           # 12  NEW
    test_session_abuse()         # 13  NEW
    test_jsonrpc_protocol()      # 14  NEW
    test_origin_validation()     # 15  NEW
    test_resources_read()        # 16  NEW
    test_prompts_get()           # 17  NEW
    test_concurrent_execution()  # 18  NEW
    test_format_parameter()      # 19  NEW

    # Summary
    total = len(results)
    passed = sum(1 for _, p in results if p)
    failed = total - passed
    print("\n" + "=" * 70)
    print(f"  SUMMARY: {passed}/{total} passed, {failed} failed")
    print("=" * 70)

    if failed > 0:
        print("\n  FAILURES:")
        for name, p in results:
            if not p:
                print(f"    - {name}")

    print()
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
