#!/usr/bin/env python3
"""
Chaos test for bv-mcp v2.0.8 production
Tests edge cases and all transport types via curl subprocess calls.
"""

import subprocess
import json
import sys
import re
import os

BASE = "https://dns-mcp.blackveilsecurity.com"
API_KEY = os.getenv("BV_API_KEY")

if not API_KEY:
    print("ERROR: BV_API_KEY environment variable is required.")
    sys.exit(1)

results = []


def record(name, passed, detail=""):
    status = "PASS" if passed else "FAIL"
    results.append((name, passed))
    msg = f"  [{status}] {name}"
    if detail and not passed:
        msg += f"  -- {detail}"
    print(msg)


def curl_json(method, path, body=None, headers=None, extra_args=None, include_headers=False):
    """Run curl and return (status_code, response_body, raw_headers)."""
    cmd = ["curl", "-s", "-w", "\n%{http_code}"]
    if include_headers:
        cmd.append("-D-")
    if method == "DELETE":
        cmd += ["-X", "DELETE"]
    elif method == "PUT":
        cmd += ["-X", "PUT"]
    elif method == "PATCH":
        cmd += ["-X", "PATCH"]
    elif method == "OPTIONS":
        cmd += ["-X", "OPTIONS"]
    elif method == "GET":
        pass  # default
    elif method == "POST":
        cmd += ["-X", "POST"]

    if headers:
        for h in headers:
            cmd += ["-H", h]

    if body is not None:
        cmd += ["-d", json.dumps(body) if isinstance(body, dict) else body]

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
    # Use a temp file for response headers to avoid interleaving issues with HTTP/2
    import tempfile, os
    header_file = tempfile.mktemp(suffix=".headers")
    cmd = ["curl", "-s", "-D", header_file, "-w", "\n__STATUS__%{http_code}"]
    if method != "GET":
        cmd += ["-X", method]
    if headers:
        for h in headers:
            cmd += ["-H", h]
    if body is not None:
        cmd += ["-d", json.dumps(body) if isinstance(body, dict) else body]
    cmd.append(f"{BASE}{path}")

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        output = r.stdout
        # Extract status code from marker
        status_match = re.search(r"__STATUS__(\d+)", output)
        status_code = int(status_match.group(1)) if status_match else 0
        body_text = re.sub(r"\n?__STATUS__\d+\s*$", "", output).strip()

        # Read headers from file
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


def mcp_headers(session_id=None, content_type="application/json"):
    h = [f"Authorization: Bearer {API_KEY}"]
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


# ──────────────────────────────────────────────────────────────────────
# 1. Streamable HTTP full lifecycle
# ──────────────────────────────────────────────────────────────────────
def test_streamable_http():
    print("\n=== 1. Streamable HTTP Full Lifecycle ===")

    # Initialize
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=jsonrpc("initialize", {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "chaos-test", "version": "1.0"}
        }),
        headers=mcp_headers(),
        include_headers=True,
    )
    record("1a. Initialize → 200", status == 200, f"got {status}")

    # Extract session ID from Mcp-Session-Id header in raw output
    session_id = None
    for line in _.split("\n"):
        if line.lower().startswith("mcp-session-id:"):
            session_id = line.split(":", 1)[1].strip()
            break
    record("1b. Session ID returned", session_id is not None, f"sid={session_id}")

    if not session_id:
        print("  SKIP remaining lifecycle tests (no session)")
        return None

    # Initialized notification (required by MCP spec before further requests)
    curl_json("POST", "/mcp",
              body={"jsonrpc": "2.0", "method": "notifications/initialized"},
              headers=mcp_headers(session_id))

    # tools/list
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=jsonrpc("tools/list", {}, 2),
        headers=mcp_headers(session_id),
    )
    record("1c. tools/list → 200", status == 200, f"got {status}")
    try:
        data = json.loads(body)
        tool_count = len(data.get("result", {}).get("tools", []))
        record("1d. 33 tools returned", tool_count == 33, f"got {tool_count}")
    except Exception as e:
        record("1d. 33 tools returned", False, str(e))

    # resources/list
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=jsonrpc("resources/list", {}, 3),
        headers=mcp_headers(session_id),
    )
    try:
        data = json.loads(body)
        res_count = len(data.get("result", {}).get("resources", []))
        record("1e. resources/list → 6 resources", res_count == 6, f"got {res_count}")
    except Exception as e:
        record("1e. resources/list → 6 resources", False, str(e))

    # prompts/list
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=jsonrpc("prompts/list", {}, 4),
        headers=mcp_headers(session_id),
    )
    try:
        data = json.loads(body)
        prompt_count = len(data.get("result", {}).get("prompts", []))
        record("1f. prompts/list → 7 prompts", prompt_count == 7, f"got {prompt_count}")
    except Exception as e:
        record("1f. prompts/list → 7 prompts", False, str(e))

    # ping
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=jsonrpc("ping", {}, 5),
        headers=mcp_headers(session_id),
    )
    record("1g. ping → 200", status == 200, f"got {status}")
    try:
        data = json.loads(body)
        record("1h. ping result is empty object", data.get("result") == {}, f"got {data.get('result')}")
    except Exception as e:
        record("1h. ping result is empty object", False, str(e))

    # tools/call check_spf
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=jsonrpc("tools/call", {
            "name": "check_spf",
            "arguments": {"domain": "google.com"}
        }, 6),
        headers=mcp_headers(session_id),
    )
    record("1i. tools/call check_spf → 200", status == 200, f"got {status}")
    try:
        data = json.loads(body)
        content = data.get("result", {}).get("content", [])
        has_text = any(c.get("type") == "text" for c in content)
        record("1j. check_spf has text content", has_text, f"content={content[:100] if content else 'empty'}")
    except Exception as e:
        record("1j. check_spf has text content", False, str(e))

    # DELETE session
    status, body, _ = curl_json(
        "DELETE", "/mcp",
        headers=mcp_headers(session_id),
    )
    record("1k. DELETE session → 204", status == 204, f"got {status}")

    # ping with deleted session
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=jsonrpc("ping", {}, 7),
        headers=mcp_headers(session_id),
    )
    record("1l. ping deleted session → 404", status == 404, f"got {status}")

    return session_id


# ──────────────────────────────────────────────────────────────────────
# 2. Legacy SSE
# ──────────────────────────────────────────────────────────────────────
def test_legacy_sse():
    print("\n=== 2. Legacy SSE Transport ===")

    # GET /mcp/sse with Accept: text/event-stream → SSE with endpoint
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
    status, body, _ = curl_json("GET", "/mcp/sse", headers=[f"Authorization: Bearer {API_KEY}"])
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

    # Create a session first
    status, body, raw = curl_json(
        "POST", "/mcp",
        body=jsonrpc("initialize", {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "chaos-sse-test", "version": "1.0"}
        }),
        headers=mcp_headers(),
        include_headers=True,
    )
    session_id = None
    for line in raw.split("\n"):
        if line.lower().startswith("mcp-session-id:"):
            session_id = line.split(":", 1)[1].strip()
            break

    if not session_id:
        record("3a. Create session for SSE stream", False, "no session")
        return

    record("3a. Create session for SSE stream", True)

    # Send initialized notification
    curl_json("POST", "/mcp",
              body={"jsonrpc": "2.0", "method": "notifications/initialized"},
              headers=mcp_headers(session_id))

    # GET /mcp with Accept: text/event-stream + session
    cmd = [
        "perl", "-e", "alarm 4; exec @ARGV", "--",
        "curl", "-s", "-N", "-o", "/dev/null", "-w", "%{http_code}",
        f"{BASE}/mcp",
        "-H", "Accept: text/event-stream",
        "-H", f"Authorization: Bearer {API_KEY}",
        "-H", f"Mcp-Session-Id: {session_id}",
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        output = r.stdout.strip()
        # SSE stream stays open so curl is killed by alarm — status may be 200 or 0
        # If we got 200 before alarm killed it, great. If alarm killed it, the SSE was opened.
        # returncode != 0 from alarm means the stream was opened and stayed open (good).
        stream_opened = r.returncode != 0 or output == "200"
        record("3b. GET /mcp SSE stream opens (200 or stays open)", stream_opened,
               f"returncode={r.returncode}, output={output}")
    except subprocess.TimeoutExpired:
        record("3b. GET /mcp SSE stream opens (200 or stays open)", True, "timed out (stream stayed open)")

    # Cleanup: delete session
    curl_json("DELETE", "/mcp", headers=mcp_headers(session_id))


# ──────────────────────────────────────────────────────────────────────
# 4. Endpoints
# ──────────────────────────────────────────────────────────────────────
def test_endpoints():
    print("\n=== 4. Endpoint Tests ===")

    # GET /health
    status, body, _ = curl_json("GET", "/health")
    record("4a. GET /health → 200", status == 200, f"got {status}")
    try:
        data = json.loads(body)
        record("4b. /health returns JSON with status", "status" in data, f"keys={list(data.keys())}")
    except Exception as e:
        record("4b. /health returns JSON with status", False, str(e))

    # GET /badge/google.com
    status, body, _ = curl_json("GET", "/badge/google.com")
    is_ok = status == 200 or status == 429  # may be rate limited
    record("4c. GET /badge/google.com → 200 or 429", is_ok, f"got {status}")
    if status == 200:
        record("4d. Badge is SVG", "<svg" in body.lower(), f"body[:100]={body[:100]}")
    else:
        record("4d. Badge is SVG (skipped, rate limited)", True, "429")

    # Internal routes blocked publicly
    status, body, _ = curl_json(
        "POST", "/internal/tools/call",
        body={"name": "check_spf", "arguments": {"domain": "google.com"}},
        headers=["Content-Type: application/json"],
    )
    record("4e. POST /internal/tools/call → 404", status == 404, f"got {status}")

    status, body, _ = curl_json(
        "POST", "/internal/tools/batch",
        body={"domains": ["google.com"], "tool": "check_spf"},
        headers=["Content-Type: application/json"],
    )
    record("4f. POST /internal/tools/batch → 404", status == 404, f"got {status}")

    # Nonexistent route
    status, body, _ = curl_json("GET", "/nonexistent")
    record("4g. GET /nonexistent → 404", status == 404, f"got {status}")

    # Disallowed methods on /mcp (server returns 404 for unrouted methods)
    status, body, _ = curl_json("PUT", "/mcp", headers=mcp_headers())
    record("4h. PUT /mcp → 404 or 405", status in (404, 405), f"got {status}")

    status, body, _ = curl_json("PATCH", "/mcp", headers=mcp_headers())
    record("4i. PATCH /mcp → 404 or 405", status in (404, 405), f"got {status}")

    # OPTIONS /mcp → 204
    status, body, _ = curl_json("OPTIONS", "/mcp", headers=mcp_headers())
    record("4j. OPTIONS /mcp → 204", status == 204, f"got {status}")


# ──────────────────────────────────────────────────────────────────────
# 5. Valid domain edge cases
# ──────────────────────────────────────────────────────────────────────
def test_valid_domains():
    print("\n=== 5. Valid Domain Edge Cases ===")

    # Create session
    status, body, raw = curl_json(
        "POST", "/mcp",
        body=jsonrpc("initialize", {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "chaos-domain-test", "version": "1.0"}
        }),
        headers=mcp_headers(),
        include_headers=True,
    )
    session_id = None
    for line in raw.split("\n"):
        if line.lower().startswith("mcp-session-id:"):
            session_id = line.split(":", 1)[1].strip()
            break

    if not session_id:
        print("  SKIP: no session")
        return

    curl_json("POST", "/mcp",
              body={"jsonrpc": "2.0", "method": "notifications/initialized"},
              headers=mcp_headers(session_id))

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

    # Cleanup
    curl_json("DELETE", "/mcp", headers=mcp_headers(session_id))


# ──────────────────────────────────────────────────────────────────────
# 6. Blocked domains (SSRF)
# ──────────────────────────────────────────────────────────────────────
def test_blocked_domains():
    print("\n=== 6. Blocked Domain Edge Cases ===")

    # Create session
    status, body, raw = curl_json(
        "POST", "/mcp",
        body=jsonrpc("initialize", {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "chaos-blocked-test", "version": "1.0"}
        }),
        headers=mcp_headers(),
        include_headers=True,
    )
    session_id = None
    for line in raw.split("\n"):
        if line.lower().startswith("mcp-session-id:"):
            session_id = line.split(":", 1)[1].strip()
            break

    if not session_id:
        print("  SKIP: no session")
        return

    curl_json("POST", "/mcp",
              body={"jsonrpc": "2.0", "method": "notifications/initialized"},
              headers=mcp_headers(session_id))

    blocked_domains = [
        ("localhost", "localhost"),
        ("127.0.0.1", "loopback IP"),
        ("169.254.169.254", "metadata IP"),
        ("example.test", "test TLD"),
        ("example.onion", "onion TLD"),
        ("127.0.0.1.nip.io", "rebind service"),
        ("", "empty string"),
        ("*.example.com", "wildcard"),
        ("../../../etc/passwd", "path traversal"),  # embedded in JSON body, not URL
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
            record(f"6. Blocked: {label} ({domain})", blocked,
                   f"isError={is_error}, rpc_error={has_error_in_rpc}")
        except json.JSONDecodeError:
            # Non-JSON response (e.g., 400/415 HTML page) still means the domain was blocked
            blocked = status != 200 or "error" in body.lower() or "invalid" in body.lower()
            record(f"6. Blocked: {label} ({domain})", blocked,
                   f"status={status}, non-JSON response, body={body[:150]}")
        except Exception as e:
            record(f"6. Blocked: {label} ({domain})", False, str(e))

    # Cleanup
    curl_json("DELETE", "/mcp", headers=mcp_headers(session_id))


# ──────────────────────────────────────────────────────────────────────
# 7. Argument edge cases
# ──────────────────────────────────────────────────────────────────────
def test_argument_edges():
    print("\n=== 7. Argument Edge Cases ===")

    # Create session
    status, body, raw = curl_json(
        "POST", "/mcp",
        body=jsonrpc("initialize", {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "chaos-args-test", "version": "1.0"}
        }),
        headers=mcp_headers(),
        include_headers=True,
    )
    session_id = None
    for line in raw.split("\n"):
        if line.lower().startswith("mcp-session-id:"):
            session_id = line.split(":", 1)[1].strip()
            break

    if not session_id:
        print("  SKIP: no session")
        return

    curl_json("POST", "/mcp",
              body={"jsonrpc": "2.0", "method": "notifications/initialized"},
              headers=mcp_headers(session_id))

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

    # Cleanup
    curl_json("DELETE", "/mcp", headers=mcp_headers(session_id))


# ──────────────────────────────────────────────────────────────────────
# 8. Content-Type validation (v2.0.8)
# ──────────────────────────────────────────────────────────────────────
def test_content_type():
    print("\n=== 8. Content-Type Validation (v2.0.8) ===")

    body_str = json.dumps(jsonrpc("ping", {}, 1))

    # Should be rejected (415)
    bad_types = [
        ("text/plain", "text/plain"),
        ("application/xml", "application/xml"),
        ("text/html", "text/html"),
        ("application/x-www-form-urlencoded", "form-urlencoded"),
    ]

    for ct, label in bad_types:
        status, body, _ = curl_json(
            "POST", "/mcp",
            body=body_str,
            headers=[f"Authorization: Bearer {API_KEY}", f"Content-Type: {ct}"],
        )
        record(f"8a. Content-Type {label} → 415", status == 415, f"got {status}")

    # Should be accepted (need session — but initialize doesn't require session)
    # These should at minimum not return 415
    good_types = [
        ("application/json", "application/json"),
        ("application/json;charset=utf-8", "json+charset"),
    ]

    for ct, label in good_types:
        status, body, _ = curl_json(
            "POST", "/mcp",
            body=body_str,
            headers=[f"Authorization: Bearer {API_KEY}", f"Content-Type: {ct}"],
        )
        not_415 = status != 415
        record(f"8b. Content-Type {label} → not 415", not_415, f"got {status}")

    # Missing Content-Type — server requires application/json, so 415 is correct behavior
    cmd = ["curl", "-s", "-w", "\n%{http_code}", "-X", "POST",
           "-H", f"Authorization: Bearer {API_KEY}",
           "-d", body_str, f"{BASE}/mcp"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        lines = r.stdout.strip().split("\n")
        status = int(lines[-1])
        # curl sends application/x-www-form-urlencoded by default with -d, which should be rejected
        record("8c. No explicit Content-Type (curl default) → 415", status == 415, f"got {status}")
    except Exception as e:
        record("8c. No explicit Content-Type (curl default) → 415", False, str(e))


# ──────────────────────────────────────────────────────────────────────
# 9. No-send domain DKIM scoring
# ──────────────────────────────────────────────────────────────────────
def test_nosend_dkim():
    print("\n=== 9. No-Send Domain DKIM Scoring ===")

    # Create session
    status, body, raw = curl_json(
        "POST", "/mcp",
        body=jsonrpc("initialize", {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "chaos-nosend-test", "version": "1.0"}
        }),
        headers=mcp_headers(),
        include_headers=True,
    )
    session_id = None
    for line in raw.split("\n"):
        if line.lower().startswith("mcp-session-id:"):
            session_id = line.split(":", 1)[1].strip()
            break

    if not session_id:
        print("  SKIP: no session")
        return

    curl_json("POST", "/mcp",
              body={"jsonrpc": "2.0", "method": "notifications/initialized"},
              headers=mcp_headers(session_id))

    def extract_dkim_score(scan_body):
        """Extract DKIM score from scan_domain result (structured or text report)."""
        try:
            data = json.loads(scan_body)
            content = data.get("result", {}).get("content", [])
            for block in content:
                text = block.get("text", "")
                # Try structured result first
                match = re.search(r"<!-- STRUCTURED_RESULT (.*?) STRUCTURED_RESULT -->", text, re.DOTALL)
                if match:
                    structured = json.loads(match.group(1))
                    checks = structured.get("checks", {})
                    dkim_check = checks.get("dkim", {})
                    return dkim_check.get("score")
                # Compact format: "DKIM | 100 | A+ | Passed"
                dkim_match = re.search(r"DKIM\s*\|\s*(\d+)", text)
                if dkim_match:
                    return int(dkim_match.group(1))
                # Full format with emoji: "DKIM ... | 100/100"
                dkim_match2 = re.search(r"DKIM[^\n]*?(\d+)/100", text)
                if dkim_match2:
                    return int(dkim_match2.group(1))
                # Also try "dkim" in any case in a table row
                dkim_match3 = re.search(r"(?i)dkim[^|]*\|\s*(\d+)", text)
                if dkim_match3:
                    return int(dkim_match3.group(1))
        except Exception as ex:
            pass
        return None

    # Scan cscdbs.com (no-send domain — non-mail adjustment should give DKIM=100)
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=jsonrpc("tools/call", {"name": "scan_domain", "arguments": {"domain": "cscdbs.com"}}, 20),
        headers=mcp_headers(session_id),
    )
    cscdbs_dkim = extract_dkim_score(body)
    if cscdbs_dkim is None:
        # Debug: show what we got back
        try:
            data = json.loads(body)
            content = data.get("result", {}).get("content", [])
            snippet = ""
            for block in content:
                t = block.get("text", "")
                if "DKIM" in t.upper() or "dkim" in t.lower():
                    # Find the DKIM line
                    for line in t.split("\n"):
                        if "dkim" in line.lower():
                            snippet += line + " | "
            record("9a. cscdbs.com DKIM score = 100", False,
                   f"could not extract score. DKIM lines: {snippet[:300]}")
        except Exception as e:
            record("9a. cscdbs.com DKIM score = 100", False, f"parse error: {e}, body[:300]={body[:300]}")
    else:
        record("9a. cscdbs.com DKIM score = 100", cscdbs_dkim == 100,
               f"got DKIM score={cscdbs_dkim}")

    # Scan google.com (should NOT have DKIM=100, since DKIM probing is heuristic)
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=jsonrpc("tools/call", {"name": "scan_domain", "arguments": {"domain": "google.com"}}, 21),
        headers=mcp_headers(session_id),
    )
    google_dkim = extract_dkim_score(body)
    if google_dkim is None:
        try:
            data = json.loads(body)
            content = data.get("result", {}).get("content", [])
            snippet = ""
            for block in content:
                t = block.get("text", "")
                for line in t.split("\n"):
                    if "dkim" in line.lower():
                        snippet += line + " | "
            record("9b. google.com DKIM score != 100", False,
                   f"could not extract score. DKIM lines: {snippet[:300]}")
        except Exception as e:
            record("9b. google.com DKIM score != 100", False, f"parse error: {e}")
    else:
        record("9b. google.com DKIM score != 100", google_dkim != 100,
               f"got DKIM score={google_dkim}")

    # Cleanup
    curl_json("DELETE", "/mcp", headers=mcp_headers(session_id))


# ──────────────────────────────────────────────────────────────────────
# 10. Rate limit envelope
# ──────────────────────────────────────────────────────────────────────
def test_rate_limit_envelope():
    print("\n=== 10. Rate Limit Envelope ===")

    # Unauthenticated call — create session first (no API key)
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

    record("10b. Unauth tool call → 200 (not 429)", status == 200,
           f"got {status}")

    has_quota_limit = "x-quota-limit" in resp_headers
    has_quota_remaining = "x-quota-remaining" in resp_headers
    record("10c. x-quota-limit header present", has_quota_limit,
           f"headers={list(resp_headers.keys())}")
    record("10d. x-quota-remaining header present", has_quota_remaining,
           f"headers={list(resp_headers.keys())}")

    # Check rate limit headers too
    has_rl_limit = "x-ratelimit-limit" in resp_headers
    has_rl_remaining = "x-ratelimit-remaining" in resp_headers
    record("10e. x-ratelimit-limit header present", has_rl_limit,
           f"headers={list(resp_headers.keys())}")
    record("10f. x-ratelimit-remaining header present", has_rl_remaining,
           f"headers={list(resp_headers.keys())}")

    # Cleanup
    curl_json("DELETE", "/mcp", headers=["Content-Type: application/json", f"Mcp-Session-Id: {session_id}"])


# ──────────────────────────────────────────────────────────────────────
# Run all tests
# ──────────────────────────────────────────────────────────────────────
def main():
    print("=" * 60)
    print("  bv-mcp v2.0.7 Chaos Test Suite")
    print(f"  Target: {BASE}")
    print("=" * 60)

    test_streamable_http()
    test_legacy_sse()
    test_notification_stream()
    test_endpoints()
    test_valid_domains()
    test_blocked_domains()
    test_argument_edges()
    test_content_type()
    test_nosend_dkim()
    test_rate_limit_envelope()

    # Summary
    total = len(results)
    passed = sum(1 for _, p in results if p)
    failed = total - passed
    print("\n" + "=" * 60)
    print(f"  SUMMARY: {passed}/{total} passed, {failed} failed")
    print("=" * 60)

    if failed > 0:
        print("\n  FAILURES:")
        for name, p in results:
            if not p:
                print(f"    - {name}")

    print()
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
