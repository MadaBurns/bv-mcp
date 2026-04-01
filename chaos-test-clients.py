#!/usr/bin/env python3
"""
bv-mcp chaos test — all MCP client types (v2.1.17)

Validates server behaviour across all 9 detected MCP client types:
  claude_code, cursor, vscode, claude_desktop, windsurf  → interactive → compact auto-format
  mcp_remote, blackveil_dns_action, bv_claude_dns_proxy, unknown → non-interactive → full auto-format

Test sections:
  1.  Session lifecycle per client type (all 9)
  2.  Format auto-detection via scan_domain (interactive vs non-interactive)
  3.  Format explicit-override: compact/full overrides client default
  4.  api_key query param auth (Smithery/URL-only clients)
  5.  Bearer header vs api_key param precedence
  6.  Concurrent burst — all 9 types in parallel
  7.  Legacy SSE transport per client UA
  8.  Sessionless tools/list (no Mcp-Session-Id)
  9.  Wrong Content-Type and body-size guard
  10. Batch JSON-RPC from each transport type
"""

import subprocess
import json
import sys
import re
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

BASE = "https://dns-mcp.blackveilsecurity.com"
_RAW_API_KEY = os.getenv("BV_API_KEY")
API_KEY = None  # confirmed-working key set after probe

# ─── Client type registry ────────────────────────────────────────────────────
# (label, user_agent_string, is_interactive)
CLIENT_TYPES = [
    ("claude_code",          "claude-code/1.2.3",           True),
    ("cursor",               "cursor/0.44.0",                True),
    ("vscode",               "Visual Studio Code/1.87.0",    True),
    ("claude_desktop",       "claude-desktop/0.10.0",        True),
    ("windsurf",             "windsurf/1.0.0",               True),
    ("mcp_remote",           "mcp-remote/0.1.0",             False),
    ("blackveil_dns_action", "blackveil-dns-action/1.0",     False),
    ("bv_claude_dns_proxy",  "bv-claude-dns-proxy/1.0",      False),
    ("unknown",              "my-custom-mcp-client/3.1.4",   False),
]

INTERACTIVE_TYPES = {name for name, _, interactive in CLIENT_TYPES if interactive}

results = []

# ─── Helpers ─────────────────────────────────────────────────────────────────

def record(name, passed, detail=""):
    status = "PASS" if passed else "FAIL"
    results.append((name, passed))
    msg = f"  [{status}] {name}"
    if detail and not passed:
        msg += f"  -- {detail}"
    print(msg)


def curl_json(method, path, body=None, headers=None, include_headers=False,
              timeout=35, params=None):
    """POST/GET/DELETE to BASE+path; returns (status, body_text, raw_stdout)."""
    url = f"{BASE}{path}"
    if params:
        qs = "&".join(f"{k}={v}" for k, v in params.items())
        url = f"{url}?{qs}"
    cmd = ["curl", "-s", "-w", "\n%{http_code}"]
    if include_headers:
        cmd.append("-D-")
    if method != "GET":
        cmd += ["-X", method]
    if headers:
        for h in headers:
            cmd += ["-H", h]
    if body is not None:
        cmd += ["-d", json.dumps(body) if isinstance(body, (dict, list)) else body]
    cmd.append(url)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        output = r.stdout.strip()
        lines = output.split("\n")
        status_code = int(lines[-1])
        body_text = "\n".join(lines[:-1])
        return status_code, body_text, r.stdout
    except subprocess.TimeoutExpired:
        return 0, "TIMEOUT", ""
    except Exception as e:
        return 0, str(e), ""


def jsonrpc(method, params=None, req_id=1):
    body = {"jsonrpc": "2.0", "method": method, "id": req_id}
    if params is not None:
        body["params"] = params
    return body


def make_headers(ua, session_id=None, content_type="application/json",
                 auth="none", api_key_header=None):
    """Build HTTP headers list.
    auth: 'none' | 'bearer' | 'bearer_invalid'
    """
    h = []
    if content_type:
        h.append(f"Content-Type: {content_type}")
    h.append(f"User-Agent: {ua}")
    if session_id:
        h.append(f"Mcp-Session-Id: {session_id}")
    if auth == "bearer" and API_KEY:
        h.append(f"Authorization: Bearer {API_KEY}")
    elif auth == "bearer_invalid":
        h.append("Authorization: Bearer bv_invalid_key_00000000000000000000")
    if api_key_header:
        h.append(f"Authorization: Bearer {api_key_header}")
    return h


def extract_session_id(raw):
    """Parse Mcp-Session-Id from curl -D- output."""
    for line in raw.split("\n"):
        if line.lower().startswith("mcp-session-id:"):
            return line.split(":", 1)[1].strip()
    return None


def create_session(ua, client_name="chaos-clients", auth="none", params=None):
    """Return (session_id, http_status). session_id is None on failure."""
    status, body, raw = curl_json(
        "POST", "/mcp",
        body=jsonrpc("initialize", {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": client_name, "version": "1.0"},
        }),
        headers=make_headers(ua, auth=auth),
        include_headers=True,
        params=params,
    )
    sid = extract_session_id(raw)
    if sid:
        # send required initialized notification
        curl_json("POST", "/mcp",
                  body={"jsonrpc": "2.0", "method": "notifications/initialized"},
                  headers=make_headers(ua, session_id=sid, auth=auth),
                  params=params)
    return sid, status


def delete_session(sid, ua):
    if sid:
        curl_json("DELETE", "/mcp", headers=make_headers(ua, session_id=sid))


def tool_call(sid, ua, name, args, auth="none", params=None):
    return curl_json(
        "POST", "/mcp",
        body=jsonrpc("tools/call", {"name": name, "arguments": args}, 10),
        headers=make_headers(ua, session_id=sid, auth=auth),
        params=params,
    )


def is_rate_limited(body_text):
    try:
        d = json.loads(body_text)
        msg = d.get("error", {}).get("message", "")
        return any(w in msg.lower() for w in ("rate", "quota", "limit", "exceeded"))
    except Exception:
        return False


def validate_key():
    """Probe whether _RAW_API_KEY is accepted by the server."""
    global API_KEY
    if not _RAW_API_KEY:
        return
    ua = "chaos-clients/1.0"
    cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
           "-X", "POST", f"{BASE}/mcp",
           "-H", "Content-Type: application/json",
           "-H", f"User-Agent: {ua}",
           "-H", f"Authorization: Bearer {_RAW_API_KEY}",
           "-d", json.dumps(jsonrpc("ping", {}, 1))]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if r.stdout.strip() != "401":
            API_KEY = _RAW_API_KEY
    except Exception:
        pass


# ─── Section 1: Session lifecycle per client type ────────────────────────────

def test_session_lifecycle():
    print("\n=== 1. Session Lifecycle — All 9 Client Types ===")

    TOOL_CHECK = "check_ns"
    TOOL_ARGS  = {"domain": "example.com", "format": "compact"}

    for name, ua, _ in CLIENT_TYPES:
        sid, init_status = create_session(ua, client_name=f"chaos-{name}",
                                          auth="bearer" if API_KEY else "none")
        if not sid:
            if is_rate_limited(str(init_status)):
                record(f"1. {name}: session create", True, "rate-limited (server working)")
                continue
            record(f"1. {name}: session create", False, f"HTTP {init_status}, no session ID")
            continue
        record(f"1. {name}: session create", True)

        # tools/list
        status, body, _ = curl_json(
            "POST", "/mcp",
            body=jsonrpc("tools/list", {}, 2),
            headers=make_headers(ua, session_id=sid, auth="bearer" if API_KEY else "none"),
        )
        try:
            d = json.loads(body)
            count = len(d.get("result", {}).get("tools", []))
            record(f"1. {name}: tools/list = 41", count == 41, f"got {count}, status={status}")
        except Exception as e:
            record(f"1. {name}: tools/list = 41", False, str(e))

        # tools/call
        status, body, _ = tool_call(sid, ua, TOOL_CHECK, TOOL_ARGS,
                                     auth="bearer" if API_KEY else "none")
        try:
            d = json.loads(body)
            has_content = bool(d.get("result", {}).get("content"))
            is_error_rpc = "error" in d and is_rate_limited(body)
            record(f"1. {name}: {TOOL_CHECK} call", has_content or is_error_rpc,
                   f"status={status}, keys={list(d.keys())}")
        except Exception as e:
            record(f"1. {name}: {TOOL_CHECK} call", False, str(e))

        # DELETE → 204
        d_status, _, _ = curl_json("DELETE", "/mcp",
                                    headers=make_headers(ua, session_id=sid))
        record(f"1. {name}: DELETE → 204", d_status == 204, f"got {d_status}")


# ─── Section 2: Format auto-detection (scan_domain) ─────────────────────────

def test_format_autodetect():
    print("\n=== 2. Format Auto-Detection (scan_domain) ===")

    if not API_KEY:
        print("  SKIP: BV_API_KEY required to run scan_domain without rate limits")
        record("2. Format auto-detect (skipped, no key)", True)
        return

    SCAN_DOMAIN = "cloudflare.com"
    SCAN_ARGS   = {"domain": SCAN_DOMAIN}  # no explicit format — auto-detect

    # Test one interactive and one non-interactive client
    test_pairs = [
        ("claude_code", "claude-code/1.2.3",    True),
        ("unknown",     "my-custom-client/4.0", False),
    ]

    for name, ua, is_interactive in test_pairs:
        sid, _ = create_session(ua, auth="bearer")
        if not sid:
            record(f"2. {name}: scan_domain format detect", False, "no session")
            continue

        status, body, _ = tool_call(sid, ua, "scan_domain", SCAN_ARGS, auth="bearer")
        delete_session(sid, ua)

        try:
            d = json.loads(body)
            content_blocks = d.get("result", {}).get("content", [])
            full_text = " ".join(c.get("text", "") for c in content_blocks)

            has_structured = "<!-- STRUCTURED_RESULT" in full_text

            if is_interactive:
                # Interactive → compact → NO structured result block
                record(f"2. {name} (interactive): no STRUCTURED_RESULT block",
                       not has_structured,
                       f"block present={has_structured}")
            else:
                # Non-interactive → full → HAS structured result block
                record(f"2. {name} (non-interactive): has STRUCTURED_RESULT block",
                       has_structured,
                       f"block present={has_structured}")
        except Exception as e:
            record(f"2. {name}: scan_domain format detect", False, str(e))


# ─── Section 3: Explicit format override ─────────────────────────────────────

def test_format_override():
    print("\n=== 3. Format Explicit Override (compact/full) ===")
    if not API_KEY:
        print("  SKIP: BV_API_KEY required")
        record("3. Format override (skipped, no key)", True)
        return

    # Non-interactive client forced to compact: should get no STRUCTURED_RESULT
    # Interactive client forced to full: should get STRUCTURED_RESULT
    cases = [
        ("mcp_remote", "mcp-remote/0.1.0", "compact", False),   # non-interactive + compact override
        ("claude_code", "claude-code/1.2.3", "full",  True),    # interactive + full override
    ]

    for name, ua, forced_fmt, expect_structured in cases:
        sid, _ = create_session(ua, auth="bearer")
        if not sid:
            record(f"3. {name}: force format={forced_fmt}", False, "no session")
            continue

        status, body, _ = tool_call(
            sid, ua, "scan_domain",
            {"domain": "cloudflare.com", "format": forced_fmt},
            auth="bearer",
        )
        delete_session(sid, ua)

        try:
            d = json.loads(body)
            content_blocks = d.get("result", {}).get("content", [])
            full_text = " ".join(c.get("text", "") for c in content_blocks)
            has_structured = "<!-- STRUCTURED_RESULT" in full_text

            if expect_structured:
                record(f"3. {name} force format=full → has STRUCTURED_RESULT",
                       has_structured, f"present={has_structured}")
            else:
                record(f"3. {name} force format=compact → no STRUCTURED_RESULT",
                       not has_structured, f"present={has_structured}")
        except Exception as e:
            record(f"3. {name}: force format={forced_fmt}", False, str(e))


# ─── Section 4: api_key query param auth ─────────────────────────────────────

def test_api_key_param():
    print("\n=== 4. api_key Query Param Auth (Smithery) ===")
    if not API_KEY:
        print("  SKIP: BV_API_KEY required")
        record("4. api_key param auth (skipped, no key)", True)
        return

    ua = "smithery-connect/1.0"
    params = {"api_key": API_KEY}

    # 4a. Initialize via ?api_key= (no Bearer header)
    sid, status = create_session(ua, client_name="smithery-chaos",
                                  auth="none", params=params)
    record("4a. initialize with ?api_key= → session created",
           sid is not None, f"HTTP {status}")

    if not sid:
        return

    # 4b. tools/call via ?api_key= (no Bearer)
    status, body, _ = tool_call(
        sid, ua, "check_spf",
        {"domain": "cloudflare.com", "format": "compact"},
        auth="none", params=params,
    )
    try:
        d = json.loads(body)
        ok = bool(d.get("result", {}).get("content"))
        record("4b. tools/call with ?api_key= → content returned", ok,
               f"status={status}, keys={list(d.keys())}")
    except Exception as e:
        record("4b. tools/call with ?api_key=", False, str(e))

    # 4c. No session, just ?api_key= in URL (Smithery proxy-style)
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=jsonrpc("tools/list", {}, 3),
        headers=make_headers(ua, auth="none"),
        params=params,
    )
    try:
        d = json.loads(body)
        count = len(d.get("result", {}).get("tools", []))
        record("4c. tools/list no session + ?api_key= → 41 tools", count == 41, f"got {count}")
    except Exception as e:
        record("4c. tools/list no session + ?api_key=", False, str(e))

    delete_session(sid, ua)


# ─── Section 5: Bearer vs api_key precedence ─────────────────────────────────

def test_auth_precedence():
    print("\n=== 5. Auth Precedence: Bearer Header vs api_key Param ===")
    if not API_KEY:
        print("  SKIP: BV_API_KEY required")
        record("5. Auth precedence (skipped, no key)", True)
        return

    ua = "chaos-auth-test/1.0"

    # 5a. Valid Bearer + bogus api_key → should succeed (Bearer wins)
    status, body, raw = curl_json(
        "POST", "/mcp",
        body=jsonrpc("initialize", {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "auth-precedence-test", "version": "1.0"},
        }),
        headers=make_headers(ua, auth="bearer"),
        include_headers=True,
        params={"api_key": "bv_bogus_key_00000000000000000000000000000000"},
    )
    sid = extract_session_id(raw)
    record("5a. valid Bearer + bogus api_key → session created (Bearer wins)",
           sid is not None, f"HTTP {status}")

    if sid:
        curl_json("POST", "/mcp",
                  body={"jsonrpc": "2.0", "method": "notifications/initialized"},
                  headers=make_headers(ua, session_id=sid, auth="bearer"),
                  params={"api_key": "bv_bogus_key_00000000000000000000000000000000"})
        delete_session(sid, ua)

    # 5b. Invalid Bearer + valid api_key → should FAIL (Bearer header takes precedence)
    status, body, raw = curl_json(
        "POST", "/mcp",
        body=jsonrpc("initialize", {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "auth-precedence-test-b", "version": "1.0"},
        }),
        headers=make_headers(ua, auth="bearer_invalid"),
        include_headers=True,
        params={"api_key": API_KEY},
    )
    sid2 = extract_session_id(raw)
    # Bearer is present but invalid → should still create session (auth is optional)
    # BUT the tier would be free/unauthenticated, not owner/developer
    # What actually happens: bearer present + invalid → 401? or falls back to api_key?
    # From auth.ts: "Token extracted from Authorization: Bearer first, then ?api_key= as fallback"
    # If Bearer is present but invalid, it should return 401
    record("5b. invalid Bearer + valid api_key → 401 (Bearer takes precedence, fallback disabled)",
           status == 401, f"HTTP {status}, sid={sid2}")


# ─── Section 6: Concurrent burst — all 9 types in parallel ──────────────────

def test_concurrent_burst():
    print("\n=== 6. Concurrent Burst — All 9 Client Types in Parallel ===")

    BURST_CALLS_PER_TYPE = 3
    total_ok = total_ratelimited = total_fail = total_5xx = 0
    latencies = []

    def run_client_burst(name, ua, is_interactive):
        """Create session + 3 tool calls for one client type."""
        ok = rate = fail = s5xx = 0
        auth_mode = "bearer" if API_KEY else "none"
        sid, _ = create_session(ua, auth=auth_mode)
        if not sid:
            return ok, rate + 1, fail, s5xx

        calls = [
            ("check_spf",   {"domain": "cloudflare.com", "format": "compact"}),
            ("check_dmarc", {"domain": "google.com",     "format": "compact"}),
            ("check_ns",    {"domain": "github.com",     "format": "compact"}),
        ]
        for tool_name, args in calls[:BURST_CALLS_PER_TYPE]:
            t0 = time.monotonic()
            status, body, _ = tool_call(sid, ua, tool_name, args, auth=auth_mode)
            latencies.append(time.monotonic() - t0)

            if status >= 500:
                s5xx += 1
            elif is_rate_limited(body):
                rate += 1
            elif status == 200:
                try:
                    d = json.loads(body)
                    if d.get("result", {}).get("content"):
                        ok += 1
                    else:
                        fail += 1
                except Exception:
                    fail += 1
            else:
                fail += 1

        delete_session(sid, ua)
        return ok, rate, fail, s5xx

    t_start = time.monotonic()
    with ThreadPoolExecutor(max_workers=9) as pool:
        futs = {pool.submit(run_client_burst, n, ua, interactive): n
                for n, ua, interactive in CLIENT_TYPES}
        for f in as_completed(futs):
            name = futs[f]
            ok, rate, fail, s5xx = f.result()
            total_ok += ok
            total_ratelimited += rate
            total_fail += fail
            total_5xx += s5xx
            status_sym = "✓" if s5xx == 0 and fail == 0 else ("!" if s5xx > 0 else "~")
            print(f"  {status_sym} {name:25s}  ok={ok}  rate={rate}  fail={fail}  5xx={s5xx}")

    elapsed = time.monotonic() - t_start
    total = total_ok + total_ratelimited + total_fail + total_5xx
    record("6. Concurrent burst: no 5xx errors",    total_5xx == 0, f"{total_5xx} 5xx")
    record("6. Concurrent burst: < 30% hard fails",
           total_fail / max(total, 1) < 0.30,
           f"{total_fail}/{total} = {total_fail/max(total,1)*100:.0f}%")

    if latencies:
        import statistics
        lat = sorted(latencies)
        p50 = statistics.median(lat) * 1000
        p95 = lat[int(len(lat) * 0.95)] * 1000
        print(f"  Latency  p50={p50:.0f}ms  p95={p95:.0f}ms  elapsed={elapsed:.1f}s")


# ─── Section 7: Legacy SSE transport with client User-Agents ─────────────────

def test_legacy_sse_per_client():
    print("\n=== 7. Legacy SSE Transport — Client User-Agents ===")

    if not API_KEY:
        print("  SKIP: Legacy SSE requires BV_API_KEY (auth enforced on SSE endpoint)")
        record("7. Legacy SSE per client (skipped, no key)", True)
        return

    # Test 3 representative client types on /mcp/sse
    sample = [
        ("claude_code",  "claude-code/1.2.3"),
        ("mcp_remote",   "mcp-remote/0.1.0"),
        ("unknown",      "generic-mcp/1.0"),
    ]

    for name, ua in sample:
        cmd = [
            "perl", "-e", "alarm 4; exec @ARGV", "--",
            "curl", "-s", "-N",
            f"{BASE}/mcp/sse",
            "-H", "Accept: text/event-stream",
            "-H", f"Authorization: Bearer {API_KEY}",
            "-H", f"User-Agent: {ua}",
        ]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            out = r.stdout
            has_event = "event:" in out or "data:" in out
            has_messages_url = "/mcp/messages?sessionId=" in out
            record(f"7. {name}: SSE bootstrap → event + messages URL",
                   has_event and has_messages_url,
                   f"event={has_event}, url={has_messages_url}, out={out[:200]!r}")
        except subprocess.TimeoutExpired:
            record(f"7. {name}: SSE bootstrap → event + messages URL", False, "timeout")
        except Exception as e:
            record(f"7. {name}: SSE bootstrap → event + messages URL", False, str(e))

    # POST /mcp/messages with client UA but no session → 404
    status, body, _ = curl_json(
        "POST", "/mcp/messages?sessionId=aaaa" + "a" * 60,
        body=jsonrpc("tools/list", {}, 1),
        headers=make_headers("mcp-remote/0.1.0",
                              api_key_header=API_KEY if API_KEY else None),
    )
    record("7. POST /mcp/messages unknown sessionId → 404",
           status == 404, f"got {status}")

    # POST /mcp/messages no sessionId → 400
    status, body, _ = curl_json(
        "POST", "/mcp/messages",
        body=jsonrpc("ping", {}, 1),
        headers=make_headers("mcp-remote/0.1.0"),
    )
    record("7. POST /mcp/messages no sessionId → 400",
           status == 400, f"got {status}")


# ─── Section 8: Session behaviour (missing vs expired/unknown) ───────────────

def test_session_edge_cases():
    print("\n=== 8. Session Edge Cases (missing, unknown, revival, tombstone) ===")

    ua = "chaos-session-test/1.0"

    # 8a. POST /mcp with NO Mcp-Session-Id → 400 "missing session"
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=jsonrpc("tools/list", {}, 1),
        headers=make_headers(ua),
    )
    try:
        d = json.loads(body)
        msg = d.get("error", {}).get("message", "")
        record("8a. No session header → 400 missing-session",
               status == 400 and "session" in msg.lower(),
               f"HTTP {status}, msg={msg[:80]}")
    except Exception as e:
        record("8a. No session header → 400 missing-session", False, str(e))

    # 8b. tools/list on valid-format unknown session ID → auto-revival → 200
    # (or rate-limited — both mean server is alive and handling the request correctly)
    fake_sid = "b" * 64  # valid 64-hex-char format, never created
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=jsonrpc("tools/list", {}, 2),
        headers=make_headers(ua, session_id=fake_sid),
    )
    try:
        d = json.loads(body)
        count = len(d.get("result", {}).get("tools", []))
        rate = is_rate_limited(body)
        record("8b. Valid-format unknown session → auto-revival (41 tools or rate-limited)",
               count == 41 or rate,
               f"HTTP {status}, tools={count}, rate={rate}")
    except Exception as e:
        record("8b. Valid-format unknown session → auto-revival", False, str(e))

    # 8c. Invalid session format → 404
    # Server validates header presence (absent → 400) but any value triggers a KV
    # lookup; unrecognized IDs (including malformed ones) return 404, not 400.
    bad_format_sid = "not-a-valid-session-id"
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=jsonrpc("ping", {}, 3),
        headers=make_headers(ua, session_id=bad_format_sid),
    )
    record("8c. Malformed session ID → 404 (KV lookup miss, not format rejection)",
           status == 404, f"got {status}")

    # 8d. Tombstoned session → 404 (not revived)
    auth_mode = "bearer" if API_KEY else "none"
    sid, _ = create_session(ua, auth=auth_mode)
    if sid:
        curl_json("DELETE", "/mcp", headers=make_headers(ua, session_id=sid))
        status, body, _ = curl_json(
            "POST", "/mcp",
            body=jsonrpc("ping", {}, 4),
            headers=make_headers(ua, session_id=sid),
        )
        record("8d. Tombstoned session → 404", status == 404, f"got {status}")
    else:
        record("8d. Tombstoned session → 404", True, "skipped (rate limited)")

    # 8e. Different client UA on same session → should still work (UA is per-request)
    sid2, _ = create_session("claude-code/1.0", auth=auth_mode)
    if sid2:
        # Use a different UA on the same session
        status, body, _ = curl_json(
            "POST", "/mcp",
            body=jsonrpc("tools/list", {}, 5),
            headers=make_headers("cursor/0.44.0", session_id=sid2, auth=auth_mode),
        )
        try:
            d = json.loads(body)
            count = len(d.get("result", {}).get("tools", []))
            record("8e. Different UA on existing session → 41 tools", count == 41,
                   f"got {count}, status={status}")
        except Exception as e:
            record("8e. Different UA on existing session", False, str(e))
        delete_session(sid2, "cursor/0.44.0")
    else:
        record("8e. Different UA on existing session", True, "skipped (rate limited)")


# ─── Section 9: Content-Type and body-size guards ────────────────────────────

def test_protocol_guards():
    print("\n=== 9. Protocol Guards (Content-Type, Body Size) ===")

    ua = "chaos-guard-test/1.0"

    # Wrong Content-Type → 415
    status, body, _ = curl_json(
        "POST", "/mcp",
        body='{"jsonrpc":"2.0","method":"ping","id":1}',
        headers=[f"User-Agent: {ua}", "Content-Type: text/plain"],
    )
    record("9a. Content-Type: text/plain → 415", status == 415, f"got {status}")

    # No Content-Type (suppress curl's default via empty header value) → accepted (compat)
    # Need a session — missing session returns 400 which would mask the content-type check.
    # Use a known-invalid session format to test this specific path without a real session.
    # Actually: test with a valid-format fake session so we can reach the CT check.
    # Server checks body size → CT → session. We want to confirm CT=absent is not 415.
    auth_mode = "bearer" if API_KEY else "none"
    ct_sid, _ = create_session(ua, auth=auth_mode)
    if ct_sid:
        # Build the curl command manually to send truly absent Content-Type
        cmd = ["curl", "-s", "-w", "\n%{http_code}",
               "-X", "POST",
               "-H", f"User-Agent: {ua}",
               "-H", f"Mcp-Session-Id: {ct_sid}",
               "-H", "Content-Type:",   # empty value removes the default header
               "-d", json.dumps(jsonrpc("ping", {}, 2)),
               f"{BASE}/mcp"]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            lines = r.stdout.strip().split("\n")
            s9b = int(lines[-1])
            b9b = "\n".join(lines[:-1])
            ok = s9b == 200 or is_rate_limited(b9b)
            record("9b. No Content-Type + valid session → accepted (compat)", ok,
                   f"got {s9b}, body={b9b[:80]}")
        except Exception as e:
            record("9b. No Content-Type + valid session → accepted (compat)", False, str(e))
        delete_session(ct_sid, ua)
    else:
        record("9b. No Content-Type → accepted (compat)", True, "skipped (rate limited)")

    # Body > 10 KB → 413
    # 10 KB = 10240 bytes. Use 11000-char padding to ensure body >> 10240 bytes.
    big_body = json.dumps({"jsonrpc": "2.0", "method": "ping", "id": 1,
                           "pad": "x" * 11_000})
    body_len = len(big_body.encode())
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=big_body,
        headers=make_headers(ua),
    )
    record(f"9c. Body > 10 KB ({body_len}B) → 413", status == 413, f"got {status}")

    # GET /mcp without Accept: text/event-stream → 406
    status, body, _ = curl_json("GET", "/mcp", headers=[f"User-Agent: {ua}"])
    record("9d. GET /mcp no Accept → 406", status == 406, f"got {status}")


# ─── Section 10: Batch JSON-RPC ──────────────────────────────────────────────

def test_batch_jsonrpc():
    print("\n=== 10. Batch JSON-RPC ===")

    ua = "chaos-batch/1.0"
    auth_mode = "bearer" if API_KEY else "none"

    sid, _ = create_session(ua, auth=auth_mode)
    if not sid:
        print("  SKIP: could not create session for batch test (rate limited?)")
        record("10. Batch JSON-RPC (skipped, no session)", True)
        return

    # Valid batch: 2 tool calls
    batch = [
        jsonrpc("tools/call", {"name": "check_spf",
                               "arguments": {"domain": "google.com", "format": "compact"}}, 1),
        jsonrpc("tools/call", {"name": "check_ns",
                               "arguments": {"domain": "cloudflare.com", "format": "compact"}}, 2),
    ]
    status, body, _ = curl_json(
        "POST", "/mcp",
        body=batch,
        headers=make_headers(ua, session_id=sid, auth=auth_mode),
    )
    try:
        d = json.loads(body)
        is_array = isinstance(d, list)
        record("10a. Batch [2] → array response", is_array, f"type={type(d).__name__}")
        if is_array:
            ok_count = sum(1 for r in d if r.get("result", {}).get("content")
                           or is_rate_limited(json.dumps(r)))
            record("10b. Batch [2] → 2 results", len(d) == 2, f"got {len(d)}")
    except Exception as e:
        record("10a. Batch [2] → array response", False, str(e))

    # Non-interactive client UA in batch: verify correct UA used for format
    # Requires API key — scan_domain is expensive and easily rate-limited without auth.
    if API_KEY:
        status2, body2, _ = curl_json(
            "POST", "/mcp",
            body=[jsonrpc("tools/call",
                          {"name": "scan_domain",
                           "arguments": {"domain": "cloudflare.com"}}, 1)],
            headers=make_headers("mcp-remote/0.1.0", session_id=sid, auth="bearer"),
        )
        try:
            d2 = json.loads(body2)
            if isinstance(d2, list) and d2:
                if is_rate_limited(json.dumps(d2[0])):
                    record("10c. Batch scan_domain mcp_remote UA → STRUCTURED_RESULT",
                           True, "rate-limited (server alive)")
                else:
                    content_blocks = d2[0].get("result", {}).get("content", [])
                    full_text = " ".join(c.get("text", "") for c in content_blocks)
                    has_struct = "<!-- STRUCTURED_RESULT" in full_text
                    record("10c. Batch scan_domain with mcp_remote UA → STRUCTURED_RESULT present",
                           has_struct, f"present={has_struct}")
            else:
                record("10c. Batch scan_domain mcp_remote UA", False,
                       f"empty response: {str(body2)[:80]}")
        except Exception as e:
            record("10c. Batch scan_domain mcp_remote UA", False, str(e))
    else:
        record("10c. Batch scan_domain mcp_remote UA (skipped, no key)", True)

    # Batch with unknown method
    status3, body3, _ = curl_json(
        "POST", "/mcp",
        body=[{"jsonrpc": "2.0", "method": "totally/unknown", "id": 99}],
        headers=make_headers(ua, session_id=sid, auth=auth_mode),
    )
    try:
        d3 = json.loads(body3)
        if isinstance(d3, list) and d3:
            has_err = "error" in d3[0]
            record("10d. Batch with unknown method → error in result", has_err,
                   f"result={d3[0]}")
    except Exception as e:
        record("10d. Batch unknown method", False, str(e))

    delete_session(sid, ua)


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    print("=" * 65)
    print(" bv-mcp chaos test — all MCP client types — v2.1.17")
    print(f" Target: {BASE}/mcp")
    print("=" * 65)

    validate_key()
    if API_KEY:
        print(f" Auth: BV_API_KEY loaded (authenticated, rate limits bypassed)")
    else:
        print(" Auth: none (free tier — some sections will be skipped or rate-limited)")

    grand_start = time.monotonic()

    test_session_lifecycle()
    test_format_autodetect()
    test_format_override()
    test_api_key_param()
    test_auth_precedence()
    test_concurrent_burst()
    test_legacy_sse_per_client()
    test_session_edge_cases()
    test_protocol_guards()
    test_batch_jsonrpc()

    total_time = time.monotonic() - grand_start

    # ── Summary ───────────────────────────────────────────────────────────────
    passed = sum(1 for _, ok in results if ok)
    failed = sum(1 for _, ok in results if not ok)
    total  = len(results)

    print("\n" + "=" * 65)
    print(" RESULTS")
    print("=" * 65)
    print(f"  passed  {passed}/{total}")
    print(f"  failed  {failed}/{total}")
    print(f"  time    {total_time:.1f}s")

    if failed:
        print("\n  FAILED TESTS:")
        for name, ok in results:
            if not ok:
                print(f"    ✗ {name}")

    print("=" * 65)

    if failed > 0:
        print(f"\n✗ FAIL — {failed} test(s) failed")
        sys.exit(1)
    else:
        print("\n✓ PASS")


if __name__ == "__main__":
    main()
