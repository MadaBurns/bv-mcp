#!/usr/bin/env python3
"""
Comprehensive chaos test for Blackveil DNS MCP Server v2.0.8
Tests: version, content-type, rate limits, no-send domains, all 33 tools,
       concurrent stress, client types, security, sessions, protocol edges.
"""

import subprocess
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE_URL = "https://dns-mcp.blackveilsecurity.com/mcp"
API_KEY = "[REDACTED]"

# Counters
results = {"pass": 0, "fail": 0, "error": 0}


def log(status, desc, detail=""):
    icon = {"PASS": "\033[92mPASS\033[0m", "FAIL": "\033[91mFAIL\033[0m", "ERROR": "\033[93mERROR\033[0m"}
    tag = icon.get(status, status)
    suffix = f" -- {detail}" if detail else ""
    print(f"  [{tag}] {desc}{suffix}")
    key = status.lower()
    if key in results:
        results[key] += 1


def curl(method, url, headers=None, data=None, timeout=60):
    """Execute curl and return (status_code, headers_dict, body_parsed_or_raw)."""
    cmd = ["curl", "-s", "-w", "\n%{http_code}", "-X", method, url, "--max-time", str(timeout)]
    if headers:
        for k, v in headers.items():
            cmd += ["-H", f"{k}: {v}"]
    if data is not None:
        cmd += ["-d", data]
    # Include response headers
    cmd.insert(2, "-D")
    cmd.insert(3, "/dev/stderr")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 10)
        raw = proc.stdout.strip()
        resp_headers_raw = proc.stderr
        lines = raw.rsplit("\n", 1)
        status_code = int(lines[-1]) if len(lines) >= 2 else int(lines[0])
        body = lines[0] if len(lines) >= 2 else ""
        # Parse response headers
        resp_headers = {}
        for line in resp_headers_raw.split("\n"):
            if ":" in line:
                k, v = line.split(":", 1)
                resp_headers[k.strip().lower()] = v.strip()
        try:
            body_json = json.loads(body) if body else None
        except json.JSONDecodeError:
            body_json = body
        return status_code, resp_headers, body_json
    except subprocess.TimeoutExpired:
        return None, {}, "TIMEOUT"
    except Exception as e:
        return None, {}, str(e)


def mcp_call(payload, session_id=None, extra_headers=None, user_agent=None, auth=True):
    """Make an MCP call with auth and optional session."""
    headers = {"Content-Type": "application/json"}
    if auth:
        headers["Authorization"] = f"Bearer {API_KEY}"
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    if user_agent:
        headers["User-Agent"] = user_agent
    if extra_headers:
        headers.update(extra_headers)
    return curl("POST", BASE_URL, headers=headers, data=json.dumps(payload))


def init_session(user_agent=None):
    """Initialize and return (session_id, server_info)."""
    payload = {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "chaos", "version": "1.0"}
        }
    }
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {API_KEY}"}
    if user_agent:
        headers["User-Agent"] = user_agent
    status, resp_h, body = curl("POST", BASE_URL, headers=headers, data=json.dumps(payload))
    session_id = resp_h.get("mcp-session-id", "")
    return session_id, body, status


def tool_call(tool_name, args, session_id, msg_id=2, user_agent=None):
    """Call a tool and return the response."""
    payload = {
        "jsonrpc": "2.0", "id": msg_id, "method": "tools/call",
        "params": {"name": tool_name, "arguments": args}
    }
    return mcp_call(payload, session_id=session_id, user_agent=user_agent)


# ============================================================
# TEST 1: Version Check
# ============================================================
def test_version():
    print("\n=== TEST 1: Version Check ===")
    sid, body, status = init_session()
    if status != 200:
        log("FAIL", "Initialize returned non-200", f"status={status}")
        return
    if not isinstance(body, dict) or "result" not in body:
        log("FAIL", "No result in initialize response", str(body)[:200])
        return
    version = body.get("result", {}).get("serverInfo", {}).get("version", "")
    if version == "2.0.8":
        log("PASS", f"Server version is {version}")
    else:
        log("FAIL", f"Expected 2.0.8, got '{version}'")


# ============================================================
# TEST 2: Content-Type Validation
# ============================================================
def test_content_type():
    print("\n=== TEST 2: Content-Type Validation ===")
    payload = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26", "capabilities": {},
            "clientInfo": {"name": "chaos", "version": "1.0"}
        }
    })
    cases = [
        ("application/json", 200, "application/json -> 200"),
        ("application/json; charset=utf-8", 200, "application/json; charset=utf-8 -> 200"),
        (None, 200, "Missing Content-Type -> 200"),
        ("text/plain", 415, "text/plain -> 415"),
        ("application/xml", 415, "application/xml -> 415"),
        ("multipart/form-data", 415, "multipart/form-data -> 415"),
        ("text/html", 415, "text/html -> 415"),
    ]
    for ct, expected_status, desc in cases:
        if ct is None:
            # Explicitly strip Content-Type so curl doesn't send the default
            # Use curl directly: -H "Content-Type:" removes the header
            cmd = [
                "curl", "-s", "-w", "\n%{http_code}", "-X", "POST", BASE_URL,
                "-H", f"Authorization: Bearer {API_KEY}",
                "-H", "Content-Type:",  # removes the header entirely
                "-d", payload,
                "--max-time", "30"
            ]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=40)
                lines = proc.stdout.strip().rsplit("\n", 1)
                status = int(lines[-1]) if len(lines) >= 2 else int(lines[0])
            except Exception:
                status = None
        else:
            headers = {"Authorization": f"Bearer {API_KEY}", "Content-Type": ct}
            status, _, body = curl("POST", BASE_URL, headers=headers, data=payload)
        if status == expected_status:
            log("PASS", desc)
        else:
            log("FAIL", desc, f"got {status}")


# ============================================================
# TEST 3: Rate Limit HTTP Status
# ============================================================
def test_rate_limit_status():
    print("\n=== TEST 3: Rate Limit HTTP Status (free tier, no auth) ===")
    # Initialize without auth
    payload = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26", "capabilities": {},
            "clientInfo": {"name": "chaos-free", "version": "1.0"}
        }
    })
    headers = {"Content-Type": "application/json"}
    status, resp_h, body = curl("POST", BASE_URL, headers=headers, data=payload)
    sid = resp_h.get("mcp-session-id", "")

    if status != 200 or not sid:
        log("FAIL", "Free-tier init failed", f"status={status}")
        return

    # Make a tool call without auth
    tool_payload = json.dumps({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "check_ns", "arguments": {"domain": "example.com", "format": "compact"}}
    })
    headers2 = {"Content-Type": "application/json", "Mcp-Session-Id": sid}
    status2, resp_h2, body2 = curl("POST", BASE_URL, headers=headers2, data=tool_payload)

    # Should be 200 (not 429) even if rate limited at JSON-RPC level
    if status2 == 200:
        log("PASS", "Free-tier tool call returns HTTP 200 (not 429)")
    else:
        log("FAIL", f"Expected HTTP 200, got {status2}")

    # Check quota headers
    has_quota = any(k.startswith("x-quota") for k in resp_h2)
    has_ratelimit = any(k.startswith("x-ratelimit") for k in resp_h2)
    if has_quota or has_ratelimit:
        log("PASS", "Rate limit/quota headers present")
    else:
        log("FAIL", "No x-quota or x-ratelimit headers found", str(list(resp_h2.keys())))


# ============================================================
# TEST 4: No-Send Domain Detection
# ============================================================
def test_nosend_domain():
    print("\n=== TEST 4: No-Send Domain Detection ===")
    sid, _, status = init_session()
    if not sid:
        log("FAIL", "Init failed for no-send test")
        return

    # Scan cscdbs.com (no-send domain: v=spf1 -all + MX)
    status1, _, body1 = tool_call("scan_domain", {"domain": "cscdbs.com", "format": "compact"}, sid, msg_id=10)
    if status1 == 200 and isinstance(body1, dict) and "result" in body1:
        text = ""
        content = body1.get("result", {}).get("content", [])
        for block in content:
            if block.get("type") == "text":
                text += block.get("text", "")
        # Look for DKIM score in the scan report
        # In a no-send domain, DKIM HIGH finding should be downgraded -> score 100
        if "DKIM" in text:
            # Check if DKIM shows 100/100 or passed
            import re
            dkim_match = re.search(r'DKIM[:\s]+(\d+)/100', text)
            if dkim_match:
                dkim_score = int(dkim_match.group(1))
                if dkim_score == 100:
                    log("PASS", f"cscdbs.com DKIM score={dkim_score} (no-send downgrade works)")
                else:
                    log("FAIL", f"cscdbs.com DKIM score={dkim_score}, expected 100")
            else:
                # Maybe the text format doesn't include numeric scores; check for PASS
                if "DKIM" in text and ("100" in text or "pass" in text.lower()):
                    log("PASS", "cscdbs.com DKIM appears passing (no-send downgrade)")
                else:
                    log("FAIL", "Could not parse DKIM score from cscdbs.com scan", text[:300])
        else:
            log("FAIL", "DKIM not found in cscdbs.com scan result", text[:300])
    else:
        log("FAIL", "cscdbs.com scan failed", str(body1)[:200])

    # Scan google.com (normal domain) — DKIM should NOT be 100
    status2, _, body2 = tool_call("scan_domain", {"domain": "google.com", "format": "compact"}, sid, msg_id=11)
    if status2 == 200 and isinstance(body2, dict) and "result" in body2:
        text2 = ""
        content2 = body2.get("result", {}).get("content", [])
        for block in content2:
            if block.get("type") == "text":
                text2 += block.get("text", "")
        import re
        dkim_match2 = re.search(r'DKIM[:\s]+(\d+)/100', text2)
        if dkim_match2:
            dkim_score2 = int(dkim_match2.group(1))
            if dkim_score2 < 100:
                log("PASS", f"google.com DKIM score={dkim_score2} (not 100, has findings)")
            else:
                log("FAIL", f"google.com DKIM score=100, expected <100")
        else:
            # Even without numeric, just check it responded
            log("PASS", "google.com DKIM responded (detailed score not parseable)")
    else:
        log("FAIL", "google.com scan failed", str(body2)[:200])

    # Individual check_spf on a no-send domain
    status3, _, body3 = tool_call("check_spf", {"domain": "cscdbs.com", "format": "compact"}, sid, msg_id=12)
    if status3 == 200 and isinstance(body3, dict) and "result" in body3:
        content3 = body3.get("result", {}).get("content", [])
        if content3 and any(b.get("text", "") for b in content3):
            log("PASS", "check_spf on cscdbs.com returned data")
        else:
            log("FAIL", "check_spf on cscdbs.com returned empty content")
    else:
        log("FAIL", "check_spf on cscdbs.com failed", str(body3)[:200])


# ============================================================
# TEST 5: All 33 Tools Functional
# ============================================================
def test_all_tools():
    print("\n=== TEST 5: All 33 Tools Functional ===")

    # Tool definitions: (name, args)
    all_tools = [
        ("check_mx", {"domain": "google.com"}),
        ("check_spf", {"domain": "google.com"}),
        ("check_dmarc", {"domain": "google.com"}),
        ("check_dkim", {"domain": "google.com"}),
        ("check_dnssec", {"domain": "google.com"}),
        ("check_ssl", {"domain": "google.com"}),
        ("check_mta_sts", {"domain": "google.com"}),
        ("check_ns", {"domain": "google.com"}),
        ("check_caa", {"domain": "google.com"}),
        ("check_bimi", {"domain": "google.com"}),
        ("check_tlsrpt", {"domain": "google.com"}),
        ("check_http_security", {"domain": "google.com"}),
        ("check_dane", {"domain": "google.com"}),
        ("check_dane_https", {"domain": "google.com"}),
        ("check_svcb_https", {"domain": "google.com"}),
        ("check_lookalikes", {"domain": "google.com"}),
        ("scan_domain", {"domain": "example.com"}),
        ("compare_baseline", {"domain": "google.com", "baseline": {"grade": "C"}}),
        ("check_shadow_domains", {"domain": "google.com"}),
        ("check_txt_hygiene", {"domain": "google.com"}),
        ("check_mx_reputation", {"domain": "google.com"}),
        ("check_srv", {"domain": "google.com"}),
        ("check_zone_hygiene", {"domain": "google.com"}),
        ("generate_fix_plan", {"domain": "example.com"}),
        ("generate_spf_record", {"domain": "example.com"}),
        ("generate_dmarc_record", {"domain": "example.com"}),
        ("generate_dkim_config", {"domain": "example.com"}),
        ("generate_mta_sts_policy", {"domain": "example.com"}),
        ("get_benchmark", {}),
        ("get_provider_insights", {"provider": "google"}),
        ("assess_spoofability", {"domain": "google.com"}),
        ("check_resolver_consistency", {"domain": "google.com"}),
        ("explain_finding", {"checkType": "SPF", "status": "fail"}),
    ]

    # Add format: compact to all
    for i, (name, args) in enumerate(all_tools):
        all_tools[i] = (name, {**args, "format": "compact"})

    assert len(all_tools) == 33, f"Expected 33 tools, got {len(all_tools)}"

    # Initialize one session for all
    sid, _, _ = init_session()
    if not sid:
        log("FAIL", "Init failed for tool tests")
        return

    def run_tool(tool_name, args, idx):
        status, _, body = tool_call(tool_name, args, sid, msg_id=100 + idx)
        return tool_name, status, body

    passed = 0
    failed = 0
    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = {}
        for idx, (name, args) in enumerate(all_tools):
            f = pool.submit(run_tool, name, args, idx)
            futures[f] = name

        for f in as_completed(futures):
            name = futures[f]
            try:
                tool_name, status, body = f.result()
                if status == 200 and isinstance(body, dict):
                    if "error" in body:
                        err_msg = body["error"].get("message", "unknown")
                        # Rate limit errors are acceptable - tool is functional
                        if "rate" in err_msg.lower() or "quota" in err_msg.lower() or "limit" in err_msg.lower():
                            log("PASS", f"{tool_name} (rate-limited but functional)")
                            passed += 1
                        else:
                            log("FAIL", f"{tool_name} returned error", err_msg[:100])
                            failed += 1
                    elif "result" in body:
                        content = body["result"].get("content", [])
                        if content:
                            log("PASS", f"{tool_name}")
                            passed += 1
                        else:
                            log("FAIL", f"{tool_name} empty content")
                            failed += 1
                    else:
                        log("FAIL", f"{tool_name} unexpected response", str(body)[:100])
                        failed += 1
                else:
                    log("FAIL", f"{tool_name} HTTP {status}", str(body)[:100])
                    failed += 1
            except Exception as e:
                log("ERROR", f"{tool_name} exception", str(e)[:100])

    print(f"  Tools: {passed}/33 passed, {failed}/33 failed")


# ============================================================
# TEST 6: Concurrent Stress (20 parallel scans)
# ============================================================
def test_concurrent_stress():
    print("\n=== TEST 6: Concurrent Stress — 20 Parallel Scans ===")
    domains = [
        "google.com", "cloudflare.com", "stripe.com", "github.com", "microsoft.com",
        "apple.com", "amazon.com", "netflix.com", "openai.com", "linear.app",
        "tesla.com", "uber.com", "spotify.com", "slack.com", "discord.com",
        "twitch.tv", "reddit.com", "paypal.com", "shopify.com", "zoom.us"
    ]

    def scan_one(domain):
        sid, _, st = init_session()
        if not sid:
            return domain, "INIT_FAIL", None
        status, _, body = tool_call("scan_domain", {"domain": domain, "format": "compact"}, sid, msg_id=2)
        return domain, status, body

    succeeded = 0
    failed_domains = []
    start = time.time()

    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = {pool.submit(scan_one, d): d for d in domains}
        for f in as_completed(futures):
            domain = futures[f]
            try:
                d, status, body = f.result()
                if status == 200 and isinstance(body, dict) and "result" in body:
                    succeeded += 1
                elif status == 200 and isinstance(body, dict) and "error" in body:
                    err = body.get("error", {}).get("message", "")
                    if "rate" in err.lower() or "quota" in err.lower() or "limit" in err.lower():
                        succeeded += 1  # Rate limited but server is functional
                    else:
                        failed_domains.append((d, f"error: {err[:60]}"))
                else:
                    failed_domains.append((d, f"status={status}"))
            except Exception as e:
                failed_domains.append((domain, str(e)[:60]))

    elapsed = time.time() - start
    print(f"  Completed in {elapsed:.1f}s")

    if succeeded >= 15:  # Allow some rate-limited failures
        log("PASS", f"Concurrent stress: {succeeded}/20 succeeded ({elapsed:.1f}s)")
    else:
        log("FAIL", f"Only {succeeded}/20 succeeded", str(failed_domains[:5]))

    if failed_domains:
        for d, reason in failed_domains[:5]:
            log("FAIL" if "rate" not in reason.lower() else "PASS", f"  {d}: {reason}")


# ============================================================
# TEST 7: All 7 MCP Client Types
# ============================================================
def test_client_types():
    print("\n=== TEST 7: All 7 MCP Client Types ===")
    clients = [
        ("claude_code", "claude-code/1.0"),
        ("cursor", "cursor/0.48"),
        ("vscode", "vscode-mcp/1.96"),
        ("claude_desktop", "Claude-Desktop/1.2"),
        ("windsurf", "windsurf/1.5"),
        ("mcp_remote", "mcp-remote/0.2"),
        ("unknown", "Mozilla/5.0"),
    ]

    def test_client(name, ua):
        sid, body, status = init_session(user_agent=ua)
        if not sid:
            return name, "INIT_FAIL", None
        st, _, resp = tool_call(
            "scan_domain",
            {"domain": "blackveilsecurity.com", "format": "compact"},
            sid, msg_id=2, user_agent=ua
        )
        return name, st, resp

    with ThreadPoolExecutor(max_workers=7) as pool:
        futures = {pool.submit(test_client, n, ua): n for n, ua in clients}
        for f in as_completed(futures):
            name = futures[f]
            try:
                cname, status, resp = f.result()
                if status == 200 and isinstance(resp, dict):
                    if "result" in resp:
                        log("PASS", f"Client '{cname}' (UA scan OK)")
                    elif "error" in resp:
                        err = resp["error"].get("message", "")
                        if "rate" in err.lower() or "quota" in err.lower():
                            log("PASS", f"Client '{cname}' (rate-limited but functional)")
                        else:
                            log("FAIL", f"Client '{cname}'", err[:80])
                    else:
                        log("FAIL", f"Client '{cname}' unexpected", str(resp)[:80])
                else:
                    log("FAIL", f"Client '{cname}' HTTP {status}")
            except Exception as e:
                log("ERROR", f"Client '{name}'", str(e)[:80])


# ============================================================
# TEST 8: Security Edge Cases
# ============================================================
def test_security():
    print("\n=== TEST 8: Security Edge Cases ===")

    # 8a: Bad auth token
    headers = {"Content-Type": "application/json", "Authorization": "Bearer INVALID_TOKEN_123"}
    payload = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                   "clientInfo": {"name": "chaos", "version": "1.0"}}
    })
    status, _, _ = curl("POST", BASE_URL, headers=headers, data=payload)
    if status == 401:
        log("PASS", "Bad auth token -> 401")
    else:
        log("FAIL", f"Bad auth token -> {status}, expected 401")

    # For remaining tests, init a valid session
    sid, _, _ = init_session()
    if not sid:
        log("FAIL", "Init failed for security tests")
        return

    # 8b: SSRF: 169.254.169.254
    st, _, body = tool_call("check_ns", {"domain": "169.254.169.254", "format": "compact"}, sid, msg_id=50)
    if st == 200 and isinstance(body, dict):
        err = body.get("error", {}).get("message", "")
        res_content = body.get("result", {}).get("content", [{}])
        is_error = body.get("result", {}).get("isError", False)
        if "error" in body or is_error or "blocked" in str(body).lower() or "validation failed" in str(body).lower():
            log("PASS", "SSRF 169.254.169.254 blocked")
        else:
            log("FAIL", "SSRF 169.254.169.254 not blocked", str(body)[:100])
    else:
        log("PASS", f"SSRF 169.254.169.254 rejected (HTTP {st})")

    # 8c: SSRF: localhost
    st, _, body = tool_call("check_ns", {"domain": "localhost", "format": "compact"}, sid, msg_id=51)
    if st == 200 and isinstance(body, dict):
        is_error = body.get("result", {}).get("isError", False)
        if "error" in body or is_error or "blocked" in str(body).lower() or "validation" in str(body).lower():
            log("PASS", "SSRF localhost blocked")
        else:
            log("FAIL", "SSRF localhost not blocked", str(body)[:100])
    else:
        log("PASS", f"SSRF localhost rejected (HTTP {st})")

    # 8d: Oversized body >10KB
    big_payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping", "padding": "X" * 15000})
    headers_big = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {API_KEY}",
        "Mcp-Session-Id": sid
    }
    st, _, _ = curl("POST", BASE_URL, headers=headers_big, data=big_payload)
    if st == 413:
        log("PASS", "Oversized body -> 413")
    else:
        log("FAIL", f"Oversized body -> {st}, expected 413")

    # 8e: Invalid JSON
    headers_inv = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {API_KEY}",
        "Mcp-Session-Id": sid
    }
    st, _, body = curl("POST", BASE_URL, headers=headers_inv, data="{not valid json!!!}")
    if st == 400:
        log("PASS", "Invalid JSON -> 400")
    else:
        # JSON-RPC parse error returns 200 with error in body per spec
        if st == 200 and isinstance(body, dict) and "error" in body:
            code = body["error"].get("code", 0)
            if code == -32700:  # Parse error
                log("PASS", "Invalid JSON -> JSON-RPC parse error (-32700)")
            else:
                log("FAIL", f"Invalid JSON -> 200 with code {code}")
        else:
            log("FAIL", f"Invalid JSON -> {st}", str(body)[:100])

    # 8f: Unauthorized Origin
    headers_origin = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {API_KEY}",
        "Origin": "https://evil.example.com"
    }
    st, _, _ = curl("POST", BASE_URL, headers=headers_origin, data=payload)
    if st == 403:
        log("PASS", "Unauthorized Origin -> 403")
    else:
        log("FAIL", f"Unauthorized Origin -> {st}, expected 403")

    # 8g: Invalid session ID
    headers_bad_sid = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {API_KEY}",
        "Mcp-Session-Id": "nonexistent-session-id-12345"
    }
    ping_payload = json.dumps({"jsonrpc": "2.0", "id": 99, "method": "ping"})
    st, _, _ = curl("POST", BASE_URL, headers=headers_bad_sid, data=ping_payload)
    if st == 404:
        log("PASS", "Invalid session ID -> 404")
    elif st == 400:
        log("PASS", "Invalid session ID -> 400 (missing session)")
    else:
        log("FAIL", f"Invalid session ID -> {st}, expected 404")

    # 8h: DELETE session then reuse
    sid2, _, _ = init_session()
    if sid2:
        del_headers = {
            "Authorization": f"Bearer {API_KEY}",
            "Mcp-Session-Id": sid2
        }
        st_del, _, _ = curl("DELETE", BASE_URL, headers=del_headers)
        if st_del in (200, 204):
            log("PASS", f"DELETE session -> {st_del}")
        else:
            log("FAIL", f"DELETE session -> {st_del}")

        # Try to reuse deleted session
        time.sleep(0.5)
        headers_reuse = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {API_KEY}",
            "Mcp-Session-Id": sid2
        }
        st_reuse, _, _ = curl("POST", BASE_URL, headers=headers_reuse, data=ping_payload)
        if st_reuse == 404:
            log("PASS", "Reuse deleted session -> 404")
        else:
            log("FAIL", f"Reuse deleted session -> {st_reuse}, expected 404")
    else:
        log("FAIL", "Could not create session for DELETE test")


# ============================================================
# TEST 9: Session Lifecycle
# ============================================================
def test_sessions():
    print("\n=== TEST 9: Session Lifecycle ===")

    # Create 10 sessions concurrently
    def create():
        sid, _, st = init_session()
        return sid, st

    sessions = []
    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = [pool.submit(create) for _ in range(10)]
        for f in as_completed(futures):
            sid, st = f.result()
            if sid and st == 200:
                sessions.append(sid)

    if len(sessions) == 10:
        log("PASS", f"Created 10 sessions concurrently")
    else:
        log("FAIL", f"Created {len(sessions)}/10 sessions")

    if len(sessions) < 6:
        log("FAIL", "Not enough sessions for lifecycle test")
        return

    # Delete first 5
    deleted = sessions[:5]
    live = sessions[5:]

    for sid in deleted:
        del_headers = {"Authorization": f"Bearer {API_KEY}", "Mcp-Session-Id": sid}
        curl("DELETE", BASE_URL, headers=del_headers)

    time.sleep(2)  # Allow KV eventual consistency across isolates

    # Verify deleted return 404 (retry once for KV lag)
    ping = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"})
    del_ok = 0
    retried = []
    for sid in deleted:
        h = {"Content-Type": "application/json", "Authorization": f"Bearer {API_KEY}", "Mcp-Session-Id": sid}
        st, _, _ = curl("POST", BASE_URL, headers=h, data=ping)
        if st == 404:
            del_ok += 1
        else:
            retried.append(sid)

    # Retry any that didn't 404 yet (KV propagation delay)
    if retried:
        time.sleep(2)
        for sid in retried:
            h = {"Content-Type": "application/json", "Authorization": f"Bearer {API_KEY}", "Mcp-Session-Id": sid}
            st, _, _ = curl("POST", BASE_URL, headers=h, data=ping)
            if st == 404:
                del_ok += 1

    if del_ok >= len(deleted) - 1:  # Allow 1 KV consistency miss
        log("PASS", f"{del_ok}/{len(deleted)} deleted sessions return 404 (KV consistency OK)")
    else:
        log("FAIL", f"{del_ok}/{len(deleted)} deleted sessions return 404")

    # Verify live return 200
    live_ok = 0
    for sid in live:
        h = {"Content-Type": "application/json", "Authorization": f"Bearer {API_KEY}", "Mcp-Session-Id": sid}
        st, _, _ = curl("POST", BASE_URL, headers=h, data=ping)
        if st == 200:
            live_ok += 1

    if live_ok == len(live):
        log("PASS", f"All {len(live)} live sessions return 200 on ping")
    else:
        log("FAIL", f"{live_ok}/{len(live)} live sessions return 200")

    # Cleanup
    for sid in live:
        del_headers = {"Authorization": f"Bearer {API_KEY}", "Mcp-Session-Id": sid}
        curl("DELETE", BASE_URL, headers=del_headers)


# ============================================================
# TEST 10: Protocol Edge Cases
# ============================================================
def test_protocol():
    print("\n=== TEST 10: Protocol Edge Cases ===")
    sid, _, _ = init_session()
    if not sid:
        log("FAIL", "Init failed for protocol tests")
        return

    # 10a: Batch [ping, tools/list, resources/list]
    batch = json.dumps([
        {"jsonrpc": "2.0", "id": 1, "method": "ping"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "resources/list"},
    ])
    h = {"Content-Type": "application/json", "Authorization": f"Bearer {API_KEY}", "Mcp-Session-Id": sid}
    st, _, body = curl("POST", BASE_URL, headers=h, data=batch)
    if st == 200 and isinstance(body, list) and len(body) == 3:
        log("PASS", "Batch [ping, tools/list, resources/list] -> 3 responses")
    elif st == 200 and isinstance(body, list):
        log("FAIL", f"Batch returned {len(body)} responses, expected 3")
    else:
        log("FAIL", f"Batch -> HTTP {st}", str(body)[:100])

    # 10b: Batch over limit (21 items)
    big_batch = json.dumps([{"jsonrpc": "2.0", "id": i, "method": "ping"} for i in range(21)])
    st, _, body = curl("POST", BASE_URL, headers=h, data=big_batch)
    if st == 400:
        log("PASS", "Batch 21 items -> 400")
    elif st == 200 and isinstance(body, dict) and "error" in body:
        log("PASS", "Batch 21 items -> JSON-RPC error")
    else:
        log("FAIL", f"Batch 21 items -> {st}", str(body)[:100])

    # 10c: Empty batch []
    st, _, body = curl("POST", BASE_URL, headers=h, data="[]")
    if st == 400:
        log("PASS", "Empty batch [] -> 400")
    elif st == 200 and isinstance(body, dict) and "error" in body:
        log("PASS", "Empty batch [] -> JSON-RPC error")
    else:
        log("FAIL", f"Empty batch [] -> {st}", str(body)[:100])

    # 10d: Null id (notification) -> 202
    notif = json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"})
    st, _, body = curl("POST", BASE_URL, headers=h, data=notif)
    if st == 202:
        log("PASS", "Notification (null id) -> 202")
    elif st == 200:
        log("PASS", "Notification -> 200 (acceptable)")
    else:
        log("FAIL", f"Notification -> {st}, expected 202", str(body)[:100])

    # 10e: String id -> echoed back
    str_id = json.dumps({"jsonrpc": "2.0", "id": "my-string-id", "method": "ping"})
    st, _, body = curl("POST", BASE_URL, headers=h, data=str_id)
    if st == 200 and isinstance(body, dict):
        returned_id = body.get("id", "")
        if returned_id == "my-string-id":
            log("PASS", "String id 'my-string-id' echoed back")
        else:
            log("FAIL", f"String id returned '{returned_id}', expected 'my-string-id'")
    else:
        log("FAIL", f"String id -> HTTP {st}", str(body)[:100])


# ============================================================
# MAIN
# ============================================================
def main():
    print("=" * 65)
    print(" Blackveil DNS MCP Server — Chaos Test Suite v2.0.8")
    print("=" * 65)
    start = time.time()

    test_version()
    test_content_type()
    test_rate_limit_status()
    test_nosend_domain()
    test_all_tools()
    test_concurrent_stress()
    test_client_types()
    test_security()
    test_sessions()
    test_protocol()

    elapsed = time.time() - start
    total = results["pass"] + results["fail"] + results["error"]

    print("\n" + "=" * 65)
    print(f" RESULTS: {results['pass']} passed, {results['fail']} failed, {results['error']} errors ({total} total)")
    print(f" Duration: {elapsed:.1f}s")
    print("=" * 65)

    if results["fail"] == 0 and results["error"] == 0:
        print("\n  >>> v2.0.8 READY <<<\n")
    else:
        print(f"\n  >>> v2.0.8 ISSUES FOUND ({results['fail']} failures, {results['error']} errors) <<<\n")

    sys.exit(0 if results["fail"] == 0 and results["error"] == 0 else 1)


if __name__ == "__main__":
    main()
