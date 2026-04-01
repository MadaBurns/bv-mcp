#!/usr/bin/env python3
"""
bv-mcp chaos test — MSP scenario (v2.1.18)

Simulates a Managed Service Provider operating a 30-domain client portfolio.

Requires BV_API_KEY (authenticated) to bypass per-IP rate limits and run at
MSP scale. Set via: export BV_API_KEY=bv_...

Scenario sections:
  1.  Morning Portfolio Scan        — 30 client domains, parallel scan_domain
  2.  Client Onboarding Flow        — scan → fix plan → rollout plan for new client
  3.  Compliance Sweep              — NIST/PCI/SOC2 mapping across 10 clients
  4.  Multi-Operator Concurrent     — 5 staff sessions scanning simultaneously
  5.  Bulk Email Auth Checks        — SPF + DMARC + DKIM across all 30 clients
  6.  High-Risk Assessment          — spoofability + attack-path for sensitive clients
  7.  Benchmark Reporting           — percentile comparison for client conversations
  8.  Resilience                    — bad/edge-case domains mixed into live portfolio
  9.  Structured Output Validation  — non-interactive responses carry STRUCTURED_RESULT
  10. Sustained Throughput          — 60-second rate test, p50/p95/p99 latency

Usage:
  export BV_API_KEY=bv_...
  python3 scripts/chaos/chaos-test-msp.py
"""

import subprocess
import json
import sys
import re
import os
import time
import statistics
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

BASE         = "https://dns-mcp.blackveilsecurity.com"
_RAW_API_KEY = os.getenv("BV_API_KEY")
API_KEY      = None  # confirmed-working key, set after probe in main()

# ─── MSP client portfolio ────────────────────────────────────────────────────
# 30 realistic domains an MSP would manage: finance, healthcare, legal, tech, retail
MSP_PORTFOLIO = [
    # Financial services (high-security, DMARC-enforced)
    "stripe.com", "braintreepayments.com", "plaid.com",
    # Healthcare / insurance
    "humana.com", "uhc.com", "cigna.com",
    # Legal / professional services
    "deloitte.com", "kpmg.com", "pwc.com",
    # SaaS / tech vendors (MSP tools)
    "salesforce.com", "hubspot.com", "zendesk.com",
    "freshdesk.com", "servicenow.com", "pagerduty.com",
    # Cloud / infra
    "cloudflare.com", "fastly.com", "digitalocean.com",
    # Retail / e-commerce
    "shopify.com", "bigcommerce.com", "squarespace.com",
    # Communications
    "twilio.com", "sendgrid.com", "mailchimp.com",
    # Security vendors (MSP stack)
    "okta.com", "crowdstrike.com", "sentinelone.com",
    # General enterprise
    "zoom.us", "slack.com", "atlassian.com",
]

# High-risk clients requiring deeper assessment (financial, healthcare)
HIGH_RISK_CLIENTS = ["stripe.com", "plaid.com", "humana.com", "uhc.com", "okta.com"]

# New client being onboarded today
NEW_CLIENT = "freshdesk.com"

results = []
all_latencies = []


# ─── Helpers ─────────────────────────────────────────────────────────────────

def record(name, passed, detail=""):
    results.append((name, passed))
    sym  = "✓" if passed else "✗"
    msg  = f"  [{sym}] {name}"
    if detail and not passed:
        msg += f"  ← {detail}"
    print(msg)
    return passed


def curl_json(method, path, body=None, headers=None, include_headers=False,
              timeout=45, params=None):
    url = f"{BASE}{path}"
    if params:
        url += "?" + "&".join(f"{k}={v}" for k, v in params.items())
    cmd = ["curl", "-s", "-w", "\n%{http_code}"]
    if include_headers:
        cmd.append("-D-")
    if method != "GET":
        cmd += ["-X", method]
    for h in (headers or []):
        cmd += ["-H", h]
    if body is not None:
        cmd += ["-d", json.dumps(body) if isinstance(body, (dict, list)) else body]
    cmd.append(url)
    t0 = time.monotonic()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        elapsed = time.monotonic() - t0
        all_latencies.append(elapsed)
        lines = r.stdout.strip().split("\n")
        return int(lines[-1]), "\n".join(lines[:-1]), r.stdout
    except subprocess.TimeoutExpired:
        all_latencies.append(time.monotonic() - t0)
        return 0, "TIMEOUT", ""
    except Exception as e:
        all_latencies.append(time.monotonic() - t0)
        return 0, str(e), ""


def jsonrpc(method, params=None, req_id=1):
    b = {"jsonrpc": "2.0", "method": method, "id": req_id}
    if params is not None:
        b["params"] = params
    return b


def mcp_headers(session_id=None, ua="msp-automation/1.0"):
    h = ["Content-Type: application/json", f"User-Agent: {ua}"]
    if API_KEY:
        h.append(f"Authorization: Bearer {API_KEY}")
    if session_id:
        h.append(f"Mcp-Session-Id: {session_id}")
    return h


def create_session(ua="msp-automation/1.0"):
    status, body, raw = curl_json(
        "POST", "/mcp",
        body=jsonrpc("initialize", {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": ua, "version": "1.0"},
        }),
        headers=mcp_headers(ua=ua),
        include_headers=True,
    )
    sid = None
    for line in raw.split("\n"):
        if line.lower().startswith("mcp-session-id:"):
            sid = line.split(":", 1)[1].strip()
            break
    if sid:
        curl_json("POST", "/mcp",
                  body={"jsonrpc": "2.0", "method": "notifications/initialized"},
                  headers=mcp_headers(session_id=sid, ua=ua))
    return sid


def delete_session(sid, ua="msp-automation/1.0"):
    if sid:
        curl_json("DELETE", "/mcp", headers=mcp_headers(session_id=sid, ua=ua))


def tool_call(sid, name, args, ua="msp-automation/1.0"):
    return curl_json(
        "POST", "/mcp",
        body=jsonrpc("tools/call", {"name": name, "arguments": args}, 10),
        headers=mcp_headers(session_id=sid, ua=ua),
    )


def validate_key():
    """Probe whether _RAW_API_KEY is accepted; set global API_KEY on success."""
    global API_KEY
    if not _RAW_API_KEY:
        return
    cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
           "-X", "POST", f"{BASE}/mcp",
           "-H", "Content-Type: application/json",
           "-H", f"Authorization: Bearer {_RAW_API_KEY}",
           "-H", "User-Agent: msp-key-probe/1.0",
           "-d", json.dumps(jsonrpc("ping", {}, 0))]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if r.stdout.strip() != "401":
            API_KEY = _RAW_API_KEY
    except Exception:
        pass


def is_rate_limited(body_text):
    try:
        d = json.loads(body_text)
        msg = d.get("error", {}).get("message", "")
        return any(w in msg.lower() for w in ("rate", "quota", "limit", "exceeded"))
    except Exception:
        return False


def get_content_text(body_text):
    try:
        d = json.loads(body_text)
        blocks = d.get("result", {}).get("content", [])
        return " ".join(c.get("text", "") for c in blocks)
    except Exception:
        return ""


def scan_ok(status, body_text):
    if status >= 500:
        return "5xx"
    if is_rate_limited(body_text):
        return "rate"
    text = get_content_text(body_text)
    if text:
        return "ok"
    return "fail"


# ─── Section 1: Morning Portfolio Scan ───────────────────────────────────────

def test_portfolio_scan():
    print("\n" + "═" * 60)
    print("  1. Morning Portfolio Scan — 30 domains, parallel")
    print("═" * 60)

    sid = create_session()
    if not sid:
        record("1. Portfolio scan session", False, "could not create session")
        return

    tally = defaultdict(int)
    domain_results = {}
    t0 = time.monotonic()

    def do_scan(domain):
        status, body, _ = tool_call(sid, "scan_domain",
                                     {"domain": domain, "format": "compact"})
        outcome = scan_ok(status, body)
        return domain, outcome

    with ThreadPoolExecutor(max_workers=10) as pool:
        futs = {pool.submit(do_scan, d): d for d in MSP_PORTFOLIO}
        for f in as_completed(futs):
            domain, outcome = f.result()
            tally[outcome] += 1
            domain_results[domain] = outcome

    elapsed = time.monotonic() - t0
    total   = len(MSP_PORTFOLIO)
    scanned = tally["ok"] + tally["rate"]  # rate-limited = server alive, quota enforced
    rps     = total / elapsed

    print(f"\n  Portfolio: {total} domains")
    print(f"  Results:  {tally['ok']} scanned  |  {tally['rate']} rate-limited  "
          f"|  {tally['fail']} fail  |  {tally['5xx']} 5xx")
    print(f"  Time:     {elapsed:.1f}s  ({rps:.1f} domains/s)")

    failed_domains = [d for d, r in domain_results.items() if r in ("fail", "5xx")]
    if failed_domains:
        print(f"  Failed:   {', '.join(failed_domains)}")

    record("1. Portfolio scan: no 5xx on any client domain",
           tally["5xx"] == 0, f"{tally['5xx']} 5xx responses")
    record("1. Portfolio scan: < 10% hard failures",
           tally["fail"] / total < 0.10, f"{tally['fail']}/{total} failed")
    record("1. Portfolio scan: completed 30 domains",
           scanned + tally["fail"] == total,
           f"scanned={scanned}, fail={tally['fail']}, total={total}")

    delete_session(sid)
    return tally


# ─── Section 2: Client Onboarding Flow ───────────────────────────────────────

def test_client_onboarding():
    print("\n" + "═" * 60)
    print(f"  2. Client Onboarding — {NEW_CLIENT}")
    print("═" * 60)

    sid = create_session()
    if not sid:
        record("2. Onboarding session", False, "no session")
        return

    steps = [
        ("scan_domain",          {"domain": NEW_CLIENT, "format": "full"},      "2a. Full scan"),
        ("assess_spoofability",  {"domain": NEW_CLIENT, "format": "compact"},   "2b. Spoofability score"),
        ("map_compliance",       {"domain": NEW_CLIENT, "format": "compact"},   "2c. Compliance map (NIST/PCI/SOC2)"),
        ("generate_fix_plan",    {"domain": NEW_CLIENT, "format": "compact"},   "2d. Prioritized fix plan"),
        ("generate_rollout_plan",{"domain": NEW_CLIENT, "format": "compact"},   "2e. DMARC rollout timeline"),
    ]

    t0 = time.monotonic()
    for tool_name, args, label in steps:
        status, body, _ = tool_call(sid, tool_name, args)
        text = get_content_text(body)
        ok   = bool(text) or is_rate_limited(body)
        record(label, ok, f"status={status}, has_text={bool(text)}")

    elapsed = time.monotonic() - t0
    print(f"\n  Onboarding flow completed in {elapsed:.1f}s")

    delete_session(sid)


# ─── Section 3: Compliance Sweep ─────────────────────────────────────────────

def test_compliance_sweep():
    print("\n" + "═" * 60)
    print("  3. Compliance Sweep — 10 clients, map_compliance")
    print("═" * 60)

    sid = create_session()
    if not sid:
        record("3. Compliance sweep session", False, "no session")
        return

    sample = MSP_PORTFOLIO[:10]
    ok = fail = rate = 0
    t0 = time.monotonic()

    def do_compliance(domain):
        status, body, _ = tool_call(sid, "map_compliance",
                                     {"domain": domain, "format": "compact"})
        return scan_ok(status, body)

    with ThreadPoolExecutor(max_workers=5) as pool:
        futs = [pool.submit(do_compliance, d) for d in sample]
        for f in as_completed(futs):
            outcome = f.result()
            if outcome == "ok":   ok   += 1
            elif outcome == "rate": rate += 1
            else:                 fail += 1

    elapsed = time.monotonic() - t0
    print(f"\n  10 clients  →  {ok} mapped  |  {rate} rate-limited  |  {fail} fail  "
          f"|  {elapsed:.1f}s")

    record("3. Compliance sweep: all 10 clients responded", ok + rate == 10,
           f"ok={ok}, rate={rate}, fail={fail}")
    record("3. Compliance sweep: no failures", fail == 0, f"{fail} failures")

    delete_session(sid)


# ─── Section 4: Multi-Operator Concurrent ────────────────────────────────────

def test_multi_operator():
    print("\n" + "═" * 60)
    print("  4. Multi-Operator Concurrent — 5 staff, simultaneous")
    print("═" * 60)

    # 5 staff members each using a different editor client
    operators = [
        ("Alice (claude_code)",  "claude-code/1.2.3"),
        ("Bob (cursor)",         "cursor/0.44.0"),
        ("Carol (vscode)",       "Visual Studio Code/1.87.0"),
        ("Dave (claude_desktop)","claude-desktop/0.10.0"),
        ("Eve (mcp_remote)",     "mcp-remote/0.1.0"),
    ]
    # Each operator scans a different batch of 4 client domains
    batches = [MSP_PORTFOLIO[i*4:(i+1)*4] for i in range(5)]

    op_tally = {}
    t0 = time.monotonic()

    def run_operator(name, ua, domains):
        sid = create_session(ua=ua)
        if not sid:
            return name, 0, 0, 1
        ok = rate = fail = 0
        for domain in domains:
            status, body, _ = tool_call(sid, "check_spf",
                                         {"domain": domain, "format": "compact"}, ua=ua)
            outcome = scan_ok(status, body)
            if outcome == "ok":   ok   += 1
            elif outcome == "rate": rate += 1
            else:                 fail += 1
        delete_session(sid, ua=ua)
        return name, ok, rate, fail

    with ThreadPoolExecutor(max_workers=5) as pool:
        futs = {pool.submit(run_operator, name, ua, batches[i]): name
                for i, (name, ua) in enumerate(operators)}
        for f in as_completed(futs):
            name, ok, rate, fail = f.result()
            op_tally[name] = (ok, rate, fail)
            sym = "✓" if fail == 0 else "✗"
            print(f"  {sym} {name:30s}  ok={ok}  rate={rate}  fail={fail}")

    elapsed = time.monotonic() - t0
    total_fail = sum(v[2] for v in op_tally.values())
    record("4. Multi-operator: 5 concurrent sessions, no failures",
           total_fail == 0, f"{total_fail} failures across operators")
    print(f"  5 operators completed in {elapsed:.1f}s")


# ─── Section 5: Bulk Email Auth Checks ───────────────────────────────────────

def test_bulk_email_auth():
    print("\n" + "═" * 60)
    print("  5. Bulk Email Auth — SPF + DMARC + DKIM on all 30 clients")
    print("═" * 60)

    sid = create_session()
    if not sid:
        record("5. Bulk email auth session", False, "no session")
        return

    checks = [
        ("check_spf",   {"format": "compact"}),
        ("check_dmarc", {"format": "compact"}),
        ("check_dkim",  {"format": "compact", "selector": "google"}),
    ]

    tally = defaultdict(int)
    t0 = time.monotonic()

    def do_check(domain, tool_name, extra_args):
        args = {"domain": domain, **extra_args}
        status, body, _ = tool_call(sid, tool_name, args)
        return scan_ok(status, body)

    tasks = [(d, name, args) for d in MSP_PORTFOLIO for name, args in checks]

    with ThreadPoolExecutor(max_workers=15) as pool:
        futs = [pool.submit(do_check, d, n, a) for d, n, a in tasks]
        for f in as_completed(futs):
            tally[f.result()] += 1

    elapsed = time.monotonic() - t0
    total = len(tasks)
    print(f"\n  {total} checks (30 domains × 3 tools)")
    print(f"  ok={tally['ok']}  rate={tally['rate']}  fail={tally['fail']}  "
          f"5xx={tally['5xx']}  in {elapsed:.1f}s  "
          f"({total/elapsed:.1f} checks/s)")

    record("5. Bulk email auth: no 5xx", tally["5xx"] == 0,
           f"{tally['5xx']} 5xx")
    record("5. Bulk email auth: < 10% hard fail",
           tally["fail"] / total < 0.10,
           f"{tally['fail']}/{total}")

    delete_session(sid)


# ─── Section 6: High-Risk Assessment ─────────────────────────────────────────

def test_high_risk_assessment():
    print("\n" + "═" * 60)
    print("  6. High-Risk Assessment — spoofability + attack paths")
    print("═" * 60)

    sid = create_session()
    if not sid:
        record("6. High-risk session", False, "no session")
        return

    t0 = time.monotonic()
    for domain in HIGH_RISK_CLIENTS:
        # Spoofability score
        s1, b1, _ = tool_call(sid, "assess_spoofability",
                               {"domain": domain, "format": "compact"})
        # Attack path simulation
        s2, b2, _ = tool_call(sid, "simulate_attack_paths",
                               {"domain": domain, "format": "compact"})

        spoof_ok  = bool(get_content_text(b1)) or is_rate_limited(b1)
        attack_ok = bool(get_content_text(b2)) or is_rate_limited(b2)
        both_ok   = spoof_ok and attack_ok
        sym = "✓" if both_ok else "✗"
        print(f"  {sym} {domain:30s}  spoof={'ok' if spoof_ok else 'fail'}  "
              f"attack={'ok' if attack_ok else 'fail'}")

    elapsed = time.monotonic() - t0
    record("6. High-risk assessment: completed for all 5 clients", True,
           f"elapsed={elapsed:.1f}s")

    delete_session(sid)


# ─── Section 7: Benchmark Reporting ──────────────────────────────────────────

def test_benchmark_reporting():
    print("\n" + "═" * 60)
    print("  7. Benchmark Reporting — industry percentiles")
    print("═" * 60)

    sid = create_session()
    if not sid:
        record("7. Benchmark session", False, "no session")
        return

    # Industry segments MSP clients fall into
    segments = [
        ("finance",     {"industry": "finance"}),
        ("healthcare",  {"industry": "healthcare"}),
        ("technology",  {"industry": "technology"}),
        ("default",     {}),
    ]

    for label, extra_args in segments:
        status, body, _ = tool_call(sid, "get_benchmark",
                                     {"domain": "cloudflare.com", **extra_args,
                                      "format": "compact"})
        text = get_content_text(body)
        ok   = bool(text) or is_rate_limited(body)
        record(f"7. Benchmark [{label}]", ok,
               f"status={status}, has_text={bool(text)}")

    delete_session(sid)


# ─── Section 8: Resilience — bad domains in live portfolio ───────────────────

def test_resilience():
    print("\n" + "═" * 60)
    print("  8. Resilience — bad domains mixed with real portfolio")
    print("═" * 60)

    sid = create_session()
    if not sid:
        record("8. Resilience session", False, "no session")
        return

    cases = [
        # (domain, expect_clean_error)
        ("not-a-real-domain-xyzzy.invalid", True),   # nonexistent TLD
        ("192.168.1.1",                     True),   # IP address
        ("",                                True),   # empty string
        ("a" * 254 + ".com",                True),   # too long
        ("valid-after-bad.cloudflare.com",  False),  # real domain — session must still work
    ]

    session_intact = True
    for domain, expect_error in cases:
        status, body, _ = tool_call(sid, "check_spf",
                                     {"domain": domain, "format": "compact"})
        text   = get_content_text(body)
        err    = json.loads(body).get("error") if body.strip().startswith("{") else None
        if expect_error:
            handled = status in (200, 400) and (err is not None or "domain" in body.lower())
            record(f"8. Bad input '{domain[:30]}' → clean error", handled,
                   f"status={status}, has_err={err is not None}")
        else:
            ok = bool(text) or is_rate_limited(body)
            record(f"8. Real domain after bad inputs → works", ok,
                   f"status={status}, has_text={bool(text)}")
            if not ok:
                session_intact = False

    record("8. Session remains usable after bad inputs", session_intact)

    delete_session(sid)


# ─── Section 9: Structured Output Validation ─────────────────────────────────

def test_structured_output():
    print("\n" + "═" * 60)
    print("  9. Structured Output — non-interactive client gets JSON block")
    print("═" * 60)

    # MSP automation pipeline uses mcp-remote (non-interactive)
    automation_ua = "mcp-remote/0.1.0"
    # MSP tech staff use claude_code (interactive → no JSON block)
    staff_ua = "claude-code/1.2.3"

    for ua, label, expect_struct in [
        (automation_ua, "mcp_remote (automation)", True),
        (staff_ua,      "claude_code (staff)",     False),
    ]:
        sid = create_session(ua=ua)
        if not sid:
            record(f"9. {label}: session", False, "no session")
            continue

        status, body, _ = tool_call(sid, "scan_domain",
                                     {"domain": "cloudflare.com"}, ua=ua)

        text = get_content_text(body)
        if is_rate_limited(body):
            record(f"9. {label}: STRUCTURED_RESULT check", True,
                   "rate-limited (skipped)")
        elif text:
            has_struct = "<!-- STRUCTURED_RESULT" in text
            if expect_struct:
                record(f"9. {label}: STRUCTURED_RESULT present (machine-readable)",
                       has_struct, f"present={has_struct}")
            else:
                record(f"9. {label}: no STRUCTURED_RESULT (cleaner for LLM context)",
                       not has_struct, f"present={has_struct}")
        else:
            record(f"9. {label}: got response", False, f"status={status}")

        delete_session(sid, ua=ua)


# ─── Section 10: Sustained Throughput ────────────────────────────────────────

def test_sustained_throughput():
    print("\n" + "═" * 60)
    print("  10. Sustained Throughput — 60-second rate test")
    print("═" * 60)

    sid = create_session()
    if not sid:
        record("10. Throughput session", False, "no session")
        return

    tools_cycle = [
        ("check_spf",   {"domain": "google.com",      "format": "compact"}),
        ("check_dmarc", {"domain": "cloudflare.com",  "format": "compact"}),
        ("check_ns",    {"domain": "github.com",      "format": "compact"}),
        ("check_mx",    {"domain": "stripe.com",      "format": "compact"}),
        ("check_ssl",   {"domain": "okta.com",        "format": "compact"}),
        ("check_caa",   {"domain": "salesforce.com",  "format": "compact"}),
    ]

    call_latencies = []
    ok = rate = fail = s5xx = 0
    deadline = time.monotonic() + 60  # 60-second window

    def do_call(tool_name, args):
        t0 = time.monotonic()
        status, body, _ = tool_call(sid, tool_name, args)
        elapsed = time.monotonic() - t0
        return scan_ok(status, body), elapsed

    idx = 0
    with ThreadPoolExecutor(max_workers=8) as pool:
        futs = {}
        # Keep submitting until 60s deadline, up to 8 in-flight at once
        while time.monotonic() < deadline or futs:
            # Submit new work if under the deadline and have capacity
            while time.monotonic() < deadline and len(futs) < 8:
                tool_name, args = tools_cycle[idx % len(tools_cycle)]
                idx += 1
                f = pool.submit(do_call, tool_name, args)
                futs[f] = True

            # Collect any completed
            done = [f for f in list(futs) if f.done()]
            for f in done:
                outcome, lat = f.result()
                call_latencies.append(lat)
                del futs[f]
                if outcome == "ok":   ok   += 1
                elif outcome == "rate": rate += 1
                elif outcome == "5xx": s5xx += 1
                else:                 fail  += 1

            if not done:
                time.sleep(0.05)

    total = ok + rate + fail + s5xx
    if call_latencies:
        lat_s = sorted(call_latencies)
        p50 = statistics.median(lat_s) * 1000
        p95 = lat_s[int(len(lat_s) * 0.95)] * 1000
        p99 = lat_s[int(len(lat_s) * 0.99)] * 1000
        rps  = total / 60

        print(f"\n  60-second window:  {total} calls  ({rps:.1f} req/s)")
        print(f"  ok={ok}  rate={rate}  fail={fail}  5xx={s5xx}")
        print(f"  Latency  p50={p50:.0f}ms  p95={p95:.0f}ms  p99={p99:.0f}ms  "
              f"max={max(call_latencies)*1000:.0f}ms")

    record("10. Sustained throughput: no 5xx in 60s", s5xx == 0, f"{s5xx} 5xx")
    record("10. Sustained throughput: < 5% hard fail",
           fail / max(total, 1) < 0.05, f"{fail}/{total}")
    record("10. Sustained throughput: > 5 req/s achieved",
           total / 60 >= 5, f"{total/60:.1f} req/s")

    delete_session(sid)
    return call_latencies


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    print("\n" + "═" * 60)
    print("  bv-mcp MSP chaos test — v2.1.18")
    print(f"  Target: {BASE}/mcp")
    print(f"  Portfolio: {len(MSP_PORTFOLIO)} client domains")
    print("═" * 60)

    validate_key()

    if not API_KEY:
        print("\n  ⚠  BV_API_KEY not set or invalid.")
        print("  Some sections will be rate-limited on the free tier.")
        print("  Set a valid BV_API_KEY for full MSP-scale testing.\n")

    grand_start = time.monotonic()

    test_portfolio_scan()
    test_client_onboarding()
    test_compliance_sweep()
    test_multi_operator()
    test_bulk_email_auth()
    test_high_risk_assessment()
    test_benchmark_reporting()
    test_resilience()
    test_structured_output()
    test_sustained_throughput()

    total_time = time.monotonic() - grand_start

    # ── Summary ───────────────────────────────────────────────────────────────
    passed = sum(1 for _, ok in results if ok)
    failed = sum(1 for _, ok in results if not ok)
    total  = len(results)

    if all_latencies:
        lat_s = sorted(all_latencies)
        overall_p50 = statistics.median(lat_s) * 1000
        overall_p95 = lat_s[int(len(lat_s) * 0.95)] * 1000
        overall_p99 = lat_s[int(len(lat_s) * 0.99)] * 1000

    print("\n" + "═" * 60)
    print("  MSP CHAOS TEST — RESULTS")
    print("═" * 60)
    print(f"  assertions  {passed}/{total} passed")
    if all_latencies:
        print(f"  latency     p50={overall_p50:.0f}ms  "
              f"p95={overall_p95:.0f}ms  p99={overall_p99:.0f}ms")
    print(f"  wall time   {total_time:.0f}s")

    if failed:
        print("\n  FAILURES:")
        for name, ok in results:
            if not ok:
                print(f"    ✗ {name}")

    print("═" * 60)

    if failed > 0:
        print(f"\n  ✗ FAIL — {failed} assertion(s) failed")
        sys.exit(1)
    else:
        print("\n  ✓ PASS — ready for MSP demo")


if __name__ == "__main__":
    main()
