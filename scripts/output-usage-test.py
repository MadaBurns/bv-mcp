#!/usr/bin/env python3
"""
Compare tool OUTPUT context usage: compact vs full format.
Also measures tool definitions (schema) overhead.
"""

import json
import subprocess
import sys
import os

BASE = os.getenv("BV_MCP_URL", "https://dns-mcp.blackveilsecurity.com/mcp")
KEY = os.getenv("BV_API_KEY", "")
DOMAIN = os.getenv("TEST_DOMAIN", "blackveilsecurity.com")

TOOLS = [
    ("scan_domain", {"domain": DOMAIN}),
    ("check_spf", {"domain": DOMAIN}),
    ("check_dmarc", {"domain": DOMAIN}),
    ("check_dkim", {"domain": DOMAIN}),
    ("check_mx", {"domain": DOMAIN}),
    ("check_ssl", {"domain": DOMAIN}),
    ("check_dnssec", {"domain": DOMAIN}),
    ("check_ns", {"domain": DOMAIN}),
    ("check_caa", {"domain": DOMAIN}),
    ("check_bimi", {"domain": DOMAIN}),
    ("check_mta_sts", {"domain": DOMAIN}),
    ("check_http_security", {"domain": DOMAIN}),
    ("check_dane", {"domain": DOMAIN}),
    ("check_svcb_https", {"domain": DOMAIN}),
    ("check_subdomailing", {"domain": DOMAIN}),
    ("check_shadow_domains", {"domain": DOMAIN}),
    ("check_txt_hygiene", {"domain": DOMAIN}),
    ("check_mx_reputation", {"domain": DOMAIN}),
    ("check_srv", {"domain": DOMAIN}),
    ("check_zone_hygiene", {"domain": DOMAIN}),
    ("check_lookalikes", {"domain": DOMAIN}),
    ("check_resolver_consistency", {"domain": DOMAIN, "record_type": "A"}),
    ("check_dane_https", {"domain": DOMAIN}),
    ("check_tlsrpt", {"domain": DOMAIN}),
    ("map_compliance", {"domain": DOMAIN}),
    ("generate_fix_plan", {"domain": DOMAIN}),
    ("simulate_attack_paths", {"domain": DOMAIN}),
    ("assess_spoofability", {"domain": DOMAIN}),
    ("map_supply_chain", {"domain": DOMAIN}),
    ("batch_scan", {"domains": [DOMAIN, "example.com"]}),
    ("compare_domains", {"domains": [DOMAIN, "example.com"]}),
    ("discover_subdomains", {"domain": DOMAIN}),
    ("resolve_spf_chain", {"domain": DOMAIN}),
    ("compare_baseline", {"domain": DOMAIN, "baseline": {"require_dmarc_reject": True}}),
    ("analyze_drift", {"domain": DOMAIN, "baseline": {"score": 70, "grade": "C"}}),
    ("get_benchmark", {"industry": "technology"}),
    ("get_provider_insights", {"provider": "google"}),
    ("generate_spf_record", {"domain": DOMAIN}),
    ("generate_dmarc_record", {"domain": DOMAIN}),
    ("generate_dkim_config", {"domain": DOMAIN, "provider": "google"}),
    ("generate_mta_sts_policy", {"domain": DOMAIN}),
    ("generate_rollout_plan", {"domain": DOMAIN}),
    ("validate_fix", {"domain": DOMAIN, "check_name": "check_spf"}),
    ("explain_finding", {"finding_id": "spf_softfail"}),
]


def jsonrpc(method, params, rid):
    return {"jsonrpc": "2.0", "id": rid, "method": method, "params": params}


def curl(url, body, sid=None, ua="claude-desktop/0.10.0", timeout=45):
    cmd = [
        "curl", "-s", "--max-time", str(timeout),
        "-X", "POST", url,
        "-H", "Content-Type: application/json",
        "-H", f"User-Agent: {ua}",
    ]
    if KEY:
        cmd += ["-H", f"Authorization: Bearer {KEY}"]
    if sid:
        cmd += ["-H", f"Mcp-Session-Id: {sid}"]
    cmd += ["-d", json.dumps(body)]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
    return r.stdout


def create_session(ua):
    cmd = [
        "curl", "-s", "-D", "-", "--max-time", "15",
        "-X", "POST", BASE,
        "-H", "Content-Type: application/json",
        "-H", f"User-Agent: {ua}",
    ]
    if KEY:
        cmd += ["-H", f"Authorization: Bearer {KEY}"]
    cmd += ["-d", json.dumps(jsonrpc("initialize", {
        "protocolVersion": "2025-03-26",
        "capabilities": {},
        "clientInfo": {"name": "output-test", "version": "1.0"},
    }, 1))]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    for line in r.stdout.split("\n"):
        if line.lower().startswith("mcp-session-id:"):
            sid = line.split(":", 1)[1].strip()
            curl(BASE, {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}, sid, ua)
            return sid
    return None


def extract_text(resp):
    try:
        d = json.loads(resp)
        if "error" in d:
            return "[error]", 0, 0
        text = "".join(
            b.get("text", "")
            for b in d.get("result", {}).get("content", [])
            if b.get("type") == "text"
        )
        return text, len(text), len(text) // 4
    except Exception:
        return "", 0, 0


def main():
    if not KEY:
        print("ERROR: Set BV_API_KEY env var")
        sys.exit(1)

    print("=" * 90)
    print(" Tool output context usage — compact vs full")
    print(f" Target: {BASE}  Domain: {DOMAIN}")
    print("=" * 90)

    # Create sessions
    ua_c = "claude-desktop/0.10.0"   # interactive → compact auto
    ua_f = "mcp-remote/1.0"          # non-interactive → full auto

    sid_c = create_session(ua_c)
    sid_f = create_session(ua_f)
    if not sid_c or not sid_f:
        print("ERROR: Failed to create sessions")
        sys.exit(1)
    print(f"  compact session: {sid_c[:16]}...")
    print(f"  full session:    {sid_f[:16]}...")

    # ── Tool definitions overhead ──
    resp = curl(BASE, jsonrpc("tools/list", {}, 99), sid_c, ua_c)
    tools_data = json.loads(resp).get("result", {}).get("tools", [])
    schema_text = json.dumps(tools_data)
    schema_tokens = len(schema_text) // 4
    print(f"\n{'=' * 90}")
    print(f" TOOL DEFINITIONS (always in context for LLM)")
    print(f"{'=' * 90}")
    print(f"  {len(tools_data)} tools registered")
    print(f"  Schema JSON:  {len(schema_text):,} chars  ~{schema_tokens:,} tokens")
    print(f"  Context cost:  {schema_tokens/200_000*100:.1f}% of 200K window")

    # ── Tool outputs ──
    print(f"\n{'=' * 90}")
    print(f" TOOL OUTPUTS: compact vs full ({len(TOOLS)} tools)")
    print(f"{'=' * 90}")
    header = f"  {'Tool':<28s} {'Compact':>9s} {'Full':>9s} {'Ratio':>6s} {'Delta':>9s}"
    sep = f"  {'─' * 28} {'─' * 9} {'─' * 9} {'─' * 6} {'─' * 9}"
    print(header)
    print(sep)

    total_c = total_f = 0
    rows = []

    for i, (name, args) in enumerate(TOOLS, 1):
        print(f"  [{i:2d}/{len(TOOLS)}] {name:<28s}", end="", flush=True)

        args_c = {**args, "format": "compact"}
        args_f = {**args, "format": "full"}

        resp_c = curl(BASE, jsonrpc("tools/call", {"name": name, "arguments": args_c}, i + 10), sid_c, ua_c)
        resp_f = curl(BASE, jsonrpc("tools/call", {"name": name, "arguments": args_f}, i + 10), sid_f, ua_f)

        _, c_chars, c_tok = extract_text(resp_c)
        text_f, f_chars, f_tok = extract_text(resp_f)

        has_struct = "<!-- STRUCTURED_RESULT" in text_f
        total_c += c_tok
        total_f += f_tok

        ratio = f"{f_tok / c_tok:.1f}x" if c_tok > 0 else "n/a"
        delta = f_tok - c_tok
        struct = " +JSON" if has_struct else ""

        rows.append((name, c_tok, f_tok, ratio, delta, struct))
        print(f" {c_tok:>7,} tk {f_tok:>7,} tk {ratio:>6s} {delta:>+8,} tk{struct}")

    # Sort by full tokens descending
    rows.sort(key=lambda r: r[2], reverse=True)
    print(f"\n  {'─' * 28} {'─' * 9} {'─' * 9} {'─' * 6} {'─' * 9}")
    print(f"  SORTED BY FULL OUTPUT SIZE:")
    print(f"  {'─' * 28} {'─' * 9} {'─' * 9} {'─' * 6} {'─' * 9}")
    for name, c_tok, f_tok, ratio, delta, struct in rows:
        print(f"  {name:<28s} {c_tok:>7,} tk {f_tok:>7,} tk {ratio:>6s} {delta:>+8,} tk{struct}")
    print(sep)

    ratio_t = f"{total_f / total_c:.1f}x" if total_c > 0 else "n/a"
    print(f"  {'TOTAL':<28s} {total_c:>7,} tk {total_f:>7,} tk {ratio_t:>6s} {total_f - total_c:>+8,} tk")

    # ── Summary ──
    scan_c = next((r for r in rows if r[0] == "scan_domain"), None)
    print(f"\n{'=' * 90}")
    print(f" CONTEXT BUDGET SUMMARY (Claude 200K window)")
    print(f"{'=' * 90}")
    print(f"  Tool definitions (schema):       ~{schema_tokens:>6,} tokens  ({schema_tokens / 200_000 * 100:.1f}%)")
    if scan_c:
        print(f"  scan_domain compact:             ~{scan_c[1]:>6,} tokens  ({scan_c[1] / 200_000 * 100:.2f}%)")
        print(f"  scan_domain full:                ~{scan_c[2]:>6,} tokens  ({scan_c[2] / 200_000 * 100:.2f}%)")
    print(f"  All {len(TOOLS)} tools compact:            ~{total_c:>6,} tokens  ({total_c / 200_000 * 100:.1f}%)")
    print(f"  All {len(TOOLS)} tools full:               ~{total_f:>6,} tokens  ({total_f / 200_000 * 100:.1f}%)")
    print(f"  Full format overhead:            +{total_f - total_c:>6,} tokens  ({(total_f - total_c) / 200_000 * 100:.1f}%)")
    print(f"  Definitions + all compact:       ~{schema_tokens + total_c:>6,} tokens  ({(schema_tokens + total_c) / 200_000 * 100:.1f}%)")
    print(f"  Definitions + all full:          ~{schema_tokens + total_f:>6,} tokens  ({(schema_tokens + total_f) / 200_000 * 100:.1f}%)")
    print(f"{'=' * 90}")


if __name__ == "__main__":
    main()
