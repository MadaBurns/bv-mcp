#!/usr/bin/env python3
"""
Test context/token usage of each MCP tool.

Measures response size (chars, estimated tokens) for all 44 tools
to understand context window impact in Claude Desktop / LLM clients.
"""

import json
import subprocess
import sys
import time
import os

BASE = os.getenv("BV_MCP_URL", "https://dns-mcp.blackveilsecurity.com/mcp")
API_KEY = os.getenv("BV_API_KEY", "")
DOMAIN = os.getenv("TEST_DOMAIN", "blackveilsecurity.com")
UA = "claude-desktop/0.10.0"

# All 44 tools with appropriate arguments
TOOLS = [
    # ── Core checks (scan-included) ──
    ("check_mx", {"domain": DOMAIN}),
    ("check_spf", {"domain": DOMAIN}),
    ("check_dmarc", {"domain": DOMAIN}),
    ("check_dkim", {"domain": DOMAIN}),
    ("check_dnssec", {"domain": DOMAIN}),
    ("check_ssl", {"domain": DOMAIN}),
    ("check_mta_sts", {"domain": DOMAIN}),
    ("check_ns", {"domain": DOMAIN}),
    ("check_caa", {"domain": DOMAIN}),
    ("check_bimi", {"domain": DOMAIN}),
    ("check_tlsrpt", {"domain": DOMAIN}),
    ("check_http_security", {"domain": DOMAIN}),
    ("check_dane", {"domain": DOMAIN}),
    ("check_dane_https", {"domain": DOMAIN}),
    ("check_svcb_https", {"domain": DOMAIN}),
    ("check_subdomailing", {"domain": DOMAIN}),

    # ── Standalone checks ──
    ("check_lookalikes", {"domain": DOMAIN}),
    ("check_shadow_domains", {"domain": DOMAIN}),
    ("check_txt_hygiene", {"domain": DOMAIN}),
    ("check_mx_reputation", {"domain": DOMAIN}),
    ("check_srv", {"domain": DOMAIN}),
    ("check_zone_hygiene", {"domain": DOMAIN}),
    ("check_resolver_consistency", {"domain": DOMAIN, "record_type": "A"}),

    # ── Meta / orchestration ──
    ("scan_domain", {"domain": DOMAIN, "format": "compact"}),
    ("batch_scan", {"domains": [DOMAIN, "example.com"]}),
    ("compare_domains", {"domains": [DOMAIN, "example.com"]}),
    ("compare_baseline", {"domain": DOMAIN, "baseline": {"require_dmarc_reject": True}}),

    # ── Intelligence ──
    ("assess_spoofability", {"domain": DOMAIN}),
    ("resolve_spf_chain", {"domain": DOMAIN}),
    ("discover_subdomains", {"domain": DOMAIN}),
    ("map_supply_chain", {"domain": DOMAIN}),
    ("map_compliance", {"domain": DOMAIN}),
    ("simulate_attack_paths", {"domain": DOMAIN}),
    ("analyze_drift", {"domain": DOMAIN, "baseline": {"score": 70, "grade": "C"}}),
    ("get_benchmark", {"industry": "technology"}),
    ("get_provider_insights", {"provider": "google"}),

    # ── Remediation ──
    ("generate_fix_plan", {"domain": DOMAIN}),
    ("generate_spf_record", {"domain": DOMAIN}),
    ("generate_dmarc_record", {"domain": DOMAIN}),
    ("generate_dkim_config", {"domain": DOMAIN, "provider": "google"}),
    ("generate_mta_sts_policy", {"domain": DOMAIN}),
    ("generate_rollout_plan", {"domain": DOMAIN}),
    ("validate_fix", {"domain": DOMAIN, "check_name": "check_spf"}),

    # ── Explain ──
    ("explain_finding", {"finding_id": "spf_softfail"}),
]


def jsonrpc(method, params, req_id):
    return {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}


def curl_call(url, body, session_id=None, timeout=30):
    headers = [
        "-H", "Content-Type: application/json",
        "-H", f"User-Agent: {UA}",
    ]
    if API_KEY:
        headers += ["-H", f"Authorization: Bearer {API_KEY}"]
    if session_id:
        headers += ["-H", f"Mcp-Session-Id: {session_id}"]

    cmd = [
        "curl", "-s", "-w", "\n__HTTP_CODE__%{http_code}",
        "--connect-timeout", "10", "--max-time", str(timeout),
        "-X", "POST", url,
        *headers,
        "-d", json.dumps(body),
    ]

    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
    parts = r.stdout.rsplit("__HTTP_CODE__", 1)
    body_text = parts[0].rstrip("\n") if parts else ""
    status = int(parts[1].strip()) if len(parts) > 1 else 0
    return status, body_text


def estimate_tokens(text):
    """Rough estimate: ~4 chars per token for English text."""
    return len(text) // 4


def create_session():
    body = jsonrpc("initialize", {
        "protocolVersion": "2025-03-26",
        "capabilities": {},
        "clientInfo": {"name": "context-usage-test", "version": "1.0"},
    }, 1)

    cmd = [
        "curl", "-s", "-D", "-",
        "--connect-timeout", "10", "--max-time", "15",
        "-X", "POST", BASE,
        "-H", "Content-Type: application/json",
        "-H", f"User-Agent: {UA}",
    ]
    if API_KEY:
        cmd += ["-H", f"Authorization: Bearer {API_KEY}"]
    cmd += ["-d", json.dumps(body)]

    r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    sid = None
    for line in r.stdout.split("\n"):
        if line.lower().startswith("mcp-session-id:"):
            sid = line.split(":", 1)[1].strip()
            break
    return sid


def main():
    print("=" * 80)
    print(" bv-mcp context usage test")
    print(f" Target: {BASE}")
    print(f" Domain: {DOMAIN}")
    print(f" Format: compact (Claude Desktop auto-detect)")
    print(f" Auth:   {'Bearer key' if API_KEY else 'none (free tier)'}")
    print("=" * 80)

    sid = create_session()
    if not sid:
        print("ERROR: Failed to create session")
        sys.exit(1)
    print(f" Session: {sid[:16]}...")

    # Send initialized notification
    curl_call(BASE, {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}, sid)

    results = []
    errors = []

    for i, (tool_name, args) in enumerate(TOOLS, 1):
        label = f"[{i:2d}/{len(TOOLS)}]"
        sys.stdout.write(f"  {label} {tool_name:<30s} ")
        sys.stdout.flush()

        body = jsonrpc("tools/call", {"name": tool_name, "arguments": args}, i + 10)
        t0 = time.monotonic()
        try:
            status, resp = curl_call(BASE, body, sid, timeout=45)
            elapsed = time.monotonic() - t0
        except Exception as e:
            elapsed = time.monotonic() - t0
            print(f"TIMEOUT after {elapsed:.1f}s — {e}")
            errors.append((tool_name, f"timeout: {e}"))
            continue

        if status != 200:
            print(f"HTTP {status} after {elapsed:.1f}s")
            errors.append((tool_name, f"HTTP {status}"))
            continue

        try:
            data = json.loads(resp)
        except json.JSONDecodeError:
            print(f"invalid JSON after {elapsed:.1f}s")
            errors.append((tool_name, "invalid JSON"))
            continue

        if "error" in data:
            err_msg = data["error"].get("message", "unknown")
            print(f"RPC error: {err_msg[:60]} ({elapsed:.1f}s)")
            errors.append((tool_name, f"rpc: {err_msg[:80]}"))
            continue

        # Extract text content
        content = data.get("result", {}).get("content", [])
        text = ""
        for block in content:
            if block.get("type") == "text":
                text += block.get("text", "")

        chars = len(text)
        tokens = estimate_tokens(text)
        lines = text.count("\n") + 1
        has_structured = "<!-- STRUCTURED_RESULT" in text

        results.append({
            "tool": tool_name,
            "chars": chars,
            "tokens": tokens,
            "lines": lines,
            "elapsed": round(elapsed, 2),
            "structured": has_structured,
        })

        struct_flag = " +JSON" if has_structured else ""
        print(f"{chars:>6,} chars  ~{tokens:>5,} tok  {lines:>4} lines  {elapsed:>5.1f}s{struct_flag}")

    # ── Summary ──
    print("\n" + "=" * 80)
    print(" SUMMARY")
    print("=" * 80)

    if results:
        results.sort(key=lambda r: r["tokens"], reverse=True)

        total_chars = sum(r["chars"] for r in results)
        total_tokens = sum(r["tokens"] for r in results)
        total_time = sum(r["elapsed"] for r in results)

        print(f"\n  {'Tool':<30s} {'Chars':>8s} {'~Tokens':>8s} {'Lines':>6s} {'Time':>6s}")
        print(f"  {'─' * 30} {'─' * 8} {'─' * 8} {'─' * 6} {'─' * 6}")
        for r in results:
            flag = " *" if r["structured"] else ""
            print(f"  {r['tool']:<30s} {r['chars']:>8,} {r['tokens']:>8,} {r['lines']:>6} {r['elapsed']:>5.1f}s{flag}")
        print(f"  {'─' * 30} {'─' * 8} {'─' * 8} {'─' * 6} {'─' * 6}")
        print(f"  {'TOTAL':<30s} {total_chars:>8,} {total_tokens:>8,} {'':>6s} {total_time:>5.1f}s")

        # Context budget analysis
        print(f"\n  Context budget impact (Claude 200K window):")
        print(f"    scan_domain alone:  ", end="")
        scan = next((r for r in results if r["tool"] == "scan_domain"), None)
        if scan:
            pct = scan["tokens"] / 200_000 * 100
            print(f"~{scan['tokens']:,} tokens ({pct:.1f}%)")

        print(f"    All 16 scan checks: ", end="")
        scan_tools = [r for r in results if r["tool"].startswith("check_") and r["tool"] not in
                      ("check_lookalikes", "check_shadow_domains", "check_txt_hygiene",
                       "check_mx_reputation", "check_srv", "check_zone_hygiene",
                       "check_resolver_consistency")]
        if scan_tools:
            scan_tok = sum(r["tokens"] for r in scan_tools)
            pct = scan_tok / 200_000 * 100
            print(f"~{scan_tok:,} tokens ({pct:.1f}%)")

        print(f"    All {len(results)} tools:      ~{total_tokens:,} tokens ({total_tokens / 200_000 * 100:.1f}%)")

        # Top 5 heaviest
        print(f"\n  Top 5 heaviest tools:")
        for r in results[:5]:
            print(f"    {r['tool']:<30s} ~{r['tokens']:>6,} tokens")

    if errors:
        print(f"\n  ERRORS ({len(errors)}):")
        for name, msg in errors:
            print(f"    {name}: {msg}")

    print("\n" + "=" * 80)
    ok = len(results)
    fail = len(errors)
    print(f"  {ok} succeeded, {fail} failed")
    print("=" * 80)

    if fail > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
