#!/usr/bin/env python3
"""
Simulate a full Claude Desktop conversation: engineer troubleshooting a domain.

Measures cumulative context usage across realistic multi-turn tool calls.
Models what an LLM actually sees in its context window during a real session.
"""

import json
import subprocess
import sys
import os
import time

BASE = os.getenv("BV_MCP_URL", "https://dns-mcp.blackveilsecurity.com/mcp")
KEY = os.getenv("BV_API_KEY", "")
DOMAIN = os.getenv("TEST_DOMAIN", "tesla.com")
UA = "claude-desktop/0.10.0"


def jsonrpc(method, params, rid):
    return {"jsonrpc": "2.0", "id": rid, "method": method, "params": params}


def curl(url, body, sid=None, timeout=45):
    cmd = [
        "curl", "-s", "--max-time", str(timeout),
        "-X", "POST", url,
        "-H", "Content-Type: application/json",
        "-H", f"User-Agent: {UA}",
    ]
    if KEY:
        cmd += ["-H", f"Authorization: Bearer {KEY}"]
    if sid:
        cmd += ["-H", f"Mcp-Session-Id: {sid}"]
    cmd += ["-d", json.dumps(body)]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
    return r.stdout


def create_session():
    cmd = [
        "curl", "-s", "-D", "-", "--max-time", "15",
        "-X", "POST", BASE,
        "-H", "Content-Type: application/json",
        "-H", f"User-Agent: {UA}",
    ]
    if KEY:
        cmd += ["-H", f"Authorization: Bearer {KEY}"]
    cmd += ["-d", json.dumps(jsonrpc("initialize", {
        "protocolVersion": "2025-03-26",
        "capabilities": {},
        "clientInfo": {"name": "Claude", "version": "0.10.0"},
    }, 1))]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    for line in r.stdout.split("\n"):
        if line.lower().startswith("mcp-session-id:"):
            sid = line.split(":", 1)[1].strip()
            curl(BASE, {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}, sid)
            return sid
    return None


def call_tool(sid, name, args, rid):
    body = jsonrpc("tools/call", {"name": name, "arguments": args}, rid)
    t0 = time.monotonic()
    resp = curl(BASE, body, sid)
    elapsed = time.monotonic() - t0
    try:
        data = json.loads(resp)
        if "error" in data:
            return data["error"].get("message", "error"), 0, elapsed, True
        text = "".join(
            b.get("text", "")
            for b in data.get("result", {}).get("content", [])
            if b.get("type") == "text"
        )
        return text, len(text), elapsed, False
    except Exception as e:
        return str(e), 0, elapsed, True


# ── Conversation turns ──
# Each turn: (user_message, tool_name, tool_args, assistant_summary)
# assistant_summary models what Claude would say back (~tokens of assistant text)

CONVERSATION = [
    # Turn 1: Engineer starts
    {
        "user": f"Can you run a full security audit on {DOMAIN}? We just took over this domain and I need to know where we stand.",
        "tool": "scan_domain",
        "args": {"domain": DOMAIN, "format": "compact"},
        "assistant": f"I've completed a full DNS and email security scan of {DOMAIN}. Here's the overview:\n\n"
                     "The domain scored {{score}} with a grade of {{grade}}. Let me walk you through the key findings.\n\n"
                     "The most critical issues I found are around email authentication — specifically SPF and DMARC configuration. "
                     "There are also some infrastructure hardening opportunities. Would you like me to drill into any specific area?",
    },
    # Turn 2: Drill into SPF
    {
        "user": "The SPF issues look concerning. Can you check SPF in detail and show me the full include chain?",
        "tool": "check_spf",
        "args": {"domain": DOMAIN},
        "assistant": "Here's the detailed SPF analysis. The record has {{detail}}. "
                     "Let me also trace the full include chain to see your lookup count.",
    },
    {
        "user": None,  # continuation — no new user message
        "tool": "resolve_spf_chain",
        "args": {"domain": DOMAIN},
        "assistant": "The SPF include chain shows {{detail}}. This is important because RFC 7208 limits you to 10 DNS lookups. "
                     "Exceeding this causes SPF to permerror, which means receivers treat it as if you have no SPF at all.",
    },
    # Turn 3: Check DMARC
    {
        "user": "What about DMARC? Is it enforcing?",
        "tool": "check_dmarc",
        "args": {"domain": DOMAIN},
        "assistant": "The DMARC analysis shows {{detail}}. "
                     "This means that even if SPF or DKIM fails, mailbox providers won't quarantine or reject the messages — "
                     "they'll just deliver them. An attacker can spoof your domain freely.",
    },
    # Turn 4: Check DKIM
    {
        "user": "And DKIM? Are we signing anything?",
        "tool": "check_dkim",
        "args": {"domain": DOMAIN},
        "assistant": "DKIM probing results: {{detail}}. "
                     "Without DKIM signing, DMARC alignment relies entirely on SPF, which is fragile when emails are forwarded.",
    },
    # Turn 5: How spoofable are we?
    {
        "user": "So how easily can someone spoof us right now? Give me a risk score.",
        "tool": "assess_spoofability",
        "args": {"domain": DOMAIN},
        "assistant": "Your spoofability score is {{detail}} out of 100 (higher = more spoofable). "
                     "This factors in your SPF policy, DMARC enforcement level, DKIM presence, and MTA-STS status. "
                     "I'd recommend addressing the email authentication gaps as priority 1.",
    },
    # Turn 6: Attack paths
    {
        "user": "What attack paths does this open up? I need to present this to the security team.",
        "tool": "simulate_attack_paths",
        "args": {"domain": DOMAIN},
        "assistant": "Here are the attack paths an adversary could exploit based on your current DNS posture. "
                     "The most critical ones involve email spoofing and subdomain takeover. "
                     "I've included severity, feasibility, and specific mitigation steps for each.",
    },
    # Turn 7: Check MTA-STS
    {
        "user": "One of the attack paths mentions SMTP downgrade. Check MTA-STS for me.",
        "tool": "check_mta_sts",
        "args": {"domain": DOMAIN},
        "assistant": "MTA-STS status: {{detail}}. Without MTA-STS in enforce mode, an active network attacker "
                     "can downgrade the SMTP connection to plaintext and intercept emails in transit.",
    },
    # Turn 8: SSL check
    {
        "user": "While we're at it, is our SSL/TLS properly configured?",
        "tool": "check_ssl",
        "args": {"domain": DOMAIN},
        "assistant": "SSL/TLS analysis: {{detail}}. The certificate is valid and the configuration looks solid on that front.",
    },
    # Turn 9: Who's in our supply chain?
    {
        "user": "I want to understand all the third-party services that have DNS access or can send email as us.",
        "tool": "map_supply_chain",
        "args": {"domain": DOMAIN},
        "assistant": "Here's your DNS supply chain map. I've correlated SPF includes, NS delegation, TXT verifications, "
                     "SRV records, and CAA entries to show every third party with some level of trust. "
                     "Pay attention to the 'can send as you' category — those services can impersonate your domain.",
    },
    # Turn 10: Check for subdomain takeover
    {
        "user": "Are any of our subdomains at risk of takeover?",
        "tool": "discover_subdomains",
        "args": {"domain": DOMAIN},
        "assistant": "I found {{detail}} subdomains via Certificate Transparency logs. "
                     "Let me check for shadow domain risks across TLD variants too.",
    },
    {
        "user": None,
        "tool": "check_shadow_domains",
        "args": {"domain": DOMAIN},
        "assistant": "Shadow domain scan results: {{detail}}. These TLD variants of your domain could be used for phishing "
                     "if they're not defensively registered.",
    },
    # Turn 11: Compliance mapping
    {
        "user": "We need to pass our SOC 2 audit next quarter. How do we map against compliance frameworks?",
        "tool": "map_compliance",
        "args": {"domain": DOMAIN},
        "assistant": "Here's how your current DNS security posture maps to NIST 800-177, PCI DSS 4.0, SOC 2, and CIS Controls. "
                     "Several controls show partial or failing status that would need remediation before your SOC 2 audit.",
    },
    # Turn 12: Get benchmark
    {
        "user": "How do we compare to other companies in our industry?",
        "tool": "get_benchmark",
        "args": {"industry": "technology"},
        "assistant": "Here are the industry benchmarks. Your score puts you at the {{detail}} percentile. "
                     "The most common failures across the industry are missing DMARC enforcement and lack of DNSSEC.",
    },
    # Turn 13: Generate fix plan
    {
        "user": "OK, I'm convinced we need to fix this. Give me a prioritized remediation plan.",
        "tool": "generate_fix_plan",
        "args": {"domain": DOMAIN},
        "assistant": "Here's your prioritized fix plan, ordered by impact and effort. "
                     "I recommend starting with DMARC enforcement — it's the single highest-impact change. "
                     "Let me generate the specific DNS records you'll need.",
    },
    # Turn 14: Generate records
    {
        "user": "Generate the DMARC record for us. We want reject policy but need to monitor first.",
        "tool": "generate_dmarc_record",
        "args": {"domain": DOMAIN, "policy": "none", "rua": "dmarc-reports@" + DOMAIN},
        "assistant": "Here's your DMARC record starting with p=none for monitoring. "
                     "Deploy this first, monitor reports for 2-4 weeks, then we'll roll to quarantine and then reject.",
    },
    {
        "user": None,
        "tool": "generate_rollout_plan",
        "args": {"domain": DOMAIN},
        "assistant": "Here's a phased DMARC enforcement timeline with exact DNS records for each phase. "
                     "Phase 1 is monitoring (p=none), Phase 2 starts quarantining a percentage, "
                     "and Phase 3 moves to full reject. Each phase includes the exact TXT record to deploy.",
    },
    # Turn 15: Generate SPF fix
    {
        "user": "And fix the SPF record too — keep all existing includes but tighten the policy.",
        "tool": "generate_spf_record",
        "args": {"domain": DOMAIN},
        "assistant": "Here's the corrected SPF record. I've kept all your existing authorized senders "
                     "but tightened the policy. Make sure to replace the current record, don't add a second one.",
    },
    # Turn 16: Validate after conceptual fix
    {
        "user": "If we deploy these changes, can you verify SPF would pass?",
        "tool": "validate_fix",
        "args": {"domain": DOMAIN, "check_name": "check_spf"},
        "assistant": "I've re-run the SPF check. {{detail}}. Once you deploy the new record, "
                     "run this validation again to confirm it's picked up by DNS.",
    },
    # Turn 17: Final compare against baseline
    {
        "user": "Set a baseline at our current score so we can track improvement over time.",
        "tool": "compare_baseline",
        "args": {"domain": DOMAIN, "baseline": {"require_dmarc_reject": True, "require_spf_hardfail": True}},
        "assistant": "Baseline comparison set. Right now you're failing the DMARC reject and SPF hardfail requirements. "
                     "After deploying the fixes and completing the DMARC rollout, re-run this comparison to verify compliance.",
    },
    # Turn 18: Explain a specific finding
    {
        "user": "One more thing — can you explain what spf_too_many_lookups means? I need to put it in the Jira ticket.",
        "tool": "explain_finding",
        "args": {"finding_id": "spf_too_many_lookups"},
        "assistant": "Here's the full explanation of the SPF lookup limit finding, including impact and exact remediation steps. "
                     "You can copy this directly into the Jira ticket description.",
    },
]


def estimate_tokens(text):
    return len(text) // 4


def main():
    if not KEY:
        print("ERROR: Set BV_API_KEY env var")
        sys.exit(1)

    print("=" * 90)
    print(f" Claude Desktop conversation simulation — engineer troubleshooting {DOMAIN}")
    print(f" Target: {BASE}")
    print("=" * 90)

    sid = create_session()
    if not sid:
        print("ERROR: Failed to create session")
        sys.exit(1)
    print(f"  Session: {sid[:16]}...\n")

    # Track cumulative context
    # In a real conversation, the LLM sees:
    #   - System prompt (~2000 tokens)
    #   - Tool definitions (~7858 tokens from our test)
    #   - All previous user messages
    #   - All previous assistant messages
    #   - All previous tool outputs
    #   - Current user message

    SYSTEM_PROMPT_TOKENS = 2000
    TOOL_DEFS_TOKENS = 7858

    cumulative_user = 0
    cumulative_assistant = 0
    cumulative_tool_output = 0
    turn_num = 0
    rid = 10
    errors = []

    turn_data = []

    for step in CONVERSATION:
        user_msg = step["user"]
        tool_name = step["tool"]
        tool_args = step["args"]
        assistant_msg = step["assistant"]

        if user_msg:
            turn_num += 1

        rid += 1

        # User message tokens
        user_tok = estimate_tokens(user_msg) if user_msg else 0
        cumulative_user += user_tok

        # Call tool
        text, chars, elapsed, is_error = call_tool(sid, tool_name, tool_args, rid)

        if is_error:
            errors.append((tool_name, text[:80]))
            tool_tok = estimate_tokens(text)
        else:
            tool_tok = estimate_tokens(text)
        cumulative_tool_output += tool_tok

        # Assistant response tokens
        asst_tok = estimate_tokens(assistant_msg)
        cumulative_assistant += asst_tok

        # Total context at this point
        total_context = (
            SYSTEM_PROMPT_TOKENS
            + TOOL_DEFS_TOKENS
            + cumulative_user
            + cumulative_assistant
            + cumulative_tool_output
        )

        pct = total_context / 200_000 * 100

        status = "ERR" if is_error else "ok"
        label = f"Turn {turn_num}" if user_msg else f"  +cont"

        turn_data.append({
            "label": label,
            "tool": tool_name,
            "tool_tok": tool_tok,
            "asst_tok": asst_tok,
            "user_tok": user_tok,
            "elapsed": elapsed,
            "cumulative": total_context,
            "pct": pct,
            "status": status,
        })

        print(f"  {label:>8s}  {tool_name:<28s}  out={tool_tok:>5,} tk  "
              f"cumul={total_context:>7,} tk ({pct:>5.1f}%)  {elapsed:>5.1f}s  [{status}]")

    # ── Summary ──
    print(f"\n{'=' * 90}")
    print(f" CONVERSATION SUMMARY")
    print(f"{'=' * 90}")

    total = (
        SYSTEM_PROMPT_TOKENS
        + TOOL_DEFS_TOKENS
        + cumulative_user
        + cumulative_assistant
        + cumulative_tool_output
    )

    print(f"\n  Conversation turns:           {turn_num}")
    print(f"  Tool calls:                   {len(CONVERSATION)}")
    print(f"  Errors:                       {len(errors)}")
    print()
    print(f"  {'Component':<32s} {'Tokens':>8s}  {'% of 200K':>9s}")
    print(f"  {'─' * 32} {'─' * 8}  {'─' * 9}")
    print(f"  {'System prompt':<32s} {SYSTEM_PROMPT_TOKENS:>8,}  {SYSTEM_PROMPT_TOKENS/200_000*100:>8.1f}%")
    print(f"  {'Tool definitions (44 tools)':<32s} {TOOL_DEFS_TOKENS:>8,}  {TOOL_DEFS_TOKENS/200_000*100:>8.1f}%")
    print(f"  {'User messages (all turns)':<32s} {cumulative_user:>8,}  {cumulative_user/200_000*100:>8.1f}%")
    print(f"  {'Assistant messages (all turns)':<32s} {cumulative_assistant:>8,}  {cumulative_assistant/200_000*100:>8.1f}%")
    print(f"  {'Tool outputs (all calls)':<32s} {cumulative_tool_output:>8,}  {cumulative_tool_output/200_000*100:>8.1f}%")
    print(f"  {'─' * 32} {'─' * 8}  {'─' * 9}")
    print(f"  {'TOTAL AT END OF CONVERSATION':<32s} {total:>8,}  {total/200_000*100:>8.1f}%")
    print(f"  {'Remaining context':<32s} {200_000-total:>8,}  {(200_000-total)/200_000*100:>8.1f}%")

    # Context growth chart
    print(f"\n  Context growth across conversation:")
    print(f"  {'Turn':<10s} {'Cumulative':>10s}  {'Bar'}")
    print(f"  {'─' * 10} {'─' * 10}  {'─' * 40}")
    for td in turn_data:
        bar_len = int(td["pct"] / 100 * 40)
        bar = "█" * bar_len + "░" * (40 - bar_len)
        print(f"  {td['label']:<10s} {td['cumulative']:>8,} tk  {bar} {td['pct']:.1f}%")

    # Top tool outputs by size
    print(f"\n  Heaviest tool outputs in this conversation:")
    sorted_td = sorted(turn_data, key=lambda x: x["tool_tok"], reverse=True)
    for td in sorted_td[:5]:
        print(f"    {td['tool']:<28s} {td['tool_tok']:>5,} tokens")

    if errors:
        print(f"\n  ERRORS ({len(errors)}):")
        for name, msg in errors:
            print(f"    {name}: {msg}")

    print(f"\n{'=' * 90}")
    ok = len(CONVERSATION) - len(errors)
    print(f"  {ok}/{len(CONVERSATION)} tool calls succeeded, {turn_num} conversation turns")
    print(f"  Total wall time: sum of tool calls only (no assistant thinking time)")
    print(f"{'=' * 90}")

    if errors:
        sys.exit(1)


if __name__ == "__main__":
    main()
