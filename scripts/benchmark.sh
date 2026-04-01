#!/usr/bin/env bash
# Blackveil DNS MCP Benchmark & Stress Test
# Tests latency, throughput, and correctness across all tool categories.
set -euo pipefail

BASE="https://dns-mcp.blackveilsecurity.com"
DOMAIN="blackveilsecurity.com"

echo "═══════════════════════════════════════════════════════════════"
echo "  BLACKVEIL DNS MCP — Benchmark & Stress Test"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "Target: $BASE"
echo "Domain: $DOMAIN"
echo "Date:   $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ""

# ─── Helper: initialize session ───────────────────────────────────────
init_session() {
  local headers
  headers=$(mktemp)
  curl -s -X POST "$BASE/mcp" \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json' \
    -D "$headers" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"benchmark","version":"1.0"}}}' > /dev/null
  grep -i 'mcp-session-id:' "$headers" | sed 's/.*: //' | tr -d '\r\n'
  rm -f "$headers"
}

# ─── Helper: call a tool and measure ──────────────────────────────────
call_tool() {
  local sid="$1" name="$2" args="$3" label="$4"
  local start end elapsed size response

  start=$(python3 -c "import time; print(int(time.time()*1000))")
  response=$(curl -s -X POST "$BASE/mcp" \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json' \
    -H "Mcp-Session-Id: $sid" \
    -H "User-Agent: claude-code/1.0" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":99,\"method\":\"tools/call\",\"params\":{\"name\":\"$name\",\"arguments\":$args}}")
  end=$(python3 -c "import time; print(int(time.time()*1000))")
  elapsed=$((end - start))
  size=$(echo "$response" | wc -c | tr -d ' ')

  # Check for errors
  local is_error
  is_error=$(echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin); print('ERROR' if d.get('error') or (d.get('result',{}).get('isError')) else 'OK')" 2>/dev/null || echo "PARSE_ERROR")

  printf "  %-30s %4dms  %6s B  %s\n" "$label" "$elapsed" "$size" "$is_error"
}

# ─── 1. Health Check ──────────────────────────────────────────────────
echo "─── 1. Health Check ───────────────────────────────────────────"
HEALTH_START=$(python3 -c "import time; print(int(time.time()*1000))")
HEALTH=$(curl -s "$BASE/health")
HEALTH_END=$(python3 -c "import time; print(int(time.time()*1000))")
echo "  Health: $(echo "$HEALTH" | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])" 2>/dev/null)  $((HEALTH_END - HEALTH_START))ms"
echo ""

# ─── 2. Session Init ─────────────────────────────────────────────────
echo "─── 2. Session Initialization ─────────────────────────────────"
INIT_START=$(python3 -c "import time; print(int(time.time()*1000))")
SID=$(init_session)
INIT_END=$(python3 -c "import time; print(int(time.time()*1000))")
echo "  Session: ${SID:0:16}...  $((INIT_END - INIT_START))ms"
echo ""

# ─── 3. Protocol Methods ─────────────────────────────────────────────
echo "─── 3. Protocol Methods ───────────────────────────────────────"
for METHOD in "tools/list" "prompts/list" "resources/list"; do
  START=$(python3 -c "import time; print(int(time.time()*1000))")
  RESP=$(curl -s -X POST "$BASE/mcp" \
    -H 'Content-Type: application/json' -H 'Accept: application/json' \
    -H "Mcp-Session-Id: $SID" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":99,\"method\":\"$METHOD\",\"params\":{}}")
  END=$(python3 -c "import time; print(int(time.time()*1000))")
  SIZE=$(echo "$RESP" | wc -c | tr -d ' ')
  printf "  %-20s %4dms  %6s B\n" "$METHOD" "$((END - START))" "$SIZE"
done
echo ""

# ─── 4. Individual Tool Latency ───────────────────────────────────────
echo "─── 4. Tool Latency (single calls) ────────────────────────────"

# Core checks
call_tool "$SID" "check_spf" "{\"domain\":\"$DOMAIN\"}" "check_spf"
call_tool "$SID" "check_dmarc" "{\"domain\":\"$DOMAIN\"}" "check_dmarc"
call_tool "$SID" "check_dkim" "{\"domain\":\"$DOMAIN\"}" "check_dkim"
call_tool "$SID" "check_mx" "{\"domain\":\"$DOMAIN\"}" "check_mx"
call_tool "$SID" "check_ssl" "{\"domain\":\"$DOMAIN\"}" "check_ssl"
call_tool "$SID" "check_ns" "{\"domain\":\"$DOMAIN\"}" "check_ns"

# Scan
call_tool "$SID" "scan_domain" "{\"domain\":\"$DOMAIN\"}" "scan_domain"

# New Phase 1-4 tools
call_tool "$SID" "generate_fix_plan" "{\"domain\":\"$DOMAIN\"}" "generate_fix_plan"
call_tool "$SID" "generate_spf_record" "{\"domain\":\"$DOMAIN\"}" "generate_spf_record"
call_tool "$SID" "generate_dmarc_record" "{\"domain\":\"$DOMAIN\"}" "generate_dmarc_record"
call_tool "$SID" "generate_dkim_config" "{\"domain\":\"$DOMAIN\"}" "generate_dkim_config"
call_tool "$SID" "generate_mta_sts_policy" "{\"domain\":\"$DOMAIN\"}" "generate_mta_sts_policy"
call_tool "$SID" "assess_spoofability" "{\"domain\":\"$DOMAIN\"}" "assess_spoofability"
call_tool "$SID" "get_benchmark" "{}" "get_benchmark"
call_tool "$SID" "get_provider_insights" "{\"provider\":\"google workspace\"}" "get_provider_insights"
call_tool "$SID" "explain_finding" "{\"checkType\":\"SPF\",\"status\":\"fail\"}" "explain_finding"
call_tool "$SID" "compare_baseline" "{\"domain\":\"$DOMAIN\",\"baseline\":{\"grade\":\"B\",\"require_spf\":true}}" "compare_baseline"
echo ""

# ─── 5. Throughput Test ───────────────────────────────────────────────
echo "─── 5. Throughput Test (health endpoint) ──────────────────────"
echo "  50 requests, 10 concurrent..."
hey -n 50 -c 10 -m GET "$BASE/health" 2>&1 | grep -E "Requests/sec|Average|Fastest|Slowest|Status"
echo ""

# ─── 6. MCP Throughput (tools/list) ───────────────────────────────────
echo "─── 6. MCP Throughput (tools/list, 30 req, 5 concurrent) ─────"
hey -n 30 -c 5 -m POST \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -H "Mcp-Session-Id: $SID" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  "$BASE/mcp" 2>&1 | grep -E "Requests/sec|Average|Fastest|Slowest|Status"
echo ""

# ─── 7. Scan Throughput ───────────────────────────────────────────────
echo "─── 7. Scan Throughput (5 domains, sequential) ────────────────"
for D in "anthropic.com" "cloudflare.com" "google.com" "github.com" "example.com"; do
  call_tool "$SID" "scan_domain" "{\"domain\":\"$D\"}" "scan $D"
done
echo ""

# ─── 8. Context Size Summary ─────────────────────────────────────────
echo "─── 8. Context Size Summary ───────────────────────────────────"
TOOLS_SIZE=$(curl -s -X POST "$BASE/mcp" \
  -H 'Content-Type: application/json' -H 'Accept: application/json' \
  -H "Mcp-Session-Id: $SID" \
  -d '{"jsonrpc":"2.0","id":99,"method":"tools/list","params":{}}' | wc -c | tr -d ' ')
PROMPTS_SIZE=$(curl -s -X POST "$BASE/mcp" \
  -H 'Content-Type: application/json' -H 'Accept: application/json' \
  -H "Mcp-Session-Id: $SID" \
  -d '{"jsonrpc":"2.0","id":99,"method":"prompts/list","params":{}}' | wc -c | tr -d ' ')
echo "  tools/list:    $TOOLS_SIZE bytes (~$((TOOLS_SIZE / 4)) tokens)"
echo "  prompts/list:  $PROMPTS_SIZE bytes (~$((PROMPTS_SIZE / 4)) tokens)"
echo "  Session total: $((TOOLS_SIZE + PROMPTS_SIZE)) bytes (~$(((TOOLS_SIZE + PROMPTS_SIZE) / 4)) tokens)"
echo ""

echo "═══════════════════════════════════════════════════════════════"
echo "  Benchmark complete."
echo "═══════════════════════════════════════════════════════════════"
