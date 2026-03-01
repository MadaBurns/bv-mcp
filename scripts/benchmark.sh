#!/usr/bin/env bash
# Benchmark script for BLACKVEIL Scanner MCP endpoint.
# Usage: ./scripts/benchmark.sh [domain...]
#        ./scripts/benchmark.sh cloudflare.com google.com microsoft.com
#        BV_API_KEY=your-key ./scripts/benchmark.sh cloudflare.com
#
# Options via env vars:
#   BV_API_KEY       — bearer token (bypasses rate limiting)
#   BV_ENDPOINT      — MCP endpoint URL (default: production)
#   BV_COOLDOWN      — seconds between domains (default: 65, skipped if authenticated)

set -euo pipefail

ENDPOINT="${BV_ENDPOINT:-https://dns-mcp.blackveilsecurity.com/mcp}"
COOLDOWN="${BV_COOLDOWN:-75}"
AUTH_HEADER=""
AUTHENTICATED=false
if [[ -n "${BV_API_KEY:-}" ]]; then
	AUTH_HEADER="Authorization: Bearer $BV_API_KEY"
	AUTHENTICATED=true
fi

# Collect domains from args (default: cloudflare.com)
DOMAINS=("${@:-cloudflare.com}")
if [[ ${#DOMAINS[@]} -eq 0 ]]; then
	DOMAINS=(cloudflare.com)
fi

TOOLS=(
	check_mx
	check_spf
	check_dmarc
	check_dkim
	check_dnssec
	check_ssl
	check_mta_sts
	check_ns
	check_caa
	scan_domain
)

# Build common curl args
CURL_ARGS=(-s -w "\n%{http_code} %{time_total}")
if [[ -n "$AUTH_HEADER" ]]; then
	CURL_ARGS+=(-H "$AUTH_HEADER")
fi

HEADER_FILE=$(mktemp)
trap 'rm -f "$HEADER_FILE"' EXIT

# ---------------------------------------------------------------------------
# Run benchmark for a single domain (uses shared session)
# ---------------------------------------------------------------------------
run_domain() {
	local domain="$1"
	local session_id="$2"
	local pass=0
	local fail=0
	local total_time=0
	local req_id=${3:-1}

	printf "\n%-22s %6s %8s\n" "TOOL" "STATUS" "TIME(s)"
	printf "%-22s %6s %8s\n" "----" "------" "-------"

	for TOOL in "${TOOLS[@]}"; do
		req_id=$((req_id + 1))

		if [[ "$TOOL" == "check_dkim" ]]; then
			ARGS="{\"domain\":\"$domain\",\"selector\":\"google\"}"
		else
			ARGS="{\"domain\":\"$domain\"}"
		fi

		PAYLOAD="{\"jsonrpc\":\"2.0\",\"id\":$req_id,\"method\":\"tools/call\",\"params\":{\"name\":\"$TOOL\",\"arguments\":$ARGS}}"

		RESULT=$(curl "${CURL_ARGS[@]}" \
			-X POST "$ENDPOINT" \
			-H "Content-Type: application/json" \
			-H "Mcp-Session-Id: $session_id" \
			--data "$PAYLOAD" 2>/dev/null)

		META=$(echo "$RESULT" | tail -1)
		HTTP_CODE=$(echo "$META" | awk '{print $1}')
		TIME_S=$(echo "$META" | awk '{print $2}')

		if [[ "$HTTP_CODE" == "200" ]]; then
			STATUS="OK"
			pass=$((pass + 1))
		elif [[ "$HTTP_CODE" == "429" ]]; then
			STATUS="RATELIM"
			fail=$((fail + 1))
		else
			STATUS="ERR:$HTTP_CODE"
			fail=$((fail + 1))
		fi

		printf "%-22s %6s %8s\n" "$TOOL" "$STATUS" "$TIME_S"
		total_time=$(echo "$total_time + $TIME_S" | bc)
	done

	printf "  => %d passed, %d failed, %.2fs\n" "$pass" "$fail" "$total_time"

	# Return counts via global vars (bash limitation)
	_PASS=$pass
	_FAIL=$fail
	_TIME=$total_time
	_REQ_ID=$req_id
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
echo "========================================"
echo " BLACKVEIL Scanner Benchmark"
echo "========================================"
if $AUTHENTICATED; then
	echo "Mode: authenticated (rate limiting bypassed)"
else
	echo "Mode: unauthenticated (10 req/min, ${COOLDOWN}s cooldown between domains)"
fi
echo "Endpoint: $ENDPOINT"
echo "Domains:  ${DOMAINS[*]}"
echo "========================================"

# Initialize session
echo ""
echo "Initializing session..."
INIT_RESPONSE=$(curl "${CURL_ARGS[@]}" \
	-X POST "$ENDPOINT" \
	-H "Content-Type: application/json" \
	-D "$HEADER_FILE" \
	--data '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}' 2>/dev/null)

SESSION_ID=$(grep -i '^mcp-session-id:' "$HEADER_FILE" | head -1 | sed 's/^[^:]*: *//;s/\r//g' | tr -d '[:space:]')
if [[ -z "$SESSION_ID" ]]; then
	echo "ERROR: Failed to initialize session"
	echo "Response: $INIT_RESPONSE"
	cat "$HEADER_FILE"
	exit 1
fi
echo "Session: ${SESSION_ID:0:16}..."

GRAND_PASS=0
GRAND_FAIL=0
GRAND_TIME=0
REQ_ID=1

for i in "${!DOMAINS[@]}"; do
	DOMAIN="${DOMAINS[$i]}"

	# Cooldown between domains (skip for authenticated or first domain)
	if [[ $i -gt 0 ]] && ! $AUTHENTICATED; then
		echo ""
		echo "--- Waiting ${COOLDOWN}s for rate limit window to reset ---"
		sleep "$COOLDOWN"
	fi

	echo ""
	echo "======== $DOMAIN ========"
	run_domain "$DOMAIN" "$SESSION_ID" "$REQ_ID"

	GRAND_PASS=$((GRAND_PASS + _PASS))
	GRAND_FAIL=$((GRAND_FAIL + _FAIL))
	GRAND_TIME=$(echo "$GRAND_TIME + $_TIME" | bc)
	REQ_ID=$_REQ_ID
done

echo ""
echo "========================================"
printf "TOTAL: %d passed, %d failed across %d domain(s), %.2fs elapsed\n" \
	"$GRAND_PASS" "$GRAND_FAIL" "${#DOMAINS[@]}" "$GRAND_TIME"
echo "========================================"
