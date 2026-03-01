#!/usr/bin/env bash
# Benchmark script for BLACKVEIL Scanner MCP endpoint.
# Usage: BV_API_KEY=your-key ./scripts/benchmark.sh [domain] [endpoint]

set -euo pipefail

DOMAIN="${1:-cloudflare.com}"
ENDPOINT="${2:-https://dns-mcp.blackveilsecurity.com/mcp}"
AUTH_HEADER=""
if [[ -n "${BV_API_KEY:-}" ]]; then
	AUTH_HEADER="Authorization: Bearer $BV_API_KEY"
	echo "Mode: authenticated (rate limiting bypassed)"
else
	echo "Mode: unauthenticated (rate limited to 10 req/min)"
fi
echo "Endpoint: $ENDPOINT"
echo "Domain: $DOMAIN"
echo "---"

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

# Initialize session
echo "Initializing session..."
HEADER_FILE=$(mktemp)
trap 'rm -f "$HEADER_FILE"' EXIT

INIT_RESPONSE=$(curl "${CURL_ARGS[@]}" \
	-X POST "$ENDPOINT" \
	-H "Content-Type: application/json" \
	-D "$HEADER_FILE" \
	--data '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}' 2>/dev/null)

# Extract session ID from response headers (case-insensitive)
SESSION_ID=$(grep -i '^mcp-session-id:' "$HEADER_FILE" | head -1 | sed 's/^[^:]*: *//;s/\r//g' | tr -d '[:space:]')
if [[ -z "$SESSION_ID" ]]; then
	echo "ERROR: Failed to initialize session"
	echo "Response: $INIT_RESPONSE"
	cat "$HEADER_FILE"
	exit 1
fi
echo "Session: ${SESSION_ID:0:16}..."
echo ""

# Run each tool and collect timings
printf "%-22s %6s %8s\n" "TOOL" "STATUS" "TIME(s)"
printf "%-22s %6s %8s\n" "----" "------" "-------"

TOTAL_TIME=0
PASS=0
FAIL=0
REQ_ID=1

for TOOL in "${TOOLS[@]}"; do
	REQ_ID=$((REQ_ID + 1))

	if [[ "$TOOL" == "check_dkim" ]]; then
		ARGS="{\"domain\":\"$DOMAIN\",\"selector\":\"google\"}"
	else
		ARGS="{\"domain\":\"$DOMAIN\"}"
	fi

	PAYLOAD="{\"jsonrpc\":\"2.0\",\"id\":$REQ_ID,\"method\":\"tools/call\",\"params\":{\"name\":\"$TOOL\",\"arguments\":$ARGS}}"

	RESULT=$(curl "${CURL_ARGS[@]}" \
		-X POST "$ENDPOINT" \
		-H "Content-Type: application/json" \
		-H "Mcp-Session-Id: $SESSION_ID" \
		--data "$PAYLOAD" 2>/dev/null)

	# Last line is "HTTP_CODE TIME_TOTAL"
	META=$(echo "$RESULT" | tail -1)
	HTTP_CODE=$(echo "$META" | awk '{print $1}')
	TIME_S=$(echo "$META" | awk '{print $2}')

	if [[ "$HTTP_CODE" == "200" ]]; then
		STATUS="OK"
		PASS=$((PASS + 1))
	elif [[ "$HTTP_CODE" == "429" ]]; then
		STATUS="RATELIM"
		FAIL=$((FAIL + 1))
	else
		STATUS="ERR:$HTTP_CODE"
		FAIL=$((FAIL + 1))
	fi

	printf "%-22s %6s %8s\n" "$TOOL" "$STATUS" "$TIME_S"
	TOTAL_TIME=$(echo "$TOTAL_TIME + $TIME_S" | bc)
done

echo ""
echo "---"
printf "Total: %d passed, %d failed, %.2fs elapsed\n" "$PASS" "$FAIL" "$TOTAL_TIME"
