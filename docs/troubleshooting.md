# Troubleshooting

Operational runbook for common MCP integration and request failures.

## 1. Health Check

```bash
curl https://dns-mcp.blackveilsecurity.com/health
```

## 2. Minimal MCP Request

```bash
curl -X POST https://dns-mcp.blackveilsecurity.com/mcp \
  -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","method":"scan_domain","params":{"domain":"example.com"},"id":1}'
```

If auth is enabled:

```bash
curl -X POST https://dns-mcp.blackveilsecurity.com/mcp \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <your-api-key>' \
  --data '{"jsonrpc":"2.0","method":"scan_domain","params":{"domain":"example.com"},"id":1}'
```

## 3. Common Errors

- `401 Unauthorized`: Missing or invalid bearer token while auth is enabled.
- `Invalid or missing session`: Session mismatch between client and server. Re-initialize client session and retry.
- `429 Too Many Requests`: Rate-limited (`10/min`, `100/hr` per IP for unauthenticated `tools/call`).

## 4. Debugging Checklist

- Confirm endpoint URL is correct.
- Confirm auth mode (`open` vs bearer) matches deployment configuration.
- Verify request body is valid JSON-RPC 2.0.
- Verify `domain` is a valid public domain.
- If self-hosted, inspect Wrangler/Worker logs for request ID and tool error details.

## 5. Local Development Checks

```bash
npm run typecheck
npm test
npm run dev
```

## 6. Investigating `scan_domain` Slowness (Claude Desktop)

Perceived latency in Claude Desktop is often a combination of MCP handshake overhead and tool execution time.

Typical contributors:

- `initialize` round-trip
- `tools/list` round-trip
- `tools/call` execution (`scan_domain`)

Measure each phase separately:

```bash
ENDPOINT="https://dns-mcp.blackveilsecurity.com/mcp"
TMP_HDR=$(mktemp)

# 1) Initialize and capture session id
curl -s -o /dev/null -D "$TMP_HDR" -w 'initialize=%{time_total}\n' \
  -X POST "$ENDPOINT" \
  -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'

SESSION_ID=$(grep -i '^mcp-session-id:' "$TMP_HDR" | head -1 | sed 's/^[^:]*: *//;s/\r//g' | tr -d '[:space:]')

# 2) tools/list
curl -s -o /dev/null -w 'tools_list=%{time_total}\n' \
  -X POST "$ENDPOINT" \
  -H 'Content-Type: application/json' \
  -H "Mcp-Session-Id: $SESSION_ID" \
  --data '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'

# 3) first scan (uncached) and second scan (cached)
curl -s -o /dev/null -w 'scan_first=%{time_total}\n' \
  -X POST "$ENDPOINT" \
  -H 'Content-Type: application/json' \
  -H "Mcp-Session-Id: $SESSION_ID" \
  --data '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"scan_domain","arguments":{"domain":"example.com"}}}'

curl -s -o /dev/null -w 'scan_cached=%{time_total}\n' \
  -X POST "$ENDPOINT" \
  -H 'Content-Type: application/json' \
  -H "Mcp-Session-Id: $SESSION_ID" \
  --data '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"scan_domain","arguments":{"domain":"example.com"}}}'

rm -f "$TMP_HDR"
```

Operational tips:

- Reuse the same MCP session where possible to avoid repeated initialization overhead.
- Prefer warmed-cache measurements (`scan_cached`) when validating interactive UX.
- Use `scripts/benchmark.sh` for repeatable per-tool timing comparisons across domains.
