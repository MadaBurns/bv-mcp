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
