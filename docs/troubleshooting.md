# Troubleshooting

Operational runbook for common MCP integration and request failures.

## 0. MCP Client Configuration (Claude Desktop, VS Code, Cursor)

### Claude Desktop Not Discovering Tools

If Claude Desktop doesn't automatically use the MCP server when you make requests like "scan blackveilsecurity.com", check:

**1. Verify config file exists and is valid**

**Mac/Linux:** `~/Library/Application Support/Claude/claude_desktop_config.json`  
**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

Required config:
```json
{
  "mcpServers": {
    "dns-security": {
      "url": "https://dns-mcp.blackveilsecurity.com/mcp"
    }
  }
}
```

**Common mistakes:**
- ❌ Using `mcpServer` (singular) instead of `mcpServers` (plural)
- ❌ Adding `"type": "http"` (not needed for Claude Desktop, only VS Code)
- ❌ Invalid JSON syntax (trailing commas, missing quotes)

**2. Restart Claude Desktop completely**

After adding/editing the config:
1. Quit Claude Desktop completely (not just close the window)
2. Relaunch Claude Desktop
3. The server should connect automatically on startup

**3. Use explicit phrasing**

Instead of: "scan blackveilsecurity.com"

Try more explicit requests:
- "Use the scan_domain tool to scan blackveilsecurity.com"
- "Run a DNS security scan on blackveilsecurity.com"
- "Check DNS security for blackveilsecurity.com using the MCP tools"

**4. Verify server connectivity**

Test that the server is responding:
```bash
curl https://dns-mcp.blackveilsecurity.com/health
```

Should return: `{"status":"ok"}`

Test that tools are available:
```bash
curl -X POST https://dns-mcp.blackveilsecurity.com/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
```

Should return JSON with a tools array including `scan_domain`.

**5. Check Claude Desktop logs (Mac)**

Look for MCP connection errors in:
```bash
~/Library/Logs/Claude/
```

### Claude Code Not Auto-Routing Scan Prompts

If Claude Code is connected but prompts like `scan blackveilsecurity.com` do not route to this MCP server automatically:

**1. Verify `mcpServers` entry** in `~/.claude/settings.json`

```json
{
  "mcpServers": {
    "blackveil-dns": {
      "type": "url",
      "url": "https://dns-mcp.blackveilsecurity.com/mcp"
    }
  }
}
```

**2. Add an auto-mapping rule** in `~/.claude/mcp-mappings.json`

Map scan and DNS/security patterns to `blackveil-dns` (for example: `scan domain`, `dns scan`, `check dmarc`, `check dkim`, `check spf`, `check mx`).

**3. Ensure the server is always enabled**

In `~/.claude/mcp-mappings.json`, include `blackveil-dns` in `defaults.alwaysEnabled`.

**4. Start a new Claude Code session**

Claude Code may cache mappings per session. Restarting/reopening a session forces mapping reload.

**5. Use explicit phrasing as fallback**

- `Use scan_domain to scan blackveilsecurity.com`
- `Run check_dmarc for blackveilsecurity.com`

### VS Code / GitHub Copilot Configuration

Add to `.vscode/mcp.json` in your workspace root:

```json
{
  "servers": {
    "dns-security": {
      "type": "http",
      "url": "https://dns-mcp.blackveilsecurity.com/mcp"
    }
  }
}
```

**Note:** VS Code requires `"type": "http"` field (unlike Claude Desktop).

### Cursor Configuration

Add to `.cursor/mcp.json` in your workspace root:

```json
{
  "mcpServers": {
    "dns-security": {
      "url": "https://dns-mcp.blackveilsecurity.com/mcp"
    }
  }
}
```

Restart Cursor after adding the configuration.

## 1. Health Check

```bash
curl https://dns-mcp.blackveilsecurity.com/health
```

## 2. Minimal MCP Request

```bash
curl -X POST https://dns-mcp.blackveilsecurity.com/mcp \
  -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
```

Then call the scan tool with the returned `mcp-session-id` header:

```bash
curl -X POST https://dns-mcp.blackveilsecurity.com/mcp \
  -H 'Content-Type: application/json' \
  -H 'Mcp-Session-Id: <session-id>' \
  --data '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"scan","arguments":{"domain":"example.com"}}}'
```

`scan` is an alias for `scan_domain`.

If auth is enabled:

```bash
curl -X POST https://dns-mcp.blackveilsecurity.com/mcp \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <your-api-key>' \
  --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
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
