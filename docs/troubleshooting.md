# Troubleshooting

Operational runbook for common MCP integration and request failures.

## 0. MCP Client Configuration (Claude Desktop, VS Code, Cursor)

### Claude Desktop Not Discovering Tools

If Claude Desktop doesn't automatically use the MCP server when you make requests like "scan blackveilsecurity.com", check:

**1. Prefer a direct custom connector**

For Claude Desktop, the recommended setup is the hosted remote connector:

1. Open `claude.ai`
2. Go to **Settings → Connectors → Add custom connector**
3. Paste `https://dns-mcp.blackveilsecurity.com/mcp`

This avoids local bridge-process issues entirely.

**2. If using the config file fallback, verify it exists and is valid**

**Mac/Linux:** `~/Library/Application Support/Claude/claude_desktop_config.json`  
**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

Fallback config (native stdio — no bridge required):

**macOS / Linux:**
```json
{
  "mcpServers": {
    "blackveil-dns": {
      "type": "stdio",
      "command": "/opt/homebrew/bin/npx",
      "args": ["-y", "--package", "blackveil-dns", "blackveil-dns-mcp"]
    }
  }
}
```

**Windows:**
```json
{
  "mcpServers": {
    "blackveil-dns": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "--package", "blackveil-dns", "blackveil-dns-mcp"]
    }
  }
}
```

**Common mistakes:**
- ❌ Using `mcpServer` (singular) instead of `mcpServers` (plural)
- ❌ Using bare `npx` when Claude Desktop cannot resolve it from the GUI app environment (macOS)
- ❌ Using the full `C:\Program Files\nodejs\npx.cmd` path on Windows — the space breaks `cmd.exe` (see [§3](#3-windows-cprogram-is-not-recognized)). If bare `npx` also fails, use a wrapper `.bat` file (Option C in §3)
- ❌ Omitting `-y` and getting stuck on the first `npx` install prompt
- ❌ Invalid JSON syntax (trailing commas, missing quotes)

If Homebrew is installed elsewhere (macOS), replace `/opt/homebrew/bin/npx` with your actual `npx` path.

**3. Restart Claude Desktop completely**

After adding/editing the config:
1. Quit Claude Desktop completely (not just close the window)
2. Relaunch Claude Desktop
3. The server should connect automatically on startup

**4. Use explicit phrasing**

Instead of: "scan blackveilsecurity.com"

Try more explicit requests:
- "Use the scan_domain tool to scan blackveilsecurity.com"
- "Run a DNS security scan on blackveilsecurity.com"
- "Check DNS security for blackveilsecurity.com using the MCP tools"

**5. Verify server connectivity**

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

**6. If tools still don't connect, check Claude Desktop logs**

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
    "blackveil-dns": {
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
    "blackveil-dns": {
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

## 3. Windows: `'C:\Program' is not recognized`

If the MCP client log shows:

```
'C:\Program' is not recognized as an internal or external command,
operable program or batch file.
```

This means `cmd.exe /C` is splitting the `npx.cmd` path at the space in `C:\Program Files`. The fix depends on your client:

**Option A — Use `npx` directly as the command (preferred)**

Most MCP clients resolve `npx` from `PATH` automatically:

```json
{
  "mcpServers": {
    "blackveil-dns": {
      "command": "npx",
      "args": [
        "-y", "mcp-remote",
        "https://dns-mcp.blackveilsecurity.com/mcp",
        "--header",
        "Authorization: Bearer YOUR_API_KEY"
      ]
    }
  }
}
```

**Option B — Quote the full path**

If you must specify the full path, wrap it in escaped quotes:

```json
{
  "mcpServers": {
    "blackveil-dns": {
      "command": "cmd",
      "args": [
        "/C",
        "\"C:\\Program Files\\nodejs\\npx.cmd\"",
        "-y", "mcp-remote",
        "https://dns-mcp.blackveilsecurity.com/mcp",
        "--header",
        "Authorization: Bearer YOUR_API_KEY"
      ]
    }
  }
}
```

**Option C — Create an `npx` wrapper script**

If bare `npx` still fails (some Windows environments don't resolve it from `PATH` inside `cmd.exe /C`), create a one-line wrapper:

1. Create `C:\scripts\npx-wrapper.bat` with this content:

```bat
@echo off
"C:\Program Files\nodejs\npx.cmd" %*
```

2. Reference the wrapper in your config:

```json
{
  "mcpServers": {
    "blackveil-dns": {
      "command": "C:\\scripts\\npx-wrapper.bat",
      "args": [
        "-y", "mcp-remote",
        "https://dns-mcp.blackveilsecurity.com/mcp",
        "--header",
        "Authorization: Bearer YOUR_API_KEY"
      ]
    }
  }
}
```

The wrapper quotes the path internally, so `cmd.exe` never sees the space in `Program Files`. You can place the `.bat` file anywhere — just avoid paths with spaces.

**Option D — Use native HTTP transport (no bridge process)**

Avoid `mcp-remote` entirely. VS Code and Cursor support `"type": "http"` natively:

```json
{
  "servers": {
    "blackveil-dns": {
      "type": "http",
      "url": "https://dns-mcp.blackveilsecurity.com/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_API_KEY"
      }
    }
  }
}
```

## 4. Common Errors

- `401 Unauthorized`: Missing or invalid bearer token while auth is enabled.
- `Bad Request: missing session`: Auth is accepted, but no `Mcp-Session-Id` was sent for a stateful method. Call `initialize` first, then include the returned session ID header on follow-up MCP calls.
- `Invalid or missing session`: Session mismatch between client and server. Re-initialize client session and retry. Sessions expire after 2 hours of idle time.
- `Not Found: session expired or terminated`: Session TTL (2 hours) exceeded. Most MCP clients auto-reinitialize on 404; `mcp-remote` does not — restart Claude Desktop to force a new session.
- `429 Too Many Requests`: Rate-limited (`50/min`, `300/hr` per IP for unauthenticated `tools/call`). Note: `GET /mcp` SSE notification stream is exempt from rate limiting.
- `Error: An unexpected error occurred` on `tools/call` with IP-like domain input: input validation rejected an IP literal form. Use a real DNS domain name (for example `example.com`) instead of values like `127.1`, `0177.0.0.1`, `8.8.8.8`, or `0x8.0x8.0x8.0x8`.
- `-32601 Method not found: prompts/list`: Expected. This server does not implement prompt methods (`prompts/list`, `prompts/get`). Use `tools/list` / `tools/call` and `resources/list` / `resources/read`.
- `check_spf` finding **“SPF check timed out”** or **“SPF check could not complete”** (`errorKind: 'timeout' | 'dns_error'`, `missingControl: true`): the top-level DNS lookup for the domain failed before SPF could be read. This is not an MCP error — the tool returns a structured result with `passed: false` and `score: 0`. Retry once with `force_refresh: true`; if it persists, the authoritative DNS for the zone is unreachable.
- `check_http_security` finding **“HTTP security check timed out”** (`checkStatus: 'timeout'`, `missingControl: true`): the total 10s budget (dual-fetch + WAF body + package probe) was exhausted. The host was unreachable or extremely slow. The scan still completes — this category contributes zero rather than blocking other checks.
- `batch_scan` item with `error: 'batch_budget_exceeded'`: the 25-second wall-clock budget for the entire batch was exhausted before this domain could be scanned. Slow domains earlier in the batch (or a domain that itself hits `scan_domain`'s 12s ceiling) consume the budget. Split the batch into smaller groups, or call `scan_domain` per-domain in parallel to keep items independent.

## 5. Debugging Checklist

- Confirm endpoint URL is correct.
- Confirm auth mode (`open` vs bearer) matches configuration.
- Verify request body is valid JSON-RPC 2.0.
- Verify `domain` is a valid public DNS domain name (not an IPv4 literal in standard or alternate numeric notation).
- Inspect Wrangler/Worker logs for request ID and tool error details.

## 6. Local Development Checks

```bash
npm run typecheck
npm test
npm run dev
```

## 7. Investigating `scan_domain` Slowness (Claude Desktop)

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
