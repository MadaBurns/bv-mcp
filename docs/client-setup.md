# Client Setup

This document defines MCP client integration for `bv-mcp`.

Important: you do not need to install an npm package to use the hosted MCP service from an editor. npm installation is only for embedding the scanner API inside your own application.

Library install:

```bash
npm install blackveil-dns
```

## Endpoint

Default hosted Streamable HTTP endpoint:

`https://dns-mcp.blackveilsecurity.com/mcp`

For MCP clients, configure this endpoint directly.


## Transport Options

- `Streamable HTTP`:
  - endpoint: `https://dns-mcp.blackveilsecurity.com/mcp`
  - protocol: JSON-RPC 2.0 over HTTP
  - content type: `application/json` for `POST /mcp`
- `Native stdio`:
  - install/run via the `blackveil-dns` npm package
  - executable: `blackveil-dns-mcp`
- `Legacy HTTP+SSE`:
  - bootstrap stream: `GET https://dns-mcp.blackveilsecurity.com/mcp/sse`
  - message endpoint: `POST https://dns-mcp.blackveilsecurity.com/mcp/messages?sessionId=...`

Modern MCP clients should prefer Streamable HTTP. Use stdio for local-only clients and the legacy HTTP+SSE endpoints only for older clients that have not migrated.

## VS Code / GitHub Copilot

No npm install required.

Add to `.vscode/mcp.json`:

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

## Claude Desktop

No npm install required.

**Recommended:** Open [claude.ai](https://claude.ai) → **Settings → Connectors → Add custom connector** → paste `https://dns-mcp.blackveilsecurity.com/mcp`.

This uses native Streamable HTTP with no bridge process. Prefer this over the config file approach.

**Config file fallback:** Claude Desktop's `claude_desktop_config.json` only supports stdio servers. Use the `mcp-remote` bridge to proxy to the hosted endpoint.

Open the config file at:
- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

Add (or merge into your existing `"mcpServers"` object):

```json
{
  "mcpServers": {
    "blackveil-dns": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "https://dns-mcp.blackveilsecurity.com/mcp"]
    }
  }
}
```

**Troubleshooting:** If Claude Desktop cannot find `npx`, replace `"npx"` with the absolute path to your `npx` binary. This is common on macOS where GUI apps don't inherit shell `PATH`.

| OS | How to find your path |
|---|---|
| macOS / Linux | Run `which npx` in a terminal |
| Windows | Run `where npx` in Command Prompt |

Example (macOS Homebrew): `"/opt/homebrew/bin/npx"`. Example (Windows): `"C:\\Program Files\\nodejs\\npx.cmd"`.

After saving, fully restart Claude Desktop (macOS: Cmd+Q; Windows: close from system tray) to pick up the new config.

## Claude Code

No npm install required.

**Option A — project-level** (`.mcp.json` in repo root):

```json
{
  "mcpServers": {
    "blackveil-dns": {
      "type": "http",
      "url": "https://dns-mcp.blackveilsecurity.com/mcp"
    }
  }
}
```

**Option B — CLI:**

```bash
claude mcp add --transport http blackveil-dns https://dns-mcp.blackveilsecurity.com/mcp
```

Restart Claude Code after adding the server.

## Cursor

No npm install required.

Add to `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "blackveil-dns": {
      "url": "https://dns-mcp.blackveilsecurity.com/mcp"
    }
  }
}
```

## Prompting Tips

If your client does not auto-route tool calls from short prompts, use explicit phrasing:

- `Use scan_domain to scan blackveilsecurity.com`
- `scan blackveilsecurity.com` (server alias for `scan_domain`)
- `Run check_dmarc for blackveilsecurity.com`
- `Run check_dkim for blackveilsecurity.com`

For chat-style clients, shorthand `scan <domain>` is supported.

### Alias Support

`tools/call` accepts a narrow alias for convenience:

- `scan` -> `scan_domain`

Canonical tool names from `tools/list` remain unchanged.

Important: raw JSON-RPC `tools/call` still requires `params.name` to be a tool identifier (`scan` or `scan_domain`), not a full phrase such as `scan example.com`.

## Authentication

When auth is enabled (`BV_API_KEY` configured), clients must send:

`Authorization: Bearer <BV_API_KEY>`

## Provider Detection Configuration

Optional runtime variable:

- `PROVIDER_SIGNATURES_URL`: HTTPS URL returning provider signature JSON for managed provider detection.
- `PROVIDER_SIGNATURES_SHA256`: Required pinned SHA-256 digest for the exact JSON payload returned by `PROVIDER_SIGNATURES_URL`.
- `PROVIDER_SIGNATURES_ALLOWED_HOSTS`: Optional comma-separated hostname allowlist for runtime signature fetches.

If unset or unavailable, the server falls back to stale cache (if present) and then built-in signatures.

If `PROVIDER_SIGNATURES_URL` is set without a matching `PROVIDER_SIGNATURES_SHA256`, runtime signatures are rejected and the server falls back to stale or built-in signatures.

## Response Metadata Notes

Provider-related findings can include structured metadata in addition to human-readable detail text. Clients should tolerate and preserve metadata fields such as:

- `detectionType`
- `providers`
- `providerConfidence`
- `signatureSource`
- `signatureVersion`
- `signatureFetchedAt`

## Provider Signatures JSON Format

When using `PROVIDER_SIGNATURES_URL`, the endpoint should return JSON with this shape:

- `version` (optional string)
- `inbound` (optional array of providers)
- `outbound` (optional array of providers)

Provider object shape:

- `name` (required string)
- `domains` (required string array)
- `selectorHints` (optional string array; used for DKIM-assisted outbound inference)

Example payload:

```json
{
  "version": "2026-03-04",
  "inbound": [
    {
      "name": "Google Workspace",
      "domains": ["google.com", "googlemail.com"],
      "selectorHints": ["google"]
    },
    {
      "name": "Microsoft 365",
      "domains": ["outlook.com", "protection.outlook.com"],
      "selectorHints": ["selector1", "selector2"]
    }
  ],
  "outbound": [
    {
      "name": "Mailgun",
      "domains": ["mailgun.org"],
      "selectorHints": ["mailgun"]
    }
  ]
}
```

## Server Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/mcp` | JSON-RPC 2.0 MCP requests |
| GET | `/mcp` | SSE stream (server-to-client notifications) |
| GET | `/mcp/sse` | Legacy HTTP+SSE bootstrap stream |
| POST | `/mcp/messages` | Legacy HTTP+SSE client messages |
| DELETE | `/mcp` | Session termination |
| GET | `/health` | Health check |
