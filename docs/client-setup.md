# Client Setup

This document defines MCP client integration for `bv-mcp`.

## Endpoint

Default hosted endpoint:

`https://dns-mcp.blackveilsecurity.com/mcp`

If self-hosting, replace with your deployed Worker endpoint.

## Transport Requirements

- Protocol: JSON-RPC 2.0 over HTTP
- MCP transport: Streamable HTTP
- Content type: `application/json` for `POST /mcp`

## VS Code / GitHub Copilot

Add to `.vscode/mcp.json`:

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

## Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "dns-security": {
      "url": "https://dns-mcp.blackveilsecurity.com/mcp"
    }
  }
}
```

## Claude Code

Add to `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "blackveil-dns": {
      "type": "url",
      "url": "https://dns-mcp.blackveilsecurity.com/mcp"
    }
  },
  "enableAllProjectMcpServers": true
}
```

Optional: improve automatic tool routing by adding a DNS security auto-mapping entry in `~/.claude/mcp-mappings.json`:

```json
{
  "autoMappings": {
    "dnsSecurityScan": {
      "patterns": [
        "scan domain",
        "dns scan",
        "security scan",
        "check dmarc",
        "check dkim",
        "check spf",
        "check mx"
      ],
      "server": "blackveil-dns",
      "priority": 1
    }
  }
}
```

After editing Claude Code configuration files, start a new Claude Code session to ensure mappings are reloaded.

## Cursor

Add to `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "dns-security": {
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

## Provider Detection Configuration (Self-Hosted)

Optional runtime variable:

- `PROVIDER_SIGNATURES_URL`: HTTPS URL returning provider signature JSON for managed provider detection.

If unset or unavailable, the server falls back to stale cache (if present) and then built-in signatures.

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
| DELETE | `/mcp` | Session termination |
| GET | `/health` | Health check |
