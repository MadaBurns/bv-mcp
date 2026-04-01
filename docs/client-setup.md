# Client Setup

This document defines MCP client integration for `bv-mcp`.

Important: you do not need to install an npm package to use the hosted MCP service from an editor. npm installation is only for embedding the scanner API inside your own application.

Library install:

```bash
npm install blackveil-dns
```

The package exports `scanDomain`, `explainFinding`, and reusable check functions. It also exports `McpTool`, `TOOLS`, and `TOOL_SCHEMA_MAP` for consumers who need access to the tool definitions and schemas at build time.

## Endpoint

Default hosted Streamable HTTP endpoint:

`https://dns-mcp.blackveilsecurity.com/mcp`

For MCP clients, configure this endpoint directly.

## Secret Hygiene (Required)

- Never hardcode API keys in scripts, config examples, docs, or committed files.
- Keep local keys in `.dev.vars` (or equivalent local-only secret store) and keep those files gitignored.
- If a key is exposed, rotate immediately and update all client configs.
- Before committing, run a quick secret scan (`gitleaks detect` and/or targeted `rg` checks).
- Use placeholder values such as `YOUR_API_KEY` in documentation only.


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

**With API key** — VS Code supports `inputs` for secrets:

```json
{
  "servers": {
    "blackveil-dns": {
      "type": "http",
      "url": "https://dns-mcp.blackveilsecurity.com/mcp",
      "headers": {
        "Authorization": "Bearer ${input:bv-api-key}"
      }
    }
  },
  "inputs": [
    {
      "id": "bv-api-key",
      "type": "promptString",
      "description": "Blackveil DNS API key",
      "password": true
    }
  ]
}
```

## Claude Desktop

No npm install required.

**Recommended (free tier):** Open [claude.ai](https://claude.ai) → **Settings → Connectors → Add custom connector** → paste `https://dns-mcp.blackveilsecurity.com/mcp`.

This uses native Streamable HTTP with no bridge process. Prefer this for free-tier usage.

**With API key** — open **Settings → Developer → Edit Config** (`claude_desktop_config.json`) and add:

```json
{
  "mcpServers": {
    "blackveil-dns": {
      "command": "/opt/homebrew/bin/npx",
      "args": [
        "-y",
        "mcp-remote",
        "https://dns-mcp.blackveilsecurity.com/mcp",
        "--header",
        "Authorization: Bearer YOUR_API_KEY"
      ]
    }
  }
}
```

Fully restart Claude Desktop after editing the config. Replace `YOUR_API_KEY` with your actual key.

Important: do not commit `claude_desktop_config.json` if it contains live bearer tokens.

### Production Key Registration (Operators)

If your production Worker enforces bearer auth, the same key must be registered on the Worker as `BV_API_KEY`.

```bash
# Set/rotate the secret (creates a new version)
npx wrangler versions secret put BV_API_KEY -c .dev/wrangler.deploy.jsonc

# Route traffic to the new version
npx wrangler versions deploy -c .dev/wrangler.deploy.jsonc --yes

# Confirm the secret is present on deployed versions
npx wrangler versions secret list -c .dev/wrangler.deploy.jsonc
```

If the client key is valid but not registered in production, requests fail with `401 Unauthorized: missing or invalid bearer token`.

**Without API key (local stdio):** If you want first-party local stdio instead of the hosted HTTP connector:

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

> On macOS GUI apps, `npx` may not resolve from `PATH`; if Homebrew is installed elsewhere, replace `/opt/homebrew/bin/npx` with your actual `npx` path. After editing the config, fully restart Claude Desktop. If you already have other servers, merge `"blackveil-dns"` into your existing `"mcpServers"` object — don't paste a second `{ }` wrapper.

## Claude Code

No npm install required.

**Free tier** — project-level (`.mcp.json` in repo root):

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

Or via CLI:

```bash
claude mcp add --transport http blackveil-dns https://dns-mcp.blackveilsecurity.com/mcp
```

**With API key** — use the `api_key` query parameter with native HTTP (simplest):

```json
{
  "mcpServers": {
    "blackveil-dns": {
      "type": "http",
      "url": "https://dns-mcp.blackveilsecurity.com/mcp?api_key=YOUR_API_KEY"
    }
  }
}
```

Or via CLI:

```bash
claude mcp add --transport http blackveil-dns "https://dns-mcp.blackveilsecurity.com/mcp?api_key=YOUR_API_KEY"
```

Alternatively, use `mcp-remote` to forward the `Authorization` header (useful when sourcing the key from an env variable):

```json
{
  "mcpServers": {
    "blackveil-dns": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://dns-mcp.blackveilsecurity.com/mcp",
        "--header",
        "Authorization: Bearer YOUR_API_KEY"
      ]
    }
  }
}
```

> **Note:** Claude Code's native HTTP transport does not forward custom `headers` from config files. Use the `?api_key=` query parameter or `mcp-remote` as a bridge.

Important: if you script this setup, source the key from environment (`BV_API_KEY`) and avoid embedding token literals in shell history.

## Smithery

No npm install required.

Add via the Smithery CLI:

```bash
smithery mcp add MadaBurns/bv-mcp
```

Or connect directly with your agent using the hosted URL:

```
https://bv-mcp--madaburns.run.tools
```

**With API key** — pass during setup when prompted, or embed in the connection URL:

```
https://bv-mcp--madaburns.run.tools?api_key=YOUR_API_KEY
```

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

**With API key:**

```json
{
  "mcpServers": {
    "blackveil-dns": {
      "url": "https://dns-mcp.blackveilsecurity.com/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_API_KEY"
      }
    }
  }
}
```

## Windsurf

No npm install required.

Add to `~/.codeium/windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "blackveil-dns": {
      "serverUrl": "https://dns-mcp.blackveilsecurity.com/mcp"
    }
  }
}
```

**With API key:**

```json
{
  "mcpServers": {
    "blackveil-dns": {
      "serverUrl": "https://dns-mcp.blackveilsecurity.com/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_API_KEY"
      }
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

Authenticated requests bypass all rate limits. You can send the API key as a bearer token or a query parameter:

- **Bearer Token**: `Authorization: Bearer <YOUR_API_KEY>`
- **Query Parameter**: `?api_key=<YOUR_API_KEY>`

The query parameter method is the simplest for clients that only support URL configuration (like Claude Code, Smithery, or simple HTTP connectors).

**Important:** Claude Code and some other clients' native HTTP transport do not forward custom `headers` from config files. Use the `?api_key=` query parameter or the `mcp-remote` bridge approach shown in the per-client sections.

| Client | Recommended Auth Method | Notes |
|--------|-------------------------|-------|
| Claude Code | `?api_key=` in URL | Simple and native |
| Smithery | `?api_key=` in URL | Native integration |
| VS Code / Copilot | `headers` field | Supports secret prompt |
| Cursor | `headers` field | Direct header support |
| Windsurf | `headers` field | Direct header support |
| Claude Desktop | `mcp-remote --header` | Hosted connector (free) or bridge |
| curl / scripts | `-H "Authorization: Bearer ..."` | Standard HTTP header |

### Troubleshooting Client-Specific Behavior

If you are a developer troubleshooting how different MCP clients handle authentication, session lifecycles, or message formats, use the included chaos test:

```bash
python3 scripts/chaos/chaos-test-clients.py
```

This test covers all 9 detected MCP client types and 56 assertions across session management, auth precedence, and transport-specific edge cases.

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
