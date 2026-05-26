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

**macOS / Linux:**

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

> On macOS, if Homebrew is installed elsewhere replace `/opt/homebrew/bin/npx` with your actual `npx` path (run `which npx` to find it).

**Windows** (`%APPDATA%\Claude\claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "blackveil-dns": {
      "command": "npx",
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

> Use bare `"command": "npx"` — do **not** use the full `C:\Program Files\nodejs\npx.cmd` path. The space in `Program Files` breaks `cmd.exe` argument parsing. If bare `npx` still fails, create a wrapper `.bat` file — see [Troubleshooting § Windows](troubleshooting.md#3-windows-cprogram-is-not-recognized) for the fix and other options.

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

> If Homebrew is installed elsewhere, replace `/opt/homebrew/bin/npx` with your actual `npx` path.

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

> Use bare `"command": "npx"` on Windows — do not use the full path. If bare `npx` still fails, create a wrapper `.bat` file — see [Troubleshooting § Windows](troubleshooting.md#3-windows-cprogram-is-not-recognized) for the fix and other options.

After editing the config, fully restart Claude Desktop. If you already have other servers, merge `"blackveil-dns"` into your existing `"mcpServers"` object — don't paste a second `{ }` wrapper.

## Claude Mobile (iOS / Android)

No npm install required. MCP connectors are configured on the web and auto-sync to mobile.

**Setup:**

1. Open [claude.ai](https://claude.ai) → **Settings** → **Connectors** → **Add custom connector**
2. Enter:
   - **Name**: `Blackveil DNS`
   - **URL**: `https://dns-mcp.blackveilsecurity.com/mcp`
3. Save — the connector syncs automatically to Claude iOS and Android apps

**With API key** — append the key as a query parameter in the connector URL:

```text
https://dns-mcp.blackveilsecurity.com/mcp?api_key=YOUR_API_KEY
```

Alternatively, provide the API key as a Bearer token if the connector UI supports an authentication field.

**Limitations:**

- Only MCP **tools** are available on mobile (prompts and resources are not supported)
- Connectors must be added via the claude.ai web interface — the mobile app cannot add them directly
- Requests are routed through Anthropic's servers; the MCP server sees Anthropic's IP, not the user's device IP

**Output format:** The server auto-detects Claude Mobile clients and returns compact output (shorter findings, no emoji icons, no structured JSON blocks) optimized for mobile screen size.

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

Use one authentication method per server entry. For Claude Code's native HTTP transport, prefer the query parameter and do not also add an `Authorization` header; some clients ignore headers from config files, and an invalid token or placeholder can cause a `401` during MCP initialization.

If `.mcp.json` is committed in your project, keep it on the free-tier URL or use placeholders only. Put live keys in user-level client settings or a local ignored override, not in a tracked repository file.

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

> **Note:** Claude Code's native HTTP transport does not forward custom `headers` from config files. Use the `?api_key=` query parameter or `mcp-remote` as a bridge.

Important: if you script this setup, source the key from environment (`BV_API_KEY`) and avoid embedding token literals in shell history. `mcp-remote` and `npx` add a local bridge process, so native HTTP is preferred unless you specifically need header forwarding.

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

### Refreshing the tool list

MCP clients fetch `tools/list` once when they connect and cache it for the lifetime of that connection. The tool set is static per deployment, so the server does not emit `tools/list_changed` notifications. To pick up tools added or removed by a server update, reconnect or restart your MCP client. This is why a client may briefly show a previous tool count right after a server update until it reconnects.

## Authentication

Authenticated requests bypass per-IP rate limits and apply the caller's tier quota. Three authentication methods are supported:

- **Bearer Token**: `Authorization: Bearer <YOUR_API_KEY>`
- **Query Parameter**: `?api_key=<YOUR_API_KEY>`
- **OAuth 2.1** (authorization code + PKCE) — optional operator-enabled flow. See the [OAuth 2.1](#oauth-21) section below.

The query parameter method is the simplest for clients that only support URL configuration (like Claude Code, Smithery, or simple HTTP connectors).

**Important:** Claude Code and some other clients' native HTTP transport do not forward custom `headers` from config files. Use the `?api_key=` query parameter or the `mcp-remote` bridge approach shown in the per-client sections.

Do not configure both `?api_key=` and `Authorization` for the same server unless both values are intentionally valid. A stale placeholder in either location can make startup fail with `401 Unauthorized` instead of falling back to the free tier.

### Static API Key Tiers

Static API keys (via `?api_key=` or `Authorization: Bearer`) authenticate as a specific tier:

| Tier | Quota | Use Case | Source |
|---|---|---|---|
| free | 25 domain scans/day, 1 batch scan/day, 3 concurrent. High-cost tools have tighter per-tool limits. | Unauthenticated, public testing (e.g. Claude.ai web) | Per-IP rate limit (no key) |
| **agent** | **200 scans/day, 5 concurrent** | **Team automation, CI/CD scripts** | **`BV_API_KEY` environment variable** |
| developer | 500 scans/day, 10 concurrent | OAuth + MCP Developer plan | Stripe subscription (bv-web) |
| enterprise | 10,000 scans/day, 25 concurrent | OAuth + MCP Enterprise plan | Stripe subscription (bv-web) |

Free hosted usage keeps core DNS and email checks open for trial traffic, while high-cost or private-probe tools have tighter unauthenticated limits: `check_fast_flux` to 3/day, `check_lookalikes` and `check_shadow_domains` to 5/day, and `check_authoritative_dns_infra`, `check_subdomain_takeover`, and `check_root_server_set` to 25/day. The full brand-discovery surface — `discover_brand_domains` and the async `brand_audit_*` tools — requires an authenticated paid tier.

**Agent tier** is intended for:
- **CI/CD pipelines**: Commit-on-push DNS scans as part of security checks
- **Team automation**: Shared team key for dashboards or reporting tools
- **Internal tools**: Monitoring scripts, periodic compliance audits
- **Development**: Testing MCP integration before purchasing a paid plan

**Configuration**:

```bash
# .env (local) or CI/CD secrets
BV_API_KEY="bv_Kx8eZ2rdtUPfdzR8e_..."

# In MCP config
{
  "server": "https://dns-mcp.blackveilsecurity.com/mcp?api_key=${BV_API_KEY}"
}

# Or as header (where supported)
Authorization: Bearer bv_Kx8eZ2rdtUPfdzR8e_...
```

**Important**: 
- Agent keys are static and long-lived. Treat them like passwords.
- Do not commit keys to version control. Use environment variables or secret managers.
- Rotate regularly (no built-in rotation; delete old key and generate new one).

| Tier | Authentication | Plan/Payment | TTL | Use |
|---|---|---|---|---|
| **agent** | Static `BV_API_KEY` | Internal/team | Indefinite | Automation, CI/CD |
| **developer** (OAuth) | Stripe subscription | MCP Developer ($39/mo) | 1 hour (JWT) | Individual developers |
| **enterprise** (OAuth) | Stripe subscription | MCP Enterprise ($199/mo) | 1 hour (JWT) | Organizations |

| Client | Recommended Auth Method | Notes |
|--------|-------------------------|-------|
| Claude Mobile | Hosted connector URL | Customer OAuth is enabled on the hosted endpoint; use `?api_key=` for static-key quota |
| Claude Code | `?api_key=` in URL | Simple and native |
| Smithery | `?api_key=` in URL | Native integration |
| VS Code / Copilot | `headers` field | Supports secret prompt |
| Cursor | `headers` field | Direct header support |
| Windsurf | `headers` field | Direct header support |
| Claude Desktop | `mcp-remote --header` | Hosted connector (free) or bridge |
| curl / scripts | `-H "Authorization: Bearer ..."` | Standard HTTP header |

### OAuth 2.1

OAuth is enabled on the hosted production endpoint for the customer-consent flow. Self-hosted operators must set `ENABLE_OAUTH=true` to expose OAuth routes. The legacy owner-key consent page is separately gated by `ENABLE_OWNER_OAUTH=true` and remains disabled in production.

When enabled, the server implements RFC 6749 authorization-code grant with PKCE (S256 only), RFC 7591 dynamic client registration, and RFC 8414 / RFC 9728 discovery. Tokens are HS256 JWTs with a 1-hour TTL. Paid-plan OAuth tokens carry `developer` or `enterprise` tier claims from a validated bv-web/Stripe entitlement; `agent`, `owner`, and `partner` are reserved for static keys and admin flows.

**Discovery endpoints** (no auth; available on hosted production and on self-hosted deployments with `ENABLE_OAUTH=true`):

- `GET /.well-known/oauth-authorization-server` — RFC 8414 authorization server metadata (issuer, `/oauth/authorize`, `/oauth/token`, `/oauth/register`, supported grants + PKCE methods).
- `GET /.well-known/oauth-protected-resource` — RFC 9728 metadata pointing at `/mcp` as the protected resource.

**Flow** (performed by the MCP client, not the user directly):

1. `POST /oauth/register` with `{ "redirect_uris": [<client redirect>] }` → receive `client_id` and a one-time `client_secret`.
2. `GET /oauth/authorize` with `client_id`, `redirect_uri`, `response_type=code`, `code_challenge`, `code_challenge_method=S256`, `state` → customer OAuth delegates to bv-web for account/Stripe entitlement checks; owner-key consent is only rendered when `ENABLE_OWNER_OAUTH=true`.
3. `POST /oauth/token` with `grant_type=authorization_code`, `code`, `redirect_uri`, `client_id`, `code_verifier` → receive `access_token` (JWT).
4. Call `/mcp` with `Authorization: Bearer <access_token>`.

**Constraints:**

- PKCE is mandatory. `plain` is rejected at the schema layer — only `S256`.
- `client_secret` is hashed in KV and is only available from the one-shot DCR response. Rotating means re-registering.
- `OWNER_ALLOW_IPS` is enforced at the consent step for owner-tier JWT issuance. A stolen owner key from a non-allowlisted IP cannot mint an owner JWT.
- bv-web OAuth entitlement responses are schema-validated before code issuance and cannot grant `owner` or `partner` tiers.
- JWT revocation is by JTI. Rotation of `OAUTH_SIGNING_SECRET` invalidates every outstanding JWT at next verify.

**Reference client** (probes, rotation, and rollback runbook): [`scripts/oauth/README.md`](../scripts/oauth/README.md) and [`scripts/oauth/prod-probe.py`](../scripts/oauth/prod-probe.py).

**OAuth Tier Resolution**: See [`docs/oauth-stripe-integration.md`](./oauth-stripe-integration.md) for how Stripe subscriptions map to OAuth tiers.

### Troubleshooting Client-Specific Behavior

If you are a developer troubleshooting how different MCP clients handle authentication, session lifecycles, or message formats, use the included chaos test:

```bash
python3 scripts/chaos/chaos-test-clients.py
```

This test covers all 9 detected MCP client types across session management, auth precedence, format negotiation, and transport-specific edge cases. With no `BV_API_KEY`, it exercises the public/free-tier path. With a valid API key exported as `BV_API_KEY`, it also covers `?api_key=` authentication, Bearer precedence, authenticated Legacy SSE bootstrap, and batch `scan_domain` behavior.

Expected assertion count:

- Unauthenticated/free-tier run: 58 assertions.
- Authenticated run with `BV_API_KEY`: 65 assertions.

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
| GET | `/.well-known/oauth-authorization-server` | OAuth 2.1 authorization server metadata (RFC 8414) |
| GET | `/.well-known/oauth-protected-resource` | OAuth 2.1 protected resource metadata (RFC 9728) |
| POST | `/oauth/register` | Dynamic client registration (RFC 7591) |
| GET / POST | `/oauth/authorize` | Authorization endpoint (consent + code issuance) |
| POST | `/oauth/token` | Token endpoint (authorization code grant with PKCE) |

On the hosted endpoint, OAuth routes serve the customer flow. On self-hosted deployments, OAuth endpoints return `404` unless the operator sets `ENABLE_OAUTH=true`. The owner API-key consent UI remains disabled unless `ENABLE_OWNER_OAUTH=true`.
