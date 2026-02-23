# BLACKVEIL DNS Security MCP Server

MCP server providing DNS security analysis tools for LLM integrations.

This Cloudflare Worker exposes DNS security checks over MCP Streamable HTTP and routes all DNS queries through Cloudflare DNS-over-HTTPS.

Full platform: https://blackveilsecurity.com

## Features

- 10 MCP tools: 8 individual checks, `scan_domain`, and `explain_finding`
- 50-check scoring model alignment across 8 security categories
- Streamable HTTP transport (MCP 2025-03-26) with SSE support
- Optional bearer token auth for `/mcp` via `BV_API_KEY`
- KV-backed distributed rate limiting per IP: 10/minute and 50/hour
- KV-backed 5-minute response caching for scans and individual checks
- Cloudflare Workers compatible runtime with strict TypeScript

## Tools

| Tool | Purpose |
|---|---|
| `check_spf` | SPF policy and sender authorization checks |
| `check_dmarc` | DMARC enforcement and reporting checks |
| `check_dkim` | DKIM selector/key checks |
| `check_dnssec` | DNSSEC validation checks |
| `check_ssl` | SSL/TLS certificate baseline checks |
| `check_mta_sts` | MTA-STS policy checks |
| `check_ns` | Name server resilience and delegation checks |
| `check_caa` | Certificate authority authorization checks |
| `scan_domain` | Full 8-category scan with overall score and grade |
| `explain_finding` | Plain-language remediation guidance for findings |

## Quick Start

```bash
git clone https://github.com/MadaBurns/bv-mcp.git
cd bv-mcp
npm install
npx wrangler dev
```

Local endpoint:
- `http://localhost:8787/mcp`
- `http://localhost:8787/health`

## MCP Transport

This server supports MCP Streamable HTTP (spec `2025-03-26`):

- `POST /mcp` JSON-RPC 2.0 requests (backward compatible)
- `POST /mcp` + `Accept: text/event-stream` for SSE response streaming
- `GET /mcp` for SSE stream/session initiation
- `DELETE /mcp` for session termination

Session IDs are passed in `Mcp-Session-Id` headers.

## Claude Client Configuration

Claude Desktop / Claude.ai MCP configuration example:

```json
{
  "mcpServers": {
    "blackveil-dns-security": {
      "transport": {
        "type": "streamable-http",
        "url": "https://dns-mcp.blackveilsecurity.com/mcp"
      }
    }
  }
}
```

If auth is enabled, clients must send:

```http
Authorization: Bearer <BV_API_KEY>
```

## Configuration

`wrangler.jsonc` includes:

- `kv_namespaces`:
  - `RATE_LIMIT` for distributed rate limit counters
  - `SCAN_CACHE` for response caching
- `vars.BV_API_KEY` placeholder for local/open mode behavior

Create KV namespaces:

```bash
npx wrangler kv namespace create RATE_LIMIT
npx wrangler kv namespace create SCAN_CACHE
```

Set API key secret (optional, production):

```bash
npx wrangler secret put BV_API_KEY
```

## Authentication

Auth is optional by design:

- If `BV_API_KEY` is set, all `/mcp` requests require `Authorization: Bearer <token>`.
- If `BV_API_KEY` is unset or empty, `/mcp` runs unauthenticated (open-source/local dev mode).
- Missing/invalid tokens return JSON-RPC error with HTTP `401`.

`/health` remains unauthenticated.

## Scoring Methodology

The scan model uses 8 categories and scanner-aligned importance weighting:

- SPF: 19
- DMARC: 22
- DKIM: 10
- DNSSEC: 3
- SSL/TLS: 8
- MTA-STS: 3
- NS: 0 (informational)
- CAA: 0 (informational)
- Email bonus: up to +5

Per-check severity penalties:

- Critical: -40
- High: -25
- Medium: -15
- Low: -5
- Info: 0

Grades:

- A+ (90+)
- A (85-89)
- B+ (80-84)
- B (75-79)
- C+ (70-74)
- C (65-69)
- D+ (60-64)
- D (55-59)
- E (50-54)
- F (<50)

## Architecture

```text
MCP Client
  -> Hono Router (Cloudflare Worker)
  -> Tool Handlers
  -> Cloudflare DoH (dns-query)
  -> Scoring Engine + KV cache/rate-limit state
```

Stack:

- Hono
- Cloudflare Workers
- Cloudflare KV
- Cloudflare DoH
- Vitest + workers pool

## Development

Run tests:

```bash
npm test
```

Type-check:

```bash
npx tsc --noEmit
```

## Contributing

Issues and pull requests are welcome.

- Keep Cloudflare Worker compatibility (no Node-only APIs).
- Preserve JSON-RPC backward compatibility for MCP clients.
- Add or update tests with behavior changes.

## License

MIT
