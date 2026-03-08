# BLACKVEIL Scanner

Give Claude, Cursor, or any MCP client real-time DNS and email security scanning for any domain.
Open-source MCP server running on Cloudflare Workers. Passive, read-only checks via public DoH APIs.

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Cloudflare Workers](https://img.shields.io/badge/Runs%20on-Cloudflare%20Workers-F38020?logo=cloudflare)](https://workers.cloudflare.com/)
[![MCP 2025-03-26](https://img.shields.io/badge/MCP-2025--03--26-blue)](https://modelcontextprotocol.io/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.5-3178C6?logo=typescript)](https://www.typescriptlang.org/)

### What can it do?

Point it at any domain and get back a full security audit: SPF, DMARC, DKIM, DNSSEC, SSL/TLS, CAA, MTA-STS, and NS analysis — each scored individually and rolled into a 0–100 overall security grade. It detects dangling CNAMEs for subdomain takeover risk, identifies mail and DNS providers, and flags misconfigurations with severity ratings. Use `explain_finding` to get plain-English remediation guidance for anything it flags — explanations use everyday analogies (guest lists, wax seals, padlocks) so anyone on your team can understand the risk, not just security engineers.

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Tool Surface](#tool-surface)
- [Protocol Endpoints](#protocol-endpoints)
- [Architecture Notes](#architecture-notes)
- [Security Model](#security-model)
- [Documentation](#documentation)
- [Self-Hosting](#self-hosting)
- [Development](#development)
- [Testing](#testing)
- [License](#license)

## Overview

`bv-mcp` exposes DNS/email security checks through MCP over Streamable HTTP (JSON-RPC 2.0).

- Runtime: Cloudflare Workers
- Framework: Hono
- Language: TypeScript (strict)
- DNS backend: Cloudflare DoH (`cloudflare-dns.com/dns-query`) with optional secondary confirmation via Google DoH (`dns.google/resolve`) on empty-answer responses

This is a remote MCP server. It is not a local stdio server invoked via `npx`/`uvx`.

> 🛡️ **Want continuous monitoring?** This tool scans for DNS and email security issues. [BLACKVEIL](https://blackveilsecurity.com) provides near real-time monitoring, alerting, and Buck AI to help you fix them.

## Quick Start

Hosted endpoint:

`https://dns-mcp.blackveilsecurity.com/mcp`

**VS Code / Copilot** (`.vscode/mcp.json`):

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

**Claude Desktop** (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "dns-security": {
      "url": "https://dns-mcp.blackveilsecurity.com/mcp"
    }
  }
}
```

**Cursor** (`.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "dns-security": {
      "url": "https://dns-mcp.blackveilsecurity.com/mcp"
    }
  }
}
```

For full client setup and auth details, see `docs/client-setup.md`.

## Tool Surface

Directly callable MCP tools:

- `check_mx`
- `check_spf`
- `check_dmarc`
- `check_dkim`
- `check_dnssec`
- `check_ssl`
- `check_mta_sts`
- `check_ns`
- `check_caa`
- `scan_domain`
- `explain_finding`

`explain_finding` accepts a `checkType`, `status`, and optional `details` string, and returns a structured explanation with:
- **What this means** — plain-English description using everyday analogies (e.g., SPF as a "guest list," DKIM as a "wax seal," DNSSEC as a "notarized signature")
- **Potential impact** — what could go wrong, in terms anyone can understand
- **Adverse consequences** — real-world business effects
- **Recommendation** — specific technical steps to fix it
- **References** — links to relevant RFCs and documentation

The `details` parameter enables precise explanations: passing the finding's detail text routes to a specific explanation (e.g., distinguishing "no MTA-STS records" from "MTA-STS in testing mode") instead of a generic fallback.

Findings now include a confidence label in metadata and rendered reports:
- `deterministic`: direct protocol/record validation with clear evidence.
- `heuristic`: signal-based inference (for example selector probing or takeover indicators) and may require manual validation.
- `verified`: explicit high-confidence validation signal.

Subdomain takeover findings now include a verification label in finding metadata and reports:
- `potential`: DNS/signal indicates possible takeover; requires authorized proof-of-control validation.
- `verified`: service deprovisioning fingerprint detected; high-confidence signal pending authorized proof-of-control.
- `not_exploitable`: no takeover signal detected for the checked subdomains.

Internal check executed within `scan_domain`:

- `subdomain_takeover`

Scope and limitations are documented in `docs/coverage.md`.

## Protocol Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/mcp` | JSON-RPC 2.0 tool/protocol requests |
| `GET` | `/mcp` | SSE stream for server notifications |
| `DELETE` | `/mcp` | Session termination |
| `GET` | `/health` | Health probe |

Supported JSON-RPC protocol methods include `initialize`, `ping`, `tools/list`, `tools/call`, `resources/list`, and `resources/read`.

This server does not currently implement prompt APIs such as `prompts/list` or `prompts/get`; those calls return `-32601 Method not found`.

## Architecture Notes

Request flow:

`MCP client -> Worker/Hono -> tool handlers -> DNS DoH`

Core subsystems:

- Input sanitation and domain validation
- Optional bearer-token authentication
- Per-IP rate limiting with KV + in-memory fallback
- Scan/result caching with KV + in-memory fallback
- Structured JSON logging

For implementation details and conventions, see `CLAUDE.md`.

## Security Model

Security and operational behaviors are documented in `docs/security-and-observability.md`.

High-level summary:

- Domain inputs are validated and sanitized before execution.
- IP literals are rejected across standard and alternate numeric forms (for example `127.1`, `0177.0.0.1`, `8.8.8.8`, `0x8.0x8.0x8.0x8`).
- SSRF protections block unsafe/private targets.
- Error responses are sanitized.
- DNS resolution is performed through Cloudflare DoH, with optional secondary confirmation on empty-answer responses to reduce false negatives.
- Rate limiting defaults to `10/min` and `100/hr` per IP for unauthenticated `tools/call` traffic.
- Unauthenticated control-plane traffic (`initialize`, `tools/list`, `resources/*`, `ping`, SSE connect, and session deletion) is separately throttled at `30/min` and `300/hr` per IP.
- Session creation is rate-limited (`30/min` per IP) for unauthenticated `initialize` and new SSE session bootstrap.

Natural-language convenience:

- `tools/call` supports `scan` as an alias for `scan_domain`.
- In chat-style clients, users can typically say `scan <domain>`.
- For best cross-client reliability, explicit phrasing like `Use scan_domain to scan example.com` is still recommended.
- Raw JSON-RPC still expects `params.name` to be `scan` or `scan_domain` (not full phrases in the name field).

## Provider Detection

`check_mx` and `scan_domain` include managed provider detection with structured finding metadata.

- Inbound provider detection uses MX host matching.
- Outbound provider inference uses SPF include/redirect signals and DKIM selector hints.
- Findings may include metadata fields such as:
  - `detectionType` (`inbound` or `outbound`)
  - `providers` (matched provider names and evidence)
  - `providerConfidence` (0.0-1.0 confidence used by scoring modifier)
  - `signatureSource`, `signatureVersion`, `signatureFetchedAt`
- Signature source fallback order is: runtime source -> stale cache -> built-in signatures.

Self-hosting can optionally configure:

- `PROVIDER_SIGNATURES_URL` (runtime provider-signature JSON source)
- `PROVIDER_SIGNATURES_SHA256` (required pinned digest for runtime provider-signature JSON)
- `PROVIDER_SIGNATURES_ALLOWED_HOSTS` (optional comma-separated hostname allowlist)

## Documentation

- Client setup: `docs/client-setup.md`
- Security and observability: `docs/security-and-observability.md`
- Scoring details: `docs/scoring.md`
- Coverage and limitations: `docs/coverage.md`
- Troubleshooting: `docs/troubleshooting.md`
- Documentation style guide: `docs/style-guide.md`

## Self-Hosting

Prerequisites:

- [Node.js](https://nodejs.org/) 18+
- Cloudflare account

Deploy to your account:

```bash
git clone https://github.com/MadaBurns/bv-mcp.git
cd bv-mcp
npm install
npm run setup:kv          # Creates KV namespaces — note the printed IDs
cp wrangler.jsonc .dev/wrangler.local.jsonc
```

Edit `.dev/wrangler.local.jsonc`:

1. Set `"main"` to `"../src/index.ts"`
2. Paste the KV namespace IDs printed by `setup:kv`
3. Optionally replace the `routes` domain with your own, or remove it to use `*.workers.dev`

Then deploy:

```bash
npm run deploy
```

Alternatively, for a quick deploy without a local config copy, edit `wrangler.jsonc` directly and run:

```bash
npm run deploy:production
```

Worker endpoint pattern:

`https://<your-worker>.workers.dev/mcp`

## Development

Run locally:

```bash
git clone https://github.com/MadaBurns/bv-mcp.git
cd bv-mcp
npm run setup
npm run dev
```

Local endpoint:

`http://localhost:8787/mcp`

Configure optional auth secret:

```bash
npx wrangler secret put BV_API_KEY
```

Optional provider signature source (in `wrangler.jsonc` vars):

```json
{
  "PROVIDER_SIGNATURES_URL": "https://<your-source>/provider-signatures.json",
  "PROVIDER_SIGNATURES_SHA256": "<sha256-hex>",
  "PROVIDER_SIGNATURES_ALLOWED_HOSTS": "<your-source>"
}
```

## Testing

```bash
npm test
```

```bash
npm run typecheck
```

Manual request examples and common failure modes are in `docs/troubleshooting.md`.

## License

MIT. See `LICENSE`.
