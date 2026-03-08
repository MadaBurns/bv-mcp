# Blackveil DNS

Open-source DNS & email security scanner for Claude, Cursor, VS Code, and any MCP client.
Passive, read-only checks via Cloudflare DoH. Runs on Cloudflare Workers.

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Cloudflare Workers](https://img.shields.io/badge/Runs%20on-Cloudflare%20Workers-F38020?logo=cloudflare)](https://workers.cloudflare.com/)
[![MCP 2025-03-26](https://img.shields.io/badge/MCP-2025--03--26-blue)](https://modelcontextprotocol.io/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.5-3178C6?logo=typescript)](https://www.typescriptlang.org/)
[![Tests](https://img.shields.io/badge/Tests-630%2B-brightgreen)](https://github.com/MadaBurns/bv-mcp/actions)
[![Coverage](https://img.shields.io/badge/Coverage-~95%25-brightgreen)](https://github.com/MadaBurns/bv-mcp/actions)

### What can it do?

Point it at any domain and get back a full security audit — scored 0–100 with a letter grade.

- **Email authentication:** SPF, DMARC, DKIM — validates policy, syntax, key strength, alignment
- **SPF trust surface analysis:** Detects multi-tenant SaaS platform includes (Google, M365, SendGrid, etc.) that widen your domain's spoofing attack surface
- **Brand protection:** BIMI record validation and lookalike/typosquat domain detection with mail infrastructure probing
- **DNS infrastructure:** DNSSEC validation, NS redundancy and diversity, CAA issuer restrictions, wildcard DNS detection
- **Transport security:** SSL/TLS certificate health, HSTS, MTA-STS policy enforcement, TLS-RPT reporting
- **Threat detection:** Subdomain takeover via dangling CNAME analysis across 30+ services
- **Provider intelligence:** Infers inbound and outbound email providers from MX, SPF, and DKIM signals
- **Maturity staging:** Classifies domains into email security maturity stages (0-4: Unprotected → Hardened) with actionable next steps
- **Remediation:** `explain_finding` returns plain-English guidance using everyday analogies — guest lists, wax seals, padlocks — so anyone on your team can understand the risk

Each check runs independently or together via `scan_domain`.

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Example output](#example-output)
- [Tool Surface](#tool-surface)
- [Coverage](#coverage)
- [Protocol Endpoints](#protocol-endpoints)
- [Architecture Notes](#architecture-notes)
- [Security Model](#security-model)
- [Documentation](#documentation)
- [Development](#development)
- [Testing](#testing)
- [Why this exists](#why-this-exists)
- [License](#license)

## Overview

Blackveil DNS exposes DNS/email security checks through MCP over Streamable HTTP (JSON-RPC 2.0).

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
    "blackveil-dns": {
      "type": "http",
      "url": "https://dns-mcp.blackveilsecurity.com/mcp"
    }
  }
}
```

**Claude Code** (`.mcp.json` or via CLI):

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

```bash
claude mcp add --transport http blackveil-dns https://dns-mcp.blackveilsecurity.com/mcp
```

**Claude Desktop** (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "blackveil-dns": {
      "url": "https://dns-mcp.blackveilsecurity.com/mcp"
    }
  }
}
```

**Cursor** (`.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "blackveil-dns": {
      "url": "https://dns-mcp.blackveilsecurity.com/mcp"
    }
  }
}
```

For full client setup and auth details, see `docs/client-setup.md`.

## Example output

Run `scan_domain` against any domain to get a scored security report:

```json
{
  "domain": "example.com",
  "score": {
    "overall": 62,
    "grade": "D+",
    "categoryScores": {
      "spf": 85,
      "dmarc": 60,
      "dkim": 0,
      "dnssec": 0,
      "ssl": 100,
      "mta_sts": 0,
      "ns": 100,
      "caa": 60,
      "subdomain_takeover": 100,
      "mx": 100,
      "bimi": 100,
      "tlsrpt": 95
    },
    "findings": [
      {
        "category": "dkim",
        "title": "No DKIM records found",
        "severity": "high",
        "detail": "No DKIM key records were found for any probed selectors."
      },
      {
        "category": "dnssec",
        "title": "DNSSEC not enabled",
        "severity": "critical",
        "detail": "DNS responses are not signed. Zone does not appear to use DNSSEC."
      },
      {
        "category": "dmarc",
        "title": "DMARC policy is not enforced",
        "severity": "medium",
        "detail": "DMARC policy is set to p=none, which monitors but does not enforce."
      }
    ],
    "summary": "Score: 62/100 (D+). 3 critical, 2 high, 1 medium across 12 categories."
  },
  "checks": [
    { "category": "spf", "passed": true, "score": 85, "findings": [] },
    { "category": "dmarc", "passed": true, "score": 60, "findings": ["..."] },
    { "category": "dkim", "passed": false, "score": 0, "findings": ["..."] },
    { "category": "dnssec", "passed": false, "score": 0, "findings": ["..."] },
    { "category": "ssl", "passed": true, "score": 100, "findings": [] },
    { "category": "mta_sts", "passed": false, "score": 0, "findings": ["..."] },
    { "category": "ns", "passed": true, "score": 100, "findings": [] },
    { "category": "caa", "passed": true, "score": 60, "findings": ["..."] },
    { "category": "subdomain_takeover", "passed": true, "score": 100, "findings": [] },
    { "category": "mx", "passed": true, "score": 100, "findings": ["..."] },
    { "category": "bimi", "passed": true, "score": 100, "findings": ["..."] },
    { "category": "tlsrpt", "passed": true, "score": 95, "findings": ["..."] }
  ],
  "maturity": {
    "stage": 1,
    "label": "Basic",
    "description": "Basic email records exist but are not enforcing or monitoring.",
    "nextStep": "Add DMARC aggregate reporting (rua=) and monitor for 2-4 weeks before enforcing."
  },
  "cached": false,
  "timestamp": "2026-03-09T12:00:00.000Z"
}
```

Use `explain_finding` on any result to get plain-English remediation guidance.

## Tool Surface

Directly callable MCP tools:

- `check_mx`
- `check_spf` — includes SPF trust surface analysis (detects multi-tenant SaaS platform includes)
- `check_dmarc`
- `check_dkim`
- `check_dnssec`
- `check_ssl`
- `check_mta_sts`
- `check_ns` — includes wildcard DNS detection
- `check_caa`
- `check_bimi` — BIMI (Brand Indicators for Message Identification) record validation
- `check_tlsrpt` — TLS-RPT (SMTP TLS Reporting) record validation
- `check_lookalikes` — lookalike/typosquat domain detection (standalone, not in `scan_domain`)
- `scan_domain` — runs all checks + email security maturity staging (Stage 0-4)
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

## Coverage

Blackveil DNS covers the core checks in each security category. The full Blackveil platform extends each category with deeper analytics.

| Category | Total Scanner Checks | Free Tier (MCP/Core) | Premium Platform |
|---|---:|---|---|
| SPF | 8 | Core SPF policy and syntax checks | Advanced include-chain and sender-path analytics |
| DMARC | 10 | Core policy, pct, reporting checks, URI validation, alignment modes | Alignment depth, subdomain inheritance, reporting quality analytics |
| DKIM | 9 | Selector discovery, RSA key strength validation, v= tag checks | Selector entropy, rotation heuristics, key-age and drift analytics |
| DNSSEC | 6 | AD validation and signed-zone baseline | Chain-of-trust and rollover posture analytics |
| SSL/TLS | 8 | Certificate availability and baseline validity checks | Protocol/cipher depth, PKI posture, renewal-risk analytics |
| MTA-STS | 5 | TXT policy presence and basic policy retrieval checks | Policy hardening and reporting-depth analytics |
| NS | 4 | Delegation, diversity, and resiliency baseline checks | Infrastructure concentration and availability analytics |
| CAA | 4 | CAA presence and issuer-allowlist baseline checks | Issuance surface modeling and mis-issuance risk analytics |
| MX | 4 | MX presence, routing quality, and outbound provider inference | Mail routing posture and provider analytics |
| Subdomain Takeover | 2 | Dangling CNAME detection across known subdomains | Expanded asset discovery and takeover surface analytics |
| BIMI | 2 | BIMI record presence, logo URL, VMC validation | Brand indicator analytics and compliance monitoring |
| TLS-RPT | 2 | TLS-RPT record presence and reporting URI validation | Reporting depth and delivery analytics |
| Lookalikes | 3 | Typosquat/lookalike domain detection with DNS + MX probing | Expanded permutation strategies and monitoring |

> Total checks: **57** across all categories.

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
- `check_lookalikes` is additionally capped at `5/day` per IP (unauthenticated) with 60-minute result caching, due to high outbound query volume
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

Optional provider signature configuration:

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

## Development

Run locally:

```bash
git clone https://github.com/MadaBurns/bv-mcp.git
cd bv-mcp
npm install
npm run dev
```

Local endpoint:

`http://localhost:8787/mcp`

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

## Why this exists

Most DNS and email security tools are either paywalled SaaS dashboards or CLI scripts that require local installation and configuration. Neither works well inside an AI coding assistant where you want to check a domain's security posture mid-conversation.

Blackveil DNS is a remote MCP server — one endpoint URL, no install, no API key required. Point any MCP client at `https://dns-mcp.blackveilsecurity.com/mcp` and start scanning. Every check uses only public Cloudflare DoH APIs, so there's no active reconnaissance and nothing that requires authorization from the target domain.

Built and maintained by [BLACKVEIL Security](https://blackveilsecurity.com), a New Zealand-based cybersecurity consultancy.

Featured in [SecurityBrief](https://securitybrief.co.nz/story/exclusive-how-cybersecurity-startup-blackveil-is-targetting-ai-driven-threats), [NZ Herald](https://www.nzherald.co.nz/video/herald-now/ryan-bridge-today/cybersecurity-medimap-hack/OMLGW3OMXOVSSJ3RLFXPMAVGKE/), and the [Modern Cyber](https://www.youtube.com/watch?v=W4aJHpfB5rY) podcast.

## License

MIT. See `LICENSE`.
