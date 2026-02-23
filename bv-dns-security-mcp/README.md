# dns-security-mcp

**The open source MCP server for DNS and email security. Scan any domain from inside Claude, Cursor, or any MCP-compatible AI.**

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Cloudflare Workers](https://img.shields.io/badge/Runs%20on-Cloudflare%20Workers-F38020?logo=cloudflare)](https://workers.cloudflare.com/)
[![MCP 2025-03-26](https://img.shields.io/badge/MCP-2025--03--26-blue)](https://modelcontextprotocol.io/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.5-3178C6?logo=typescript)](https://www.typescriptlang.org/)

<!-- TODO: Replace with a real screenshot of Claude Desktop running scan_domain -->
<!-- ![Screenshot](docs/screenshot.png) -->

---

## Quick Start

```bash
# Option 1: Deploy to Cloudflare Workers (recommended)
git clone https://github.com/blackveil/dns-security-mcp.git
cd dns-security-mcp
npm install && npx wrangler deploy

# Option 2: Run locally for development
npm install && npm run dev

# Option 3: Use the hosted version (no setup required)
# MCP endpoint: https://dns-mcp.blackveil.co.nz/mcp
```

### Connect to Claude Desktop

Add this to your Claude Desktop config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "dns-security": {
      "url": "https://dns-mcp.blackveil.co.nz/mcp"
    }
  }
}
```

That's it. Open Claude and ask: *"Scan blackveil.co.nz for security issues"*.

---

## What It Does

Ten tools that check every layer of a domain's security posture — from email spoofing to certificate hygiene.

| Tool | What it checks |
|------|---------------|
| `scan_domain` | Full sweep — runs all checks in parallel, returns an overall score and letter grade |
| `check_spf` | Can anyone impersonate your email? Validates SPF records and authorised senders |
| `check_dmarc` | What happens to spoofed email? Checks DMARC policy enforcement |
| `check_dkim` | Are emails cryptographically signed? Probes DKIM selectors for key records |
| `check_ssl` | Is the connection secure? Validates certificate, expiry, and TLS configuration |
| `check_dnssec` | Can DNS responses be tampered with? Verifies DNSSEC chain of trust |
| `check_mta_sts` | Is email transport encrypted? Checks MTA-STS policy enforcement |
| `check_ns` | Is DNS infrastructure resilient? Analyses nameserver redundancy and diversity |
| `check_caa` | Who can issue certificates? Checks CAA records restricting certificate authorities |
| `explain_finding` | Don't understand a result? Get a plain-English explanation with remediation steps |

Every domain input is validated against RFC 1035, blocks private/reserved TLDs, IP addresses, and DNS rebinding services.

---

## Example Conversations

**"Is my startup's domain safe?"**
```
You:    Scan example.com for security issues
Claude: [calls scan_domain("example.com")]
        → Overall Score: 62/100 (C)
        → SPF: Warning — soft fail (~all) allows spoofed email through
        → DMARC: Fail — no DMARC record found
        → DKIM: Pass — valid key found on selector 'google'
        → DNSSEC: Fail — not enabled
        → SSL: Pass — valid certificate, expires in 287 days
```

**"Why are our emails going to spam?"**
```
You:    Check SPF and DMARC for ourdomain.com
Claude: [calls check_spf("ourdomain.com"), check_dmarc("ourdomain.com")]
        → SPF has 12 lookups (max 10) — exceeding the limit causes hard failures
        → DMARC is set to p=none — ISPs aren't enforcing any policy on spoofed mail
```

**"Explain this DNSSEC finding"**
```
You:    Explain why DNSSEC failing is a problem
Claude: [calls explain_finding({ checkType: "DNSSEC", status: "FAIL" })]
        → Without DNSSEC, attackers can poison DNS responses and redirect your
          users to malicious servers. Enable DNSSEC through your domain registrar.
```

---

## Architecture

```
MCP Client ──► Cloudflare Worker (Hono) ──► Cloudflare DoH API
                  │                            (dns-over-HTTPS)
                  ├─ In-memory rate limiter
                  ├─ In-memory scan cache (5 min TTL)
                  └─ Weighted scoring engine
```

No private bindings. No KV. No secrets. No authentication required.
The whole point is it runs standalone with `npx wrangler deploy`.

| Component | Role |
|-----------|------|
| **Hono** | HTTP framework — routes, CORS, middleware |
| **Cloudflare DoH** | All DNS queries via `https://cloudflare-dns.com/dns-query` (JSON wire format) |
| **MCP Streamable HTTP** | JSON-RPC 2.0 transport with optional SSE streaming (spec 2025-03-26) |
| **Scoring Engine** | Weighted category scores (0–100) with severity-based penalties, mapped to A+ through F |

---

## Setup & Deployment

### Prerequisites

- [Node.js](https://nodejs.org/) v18+
- A free [Cloudflare account](https://dash.cloudflare.com/sign-up)

### Deploy

```bash
git clone https://github.com/blackveil/dns-security-mcp.git
cd dns-security-mcp
npm install
npx wrangler deploy
```

Your MCP endpoint is live at `https://dns-security-mcp.<your-subdomain>.workers.dev/mcp`.

### Local Development

```bash
npm run dev
```

Worker starts at `http://localhost:8787`. The `/mcp` endpoint is open — no tokens, no setup.

---

## Connecting MCP Clients

### Claude Desktop

```json
{
  "mcpServers": {
    "dns-security": {
      "url": "https://dns-mcp.blackveil.co.nz/mcp"
    }
  }
}
```

### Cursor / VS Code Copilot

Point your MCP client at the `/mcp` endpoint using Streamable HTTP transport:

```json
{
  "mcpServers": {
    "dns-security": {
      "transport": {
        "type": "streamable-http",
        "url": "https://dns-mcp.blackveil.co.nz/mcp"
      }
    }
  }
}
```

### Supported Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/mcp` | MCP JSON-RPC 2.0 requests (SSE streaming via `Accept: text/event-stream`) |
| `GET` | `/mcp` | SSE stream for server-to-client notifications |
| `DELETE` | `/mcp` | Session termination |
| `GET` | `/health` | Health check |

---

## Running Tests

218 tests with >94% code coverage:

```bash
npm test
```

Tests use [Vitest](https://vitest.dev/) with the Cloudflare Workers pool. All DNS responses are mocked — no network calls during testing.

---

## Why We Built This

We've scanned 760,000 domains. The same mistakes show up everywhere — missing DMARC policies, broken SPF records, no DNSSEC, expired certificates nobody noticed. These aren't exotic attacks. They're the basics, and most organisations get them wrong.

MCP means your AI assistant can now run these checks in the conversation where you're already working. No dashboard to context-switch to. No CLI to remember. Just ask.

### Why It's Open Source

You're connecting an MCP tool to your AI client that sends domain queries over the wire. The first question any good security person asks is *"what is this thing actually doing with my queries?"*

If the code is closed, the answer is "trust us" — and that's a hard sell from a brand you've never heard of.

Open source means you can:
- **Audit** exactly what DNS queries are being made
- **Confirm** there's no query logging or data exfiltration
- **Self-host** if your security policy requires it
- **Contribute** improvements back

The code isn't our moat. Anyone could write a DNS security MCP in a weekend. What you can't replicate is 760,000 scans worth of industry baselines, continuous monitoring infrastructure, and the platform that fixes what this tool finds.

The repo stays open. The dataset stays private. That's the line.

— Adam Burns, [BLACKVEIL](https://blackveil.co.nz)

---

## Want Autonomous Remediation?

This tool finds problems. [BLACKVEIL](https://blackveil.co.nz) fixes them automatically.

---

## License

[MIT](LICENSE)
