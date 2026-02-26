# dns-security-mcp

**The open source MCP server for DNS and email security. Scan any domain from inside Claude, Cursor, or any MCP-compatible AI.**

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Cloudflare Workers](https://img.shields.io/badge/Runs%20on-Cloudflare%20Workers-F38020?logo=cloudflare)](https://workers.cloudflare.com/)
[![MCP 2025-03-26](https://img.shields.io/badge/MCP-2025--03--26-blue)](https://modelcontextprotocol.io/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.5-3178C6?logo=typescript)](https://www.typescriptlang.org/)

---

## Quick Start

This is a **remote MCP server** — it runs on Cloudflare Workers, not on your local machine. You can use the hosted instance or deploy your own.

### Option A: Hosted Remote (no setup)

Connect directly to the BLACKVEIL-hosted endpoint. No cloning, no deploying.

**Claude Desktop** — add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "dns-security": {
      "url": "https://dns-mcp.blackveilsecurity.com/mcp"
    }
  }
}
```

**VS Code / GitHub Copilot** — add to `.vscode/mcp.json`:

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

**Cursor** — add to `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "dns-security": {
      "url": "https://dns-mcp.blackveilsecurity.com/mcp"
    }
  }
}
```

Open your AI client and ask: *"Scan blackveilsecurity.com for security issues"*.

## Security & Robustness

This MCP server is designed for maximum security and reliability:

- **Strict input validation:** All domain inputs are normalized, sanitized, and validated against RFC 1035. Unicode, IDN, emoji, and invisible characters are handled using punycode and explicit cleaning.
- **SSRF protection:** Blocks private/reserved TLDs, IP addresses, and DNS rebinding services. No queries to internal or unsafe networks.
- **Header normalization:** All incoming HTTP headers are normalized to lowercase and strictly ASCII, preventing header spoofing and Unicode edge cases.
- **Error handling:** Centralized error middleware ensures only known validation errors are returned to clients. Unexpected errors are sanitized and logged.
- **Rate limiting:** Per-IP limits (10/min, 50/hr) enforced via Cloudflare KV with in-memory fallback. Standard rate limit headers exposed.
- **Secrets:** Optional bearer token (`BV_API_KEY`) for production auth, constant-time comparison, never stored in logs.
- **No Node.js APIs:** Fully Cloudflare Workers compatible, using only fetch, crypto, and Web APIs.
- **Testing:** 270+ tests, >94% coverage, including edge cases for Unicode, malformed requests, KV failures, and error branches.

See [CLAUDE.md](CLAUDE.md) and [.github/copilot-instructions.md](.github/copilot-instructions.md) for implementation details and best practices.

### Option B: Self-Hosted Remote (your own Cloudflare Workers)

Deploy to your own Cloudflare account for full control:

```bash
git clone https://github.com/MadaBurns/bv-mcp.git
cd bv-mcp
npm run setup        # install dependencies
npm run setup:kv     # create KV namespaces (first time only)
npm run deploy       # deploy to Cloudflare Workers
```

Your endpoint is live at `https://dns-mcp.blackveilsecurity.com/mcp`. Use that URL in the client configs above.

### Option C: Local Development

```bash
git clone https://github.com/MadaBurns/bv-mcp.git
cd bv-mcp
npm run setup && npm run dev
```

Worker starts at `http://localhost:8787/mcp`. Use `http://localhost:8787/mcp` as the URL in your client config.

> **Why not npx / uvx?** This is a *remote* MCP server (Streamable HTTP transport), not a local stdio server. It runs on Cloudflare Workers, not on your machine. Tools like `npx` and `uvx` are designed for local stdio-based MCP servers. For remote servers, you just point your client at the URL — no local process needed.

---

## What It Does

Ten tools that check every layer of a domain's security posture — from email spoofing to certificate hygiene.

| Tool | What it checks |
|------|---------------|
| `scan_domain` | Full sweep — runs all checks in parallel, returns an overall score and letter grade |
| `check_spf` | Can anyone impersonate your email? Validates SPF records and authorised senders |
| `check_dmarc` | What happens to spoofed email? Checks DMARC policy enforcement |
| `check_dkim` | Are emails cryptographically signed? Probes DKIM selectors for key records |
| `check_mx` | Does the domain accept email? Checks MX records and flags likely outbound email usage |
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
You:    Scan blackveilsecurity.com for security issues
Claude: [calls scan_domain("blackveilsecurity.com")]
        → Overall Score: 62/100 (C)
        → SPF: Warning — soft fail (~all) allows spoofed email through
        → DMARC: Fail — no DMARC record found
        → DKIM: Pass — valid key found on selector 'google'
        → DNSSEC: Fail — not enabled
        → SSL: Pass — valid certificate, expires in 287 days
```

**"Why are our emails going to spam?"**
```
You:    Check SPF and DMARC for blackveilsecurity.com
Claude: [calls check_spf("blackveilsecurity.com"), check_dmarc("blackveilsecurity.com")]
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

## How It Works

This server is **open source but queries an external service** for DNS resolution. All DNS lookups are performed via [Cloudflare's public DNS-over-HTTPS API](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/) (`cloudflare-dns.com/dns-query`). No queries are logged or stored by this server — but Cloudflare's standard [privacy policy](https://developers.cloudflare.com/1.1.1.1/privacy/public-dns-resolver/) applies to the DNS resolution itself.

The server does not phone home, collect telemetry, or send data anywhere other than Cloudflare DoH. You can verify this by auditing the source — every outbound request originates from [src/lib/dns.ts](src/lib/dns.ts).

---

## Architecture

```
MCP Client ──► Cloudflare Worker (Hono) ──► Cloudflare DoH API
                  │                            (dns-over-HTTPS)
                  ├─ KV-backed rate limiter (10/min, 50/hr per IP)
                  ├─ KV-backed scan cache (5 min TTL)
                  ├─ Optional bearer token auth
                  └─ Weighted scoring engine
```

| Component | Role |
|-----------|------|
| **Hono** | HTTP framework — routes, CORS, middleware |
| **Cloudflare DoH** | All DNS queries via `https://cloudflare-dns.com/dns-query` (JSON wire format) |
| **Cloudflare KV** | Distributed rate limiting and response caching |
| **MCP Streamable HTTP** | JSON-RPC 2.0 transport with optional SSE streaming (spec 2025-03-26) |
| **Scoring Engine** | Weighted category scores (0–100) with severity-based penalties, mapped to A+ through F |

---

## Self-Hosting Details

### Prerequisites

- [Node.js](https://nodejs.org/) v18+
- A free [Cloudflare account](https://dash.cloudflare.com/sign-up)

### Setup

```bash
npm run setup        # install dependencies
npm run setup:kv     # create RATE_LIMIT and SCAN_CACHE KV namespaces
npm run deploy       # deploy to Cloudflare Workers
```

After `setup:kv`, update the KV namespace IDs in `wrangler.jsonc` with the values printed by the command.

---

## Authentication

Auth is optional by design:

- If `BV_API_KEY` is set, all `/mcp` requests require `Authorization: Bearer <token>`.
- If `BV_API_KEY` is unset or empty, `/mcp` runs unauthenticated (open-source / local dev mode).
- Missing or invalid tokens return a JSON-RPC error with HTTP `401`.
- `/health` remains unauthenticated.

Set the API key secret (optional, production):

```bash
npx wrangler secret put BV_API_KEY
```

---

## Connecting MCP Clients

> Replace the URL below with your own endpoint if self-hosting (Option B) or running locally (Option C).

### Claude Desktop

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

### VS Code / GitHub Copilot

Add to `.vscode/mcp.json` in your workspace (or user settings):

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

### Cursor

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

### Supported Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/mcp` | MCP JSON-RPC 2.0 requests (SSE streaming via `Accept: text/event-stream`) |
| `GET` | `/mcp` | SSE stream for server-to-client notifications |
| `DELETE` | `/mcp` | Session termination |
| `GET` | `/health` | Health check |

---

## Scoring Methodology

The scan model uses 8 categories with importance weighting aligned to real-world impact:

| Category | Weight |
|----------|--------|
| DMARC | 22 |
| SPF | 19 |
| DKIM | 10 |
| SSL/TLS | 8 |
| DNSSEC | 3 |
| MTA-STS | 3 |
| NS | 0 (informational) |
| CAA | 0 (informational) |

Plus up to +5 email configuration bonus.

**Per-finding severity penalties:** Critical −40, High −25, Medium −15, Low −5, Info 0.

**Grades:** A+ (90+), A (85–89), B+ (80–84), B (75–79), C+ (70–74), C (65–69), D+ (60–64), D (55–59), E (50–54), F (<50).

---

## Running Tests

270+ tests with >94% code coverage:

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

— Adam Burns, [BLACKVEIL](https://blackveilsecurity.com)

---

## Want Autonomous Remediation?

This tool finds problems. [BLACKVEIL](https://blackveilsecurity.com) fixes them automatically.

---

## Development Container (DevContainer)

This repository supports [VS Code DevContainers](https://containers.dev/) and GitHub Codespaces for safe, reproducible development in an isolated environment.

### Quick Start

1. **Open in VS Code**
   - Install the [Dev Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers).
   - Open the repo in VS Code and select "Reopen in Container" when prompted.

2. **Open in GitHub Codespaces**
   - Click the "Code" dropdown in GitHub and select "Open with Codespaces".

### Features
- Pre-configured Node.js, TypeScript, Wrangler CLI, Vitest, and Cloudflare tools
- Port 8787 forwarded for local dev server
- Recommended extensions: Prettier, ESLint, Cloudflare, TypeScript Next
- Sample `.env.example` for secrets

### Container Details
- `.devcontainer/devcontainer.json` — DevContainer config
- `.devcontainer/Dockerfile` — Custom image (Node, Wrangler CLI, Vitest)
- `.devcontainer/.env.example` — Sample environment variables

### Usage
```bash
npm install        # Installs dependencies
npm run dev        # Starts local dev server at http://localhost:8787
npm test           # Runs tests in Cloudflare Workers pool
npm run deploy     # Deploys to Cloudflare Workers
```

You can run all development, testing, and deployment commands inside the container. No local setup required.

---


## Client Integration: VS Code, Claude, Gemini

This MCP server exposes a Model Context Protocol endpoint for DNS security analysis at:

**Endpoint:** `https://dns-mcp.blackveilsecurity.com/mcp`

### VS Code (Copilot MCP, Claude, Gemini)
- Install an MCP-compatible extension (e.g., Copilot MCP, Claude, or Gemini plugin for VS Code).
- In the extension settings, set the MCP endpoint URL to:
  
  `https://dns-mcp.blackveilsecurity.com/mcp`
- If authentication is required, set the Bearer token to your `BV_API_KEY` (leave blank for open mode).
- Ensure the extension supports JSON-RPC 2.0 over HTTP (streamable preferred).

### Claude (Anthropic)
- Use the "Add MCP Tool" or "Connect External Tool" feature in your Claude workspace.
- Set the endpoint to:
  
  `https://dns-mcp.blackveilsecurity.com/mcp`
- If prompted, provide the Bearer token (`BV_API_KEY`) or leave blank for open access.
- Claude will auto-discover available tools and schemas.

### Gemini (Google)
- In Gemini's tool/plugin settings, add a new MCP endpoint:
  
  `https://dns-mcp.blackveilsecurity.com/mcp`
- Provide the Bearer token if required.
- Gemini will list available DNS security tools after connecting.

#### Notes
- All clients must support JSON-RPC 2.0 over HTTP POST.
- Max request body: 10KB.
- Rate limits: 10 req/min, 50 req/hr per IP (see server docs).
- For custom deployments, update the endpoint URL accordingly.

For more details, see the [CLAUDE.md](CLAUDE.md) and [.github/copilot-instructions.md](.github/copilot-instructions.md).

---
## Manual Testing & Troubleshooting

### Test MCP Endpoint with curl

To manually test the MCP server, send a JSON-RPC request using curl:

```bash
curl -X POST https://dns-mcp.blackveilsecurity.com/mcp \
  -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","method":"scan_domain","params":{"domain":"example.com"},"id":1}'
```

If authentication is enabled (`BV_API_KEY` is set), add the Authorization header:

```bash
curl -X POST https://dns-mcp.blackveilsecurity.com/mcp \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <your-api-key>' \
  --data '{"jsonrpc":"2.0","method":"scan_domain","params":{"domain":"example.com"},"id":1}'
```

### Session Handling
- Most MCP clients (Claude, Cursor, Copilot) handle session automatically.
- Manual requests do **not** require a session unless your client expects it or the server is configured to require one.
- If you see `"invalid or missing session"`, try using a supported MCP client or check server configuration.

### Health Check
Verify the server is running:

```bash
curl https://dns-mcp.blackveilsecurity.com/health
```

### Troubleshooting
- **401 Unauthorized:** Ensure you are sending the correct `Authorization: Bearer <token>` header if `BV_API_KEY` is set.
- **Invalid or missing session:** Use a supported MCP client, or check if your request needs a session parameter.
- **Other errors:** Review server logs or MCP client documentation.

---
