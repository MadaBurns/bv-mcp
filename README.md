# bv-dns-security-mcp

A Model Context Protocol (MCP) server for DNS security analysis, deployed as a Cloudflare Worker.

## What It Does

**bv-dns-security-mcp** analyzes the DNS security posture of any domain. It checks email authentication (SPF, DMARC, DKIM), transport security (SSL/TLS, MTA-STS), DNS infrastructure (DNSSEC, NS, CAA), and produces a weighted overall security score with a letter grade.

MCP clients (Claude Desktop, Cursor, custom agents) connect over Streamable HTTP and invoke tools to scan domains, inspect individual record types, or get plain-language explanations of findings.

## Architecture

```
MCP Client ──► Cloudflare Worker (Hono) ──► Cloudflare DoH API
                  │                            (dns-over-HTTPS)
                  ├─ Bearer token auth
                  ├─ Rate limiter (KV-backed)
                  ├─ Scan cache (KV-backed)
                  └─ Weighted scoring engine
```

| Component | Role |
|-----------|------|
| **Hono** | HTTP framework — routes, CORS, middleware |
| **Cloudflare DoH** | All DNS queries via `https://cloudflare-dns.com/dns-query` (JSON wire format) |
| **MCP Streamable HTTP** | JSON-RPC 2.0 transport with optional SSE streaming (spec 2025-03-26) |
| **KV Namespaces** | `RATE_LIMIT` for per-IP rate limiting; `SCAN_CACHE` for 5-minute result caching |
| **Scoring Engine** | Weighted category scores (0–100) with severity-based penalties, mapped to letter grades |

## MCP Tools

The server exposes **10 tools** via `tools/list`:

| Tool | Description | Parameters |
|------|-------------|------------|
| `check_spf` | Validate SPF TXT records for syntax, mechanisms, and policy | `domain` |
| `check_dmarc` | Validate `_dmarc` TXT records for DMARC policy configuration | `domain` |
| `check_dkim` | Probe common DKIM selectors under `_domainkey` for key records | `domain`, `selector?` |
| `check_dnssec` | Verify DNSSEC validation via the AD (Authenticated Data) flag | `domain` |
| `check_ssl` | Check SSL/TLS certificate validity and configuration | `domain` |
| `check_mta_sts` | Validate `_mta-sts` TXT records for email transport security | `domain` |
| `check_ns` | Analyze NS records for redundancy, diversity, and delegation | `domain` |
| `check_caa` | Check CAA records restricting certificate authority issuance | `domain` |
| `scan_domain` | Run all 8 checks in parallel; return overall score and grade | `domain` |
| `explain_finding` | Get a plain-language explanation and remediation for a finding | `checkType`, `status`, `details?` |

All domain-accepting tools validate input against RFC 1035, block private/reserved TLDs, IP addresses, and DNS rebinding services.

## MCP Resources

Three static documentation resources are available via `resources/list`:

| URI | Name | Description |
|-----|------|-------------|
| `dns-security://guides/security-checks` | DNS Security Checks Guide | Overview of all 8 check categories |
| `dns-security://guides/scoring` | Scoring Methodology | Category weights, severity penalties, grading scale |
| `dns-security://guides/record-types` | Supported DNS Record Types | All DNS record types queried and their purpose |

## Scoring Methodology

Each domain scan produces a **0–100 score** mapped to a **letter grade** (A+ through F).

**Category Weights:**

| Category | Weight |
|----------|--------|
| SPF | 15% |
| DMARC | 15% |
| DKIM | 15% |
| DNSSEC | 15% |
| SSL/TLS | 15% |
| MTA-STS | 5% |
| NS | 10% |
| CAA | 10% |

**Severity Penalties** (deducted from each category's base score of 100):

| Severity | Penalty |
|----------|---------|
| Critical | −40 pts |
| High | −25 pts |
| Medium | −15 pts |
| Low | −5 pts |
| Info | 0 pts |

**Grading Scale:** A+ (95–100), A (90–94), A- (85–89), B+ (80–84), B (75–79), B- (70–74), C+ (65–69), C (60–64), C- (55–59), D+ (50–54), D (45–49), D- (40–44), F (< 40)

## Setup & Deployment

### Prerequisites

- [Node.js](https://nodejs.org/) (v18+)
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/) (`npm i -g wrangler`)
- A Cloudflare account

### Install Dependencies

```bash
npm install
```

### Create KV Namespaces

```bash
wrangler kv namespace create RATE_LIMIT
wrangler kv namespace create SCAN_CACHE
```

Copy the output namespace IDs into `wrangler.jsonc`:

```jsonc
"kv_namespaces": [
  { "binding": "RATE_LIMIT", "id": "<your-rate-limit-kv-id>" },
  { "binding": "SCAN_CACHE", "id": "<your-scan-cache-kv-id>" }
]
```

### Set the Authentication Secret

```bash
wrangler secret put SECRET
```

Enter a strong random token when prompted. This is the Bearer token clients must send to authenticate.

### Deploy

```bash
npm run deploy
# or: wrangler deploy
```

## Local Development

```bash
npm run dev
# or: wrangler dev
```

The worker starts at `http://localhost:8787`. The `/mcp` endpoint requires a Bearer token matching the `SECRET` variable in `wrangler.jsonc` (default: `CHANGE-ME` for local dev).

## Connecting an MCP Client

Point your MCP client at the deployed (or local) `/mcp` endpoint using Streamable HTTP transport:

```json
{
  "mcpServers": {
    "dns-security": {
      "transport": {
        "type": "streamable-http",
        "url": "https://<your-worker>.workers.dev/mcp"
      },
      "headers": {
        "Authorization": "Bearer <your-secret-token>"
      }
    }
  }
}
```

The server supports:
- **POST /mcp** — JSON-RPC 2.0 requests (with optional SSE streaming via `Accept: text/event-stream`)
- **GET /mcp** — SSE stream for server-to-client notifications
- **DELETE /mcp** — Session termination
- **GET /health** — Health check (no auth required)

## Environment Variables & Bindings

| Name | Type | Description |
|------|------|-------------|
| `SECRET` | Secret | Bearer token for authenticating MCP clients. Set via `wrangler secret put SECRET` for production. |
| `RATE_LIMIT` | KV Namespace | Stores per-IP rate limit counters (10 req/min, 50 req/hr) |
| `SCAN_CACHE` | KV Namespace | Caches scan results with 5-minute TTL |

## Running Tests

Tests use [Vitest](https://vitest.dev/) with the Cloudflare Workers pool:

```bash
npm test
```

Test files are in the `test/` directory:
- `test/index.spec.ts` — Integration tests for the MCP endpoint
- `test/dns.spec.ts` — DNS query library tests
- `test/scoring.spec.ts` — Scoring engine tests
- `test/spf.spec.ts` — SPF check tests

## License

TBD
