<div align="center">

# BLACK**V**EIL DNS

**Know where you stand.**

Open-source DNS & email security scanner for Claude, Cursor, VS Code, and MCP clients across Streamable HTTP, stdio, and legacy HTTP+SSE.

[![GitHub stars](https://img.shields.io/github/stars/MadaBurns/bv-mcp?style=flat&logo=github)](https://github.com/MadaBurns/bv-mcp/stargazers)
[![npm version](https://img.shields.io/npm/v/blackveil-dns)](https://www.npmjs.com/package/blackveil-dns)
[![npm downloads](https://img.shields.io/npm/dm/blackveil-dns)](https://www.npmjs.com/package/blackveil-dns)
[![Tests](https://img.shields.io/badge/Tests-1456-brightgreen)](https://github.com/MadaBurns/bv-mcp/actions)
[![Coverage](https://img.shields.io/badge/Coverage-~90%25-brightgreen)](https://github.com/MadaBurns/bv-mcp/actions)
[![BUSL-1.1 License](https://img.shields.io/badge/License-BUSL--1.1-blue.svg)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-2025--03--26-blue)](https://modelcontextprotocol.io/)
[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare%20Workers-F38020?logo=cloudflare&logoColor=white)](https://workers.cloudflare.com/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.5-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)

![DNS Security](https://dns-mcp.blackveilsecurity.com/badge/blackveilsecurity.com)

</div>

---

## Try it in 30 seconds

**Claude Code** (one command):

```bash
claude mcp add --transport http blackveil-dns https://dns-mcp.blackveilsecurity.com/mcp
```

Then ask: `scan anthropic.com`

**Verify the endpoint is live:**

```bash
curl https://dns-mcp.blackveilsecurity.com/health
```

No install. No API key. One URL for hosted HTTP:

```
Endpoint   https://dns-mcp.blackveilsecurity.com/mcp
Transport  Streamable HTTP · JSON-RPC 2.0
Auth       None required
```

Transport support:

- `Streamable HTTP`: `POST /mcp`, `GET /mcp`, `DELETE /mcp`
- `Native stdio`: `blackveil-dns-mcp` CLI from the `blackveil-dns` npm package
- `Legacy HTTP+SSE`: `GET /mcp/sse` bootstrap stream plus `POST /mcp/messages?sessionId=...`

<!-- TODO: Add terminal demo GIF here -->

---

## What you get

- **57+ checks across 20 categories** — SPF, DMARC, DKIM, DNSSEC, SSL/TLS, MTA-STS, NS, CAA, MX, BIMI, TLS-RPT, subdomain takeover, lookalike domains, HTTP security headers, DANE, shadow domains, TXT hygiene, MX reputation, SRV, zone hygiene
- **Maturity staging** — Stage 0-4 classification (Unprotected to Hardened) with next steps
- **Trust surface analysis** — detects shared SaaS platforms (Google, M365, SendGrid) and cross-references DMARC enforcement to determine real exposure
- **Guided remediation** — `generate_fix_plan` produces prioritized actions; record generators output ready-to-publish SPF, DMARC, DKIM, and MTA-STS records
- **Spoofability scoring** — `assess_spoofability` computes a composite 0-100 email spoofability score from SPF trust surface, DMARC enforcement, and DKIM coverage with interaction multipliers
- **Intelligence layer** — `get_benchmark` and `get_provider_insights` expose anonymized aggregate insights from scan telemetry: percentile rankings, provider cohort comparisons, and 7-day trend analysis
- **Multi-resolver consistency** — `check_resolver_consistency` queries 4 public DoH resolvers to detect GeoDNS, split-horizon DNS, or poisoning
- **Interaction scoring** — correlated weaknesses (e.g., weak DKIM + permissive DMARC) receive additional penalties beyond individual finding scores
- **Self-tuning scoring** — adaptive weights adjust category importance based on patterns seen across scans, so scores reflect real-world failure distributions rather than static assumptions
- **Provider intelligence** — inbound/outbound email provider inference from MX, SPF, DKIM
- **Context-optimized** — tool schemas, prompts, and resources are tuned for minimal token consumption in LLM clients
- **Passive and read-only** — all checks use public Cloudflare DNS-over-HTTPS; no authorization required from the target

Full scope and limitations in the coverage table below.

```
  scan_domain("anthropic.com")

  ████████████████████████████████████████░░░░░  85 / 100
  Grade: A  ·  Maturity: Enforcing

  SPF ·········· 80     MTA-STS ····· 85
  DMARC ········ 90     NS ·········· 95
  DKIM ········· 85     CAA ········· 85
  DNSSEC ······· 35     BIMI ········ 95
  SSL ········· 100     TLS-RPT ····· 95
  MX ·········· 100

  2 high · 4 medium · 5 low · 5 info
```

<div align="center">

**[Scan your domain now &rarr; blackveilsecurity.com](https://blackveilsecurity.com)**

</div>

---

## Tools

```
  33 MCP tools · 7 prompts · 6 resources

  Email Auth           Infrastructure        Brand & Threats       Meta
 ────────────         ────────────────       ─────────────────    ──────────────
  check_spf            check_dnssec           check_bimi           scan_domain
  check_dmarc          check_ns               check_tlsrpt         explain_finding
  check_dkim           check_caa              check_lookalikes     compare_baseline
  check_mta_sts        check_ssl              check_shadow_domains
  check_mx             check_http_security
  check_mx_reputation  check_dane             Intelligence         Remediation
                       check_dane_https      ──────────────       ──────────────
  DNS Hygiene          check_svcb_https       get_benchmark         generate_fix_plan
 ────────────          check_srv              get_provider_         generate_spf_record
  check_txt_hygiene    check_zone_hygiene       insights            generate_dmarc_record
                       check_resolver_        assess_spoofability   generate_dkim_config
                         consistency                                generate_mta_sts_policy

  + check_subdomain_takeover (internal — runs inside scan_domain)
```

`explain_finding` takes any finding and returns: what it means, potential impact, adverse consequences, specific steps to fix, and relevant RFCs.

`generate_fix_plan` scans a domain and produces a prioritized remediation plan with effort, impact, and dependency metadata. The record generators (`generate_spf_record`, `generate_dmarc_record`, `generate_dkim_config`, `generate_mta_sts_policy`) produce ready-to-publish DNS records based on detected configuration.

`get_benchmark` and `get_provider_insights` expose anonymized aggregate data from scan telemetry — percentile rankings, provider cohort scores, and 7-day trend analysis. `assess_spoofability` computes a composite email spoofability score (0-100) from SPF, DMARC, and DKIM with interaction multipliers.

`check_resolver_consistency` queries Cloudflare, Google, Quad9, and OpenDNS in parallel to detect GeoDNS, split-horizon DNS, or potential poisoning.

**Confidence labels:**
`deterministic` — direct protocol/record validation | `heuristic` — signal-based inference, may need manual validation | `verified` — high-confidence validation signal

**Subdomain takeover verification:**
`potential` — DNS signal, requires proof-of-control | `verified` — deprovisioning fingerprint detected | `not_exploitable` — no takeover signal

---

## Client setup

The free tier requires no authentication. If you have an API key, see the **With API key** tabs below to bypass rate limits.

<details>
<summary><b>VS Code / Copilot</b></summary>

`.vscode/mcp.json`

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

**With API key:**

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
</details>

<details>
<summary><b>Claude Code</b></summary>

`.mcp.json`

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

**With API key** — use `mcp-remote` to reliably forward the auth header:

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

Or via CLI:

```bash
claude mcp add-json blackveil-dns \
  '{"command":"npx","args":["mcp-remote","https://dns-mcp.blackveilsecurity.com/mcp","--header","Authorization: Bearer YOUR_API_KEY"]}'
```

> **Why `mcp-remote`?** Claude Code's native HTTP transport does not currently forward custom `headers` from config files. The `mcp-remote` bridge reliably passes the `Authorization` header to the server. Restart Claude Code after adding the server.
</details>

<details>
<summary><b>Claude Desktop</b></summary>

**Recommended:** Open [claude.ai](https://claude.ai) → **Settings → Connectors → Add custom connector** → paste `https://dns-mcp.blackveilsecurity.com/mcp`.

**With API key** — open **Settings → Developer → Edit Config** (`claude_desktop_config.json`) and add:

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

</details>

<details>
<summary><b>Cursor</b></summary>

`.cursor/mcp.json`

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
</details>

<details>
<summary><b>Windsurf</b></summary>

`~/.codeium/windsurf/mcp_config.json`

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
</details>

For hosted MCP setup, stdio usage, and legacy fallback endpoints, see `docs/client-setup.md`.

---

## CI/CD

Enforce DNS security grades in your pipeline with the [Blackveil DNS GitHub Action](https://github.com/MadaBurns/blackveil-dns-action):

```yaml
- uses: MadaBurns/blackveil-dns-action@v1
  with:
    domain: example.com
    minimum-grade: B
    profile: auto          # or: mail_enabled, enterprise_mail, non_mail, web_only, minimal
    api-key: ${{ secrets.BV_API_KEY }}  # optional — bypasses rate limits
```

The action outputs `score`, `grade`, `maturity`, `scoring-profile`, and `passed` for downstream steps.

## Monitoring

Get weekly DNS security reports in Slack or Discord. See [`examples/slack-discord-webhook/`](examples/slack-discord-webhook/) for a ready-to-deploy Cloudflare Cron Trigger recipe.

---

## Pricing

Full API and MCP access at every tier — no enterprise gatekeeping.

| | **Free** | **Pro** | **Enterprise** |
|---|---|---|---|
| **Price** | $0 | $39/mo ($29/mo annual) | [Contact us](https://blackveilsecurity.com) |
| **Scans/day** | 75 | 500 | 10,000+ |
| **Checks/day** (per tool) | 200 | 5,000 | Unlimited |
| **Lookalike / Shadow scans** | 20/day | 200/day | Unlimited |
| **Rate limit** | 50 req/min | None | None |
| **API access** | Yes | Yes | Yes |
| **MCP access** | Yes | Yes | Yes |
| **GitHub Action** | Yes | Yes | Yes |
| **Batch API** | — | — | Up to 500 domains/call |
| **SLA** | Best effort | 99.5% | 99.9% + custom |
| **Support** | Community | Email | Dedicated |

The free tier is generous by design — use it for personal projects, evaluations, and AI agent integrations with no strings attached. Upgrade when you need higher throughput.

Get an API key at [blackveilsecurity.com](https://blackveilsecurity.com).

---

## npm package

Install from npm when you want to call the scanner from your own Node.js app, script, or service. If you are connecting from VS Code, Claude, Cursor, or another MCP client, use the MCP endpoint configuration above instead.

```bash
npm install blackveil-dns
```

Requirements: Node 18+ or another runtime with global `fetch`, `URL`, `AbortController`, and Web Platform APIs.

<details>
<summary><b>Usage example</b></summary>

```ts
import { scanDomain, explainFinding, formatScanReport, validateDomain } from 'blackveil-dns';

const candidate = 'example.com';
const validation = validateDomain(candidate);

if (!validation.valid) {
  throw new Error(validation.error);
}

const result = await scanDomain(candidate);
console.log(formatScanReport(result));

const guidance = explainFinding('SPF', 'fail', 'No SPF record found');
console.log(guidance.recommendation);
```

The npm package exports the reusable scanner API only. It does not start the MCP server or Cloudflare Worker entrypoint.
</details>

---

<details>
<summary><b>Coverage — 57+ checks across 20 categories</b></summary>

The full [BLACKVEIL](https://blackveilsecurity.com) platform extends each with deeper analytics.

| Category | Checks | MCP (Free) | Platform |
|---|---:|---|---|
| SPF | 8 | Policy and syntax validation | Include-chain and sender-path analytics |
| DMARC | 10 | Policy, pct, reporting, alignment | Subdomain inheritance, reporting quality |
| DKIM | 9 | Selector discovery, RSA key strength | Rotation heuristics, key-age drift |
| DNSSEC | 6 | AD validation, signed-zone baseline | Chain-of-trust, rollover posture |
| SSL/TLS | 8 | Certificate availability, validity | Protocol/cipher depth, renewal risk |
| MTA-STS | 5 | TXT policy, policy retrieval | Policy hardening, reporting depth |
| NS | 4 | Delegation, diversity, resiliency | Infrastructure concentration |
| CAA | 4 | Presence, issuer allowlist | Issuance surface modeling |
| MX | 4 | Presence, routing, provider inference | Mail routing posture |
| Subdomain Takeover | 2 | Dangling CNAME detection | Expanded asset discovery |
| BIMI | 1 | Record presence, logo URL, VMC | Brand indicator compliance |
| TLS-RPT | 1 | Record presence, reporting URI | Reporting depth |
| Lookalikes | 1 | Typosquat detection, DNS + MX probing | Expanded permutation strategies |
| HTTP Security | 7 | CSP, X-Frame-Options, COOP, CORP, Permissions-Policy | Header depth analytics |
| DANE | 3 | TLSA record validation for MX and HTTPS | Certificate pinning posture |
| Shadow Domains | 1 | Alternate-TLD email spoofing risk | Extended TLD coverage |
| TXT Hygiene | 1 | Stale verifications, SaaS exposure | Shadow IT discovery |
| MX Reputation | 1 | DNSBL + PTR/FCrDNS validation | Deliverability analytics |
| SRV | 1 | Service footprint discovery | Protocol exposure analytics |
| Zone Hygiene | 1 | SOA consistency, sensitive subdomains | Infrastructure exposure |

</details>

<details>
<summary><b>Scan output — anthropic.com (real, unedited)</b></summary>

```
  BLACKVEIL DNS                                          anthropic.com
 ─────────────────────────────────────────────────────────────────────

  CATEGORY          SCORE    STATUS    KEY FINDINGS
 ─────────────────────────────────────────────────────────────────────
  SPF                80/100    PASS    Soft fail (~all), Google shared
  DMARC              90/100    PASS    p=reject, relaxed alignment
  DKIM               85/100    PASS    google selector, 2048-bit RSA
  DNSSEC             35/100    FAIL    Not enabled — no DNSKEY/DS
  SSL/TLS           100/100    PASS    HTTPS + HSTS configured
  MTA-STS            85/100    PASS    No MTA-STS/TLS-RPT records
  NS                 95/100    PASS    Cloudflare anycast
  CAA                85/100    PASS    No CAA records published
  MX                100/100    PASS    5 MX records, Google Workspace
  BIMI               95/100    PASS    Eligible but not published
  TLS-RPT            95/100    PASS    No TLS-RPT record
 ─────────────────────────────────────────────────────────────────────

  ████████████████████████████████████████░░░░░  85 / 100    Grade: A
```

### Findings

```
  SEVERITY    FINDING                                                CATEGORY
 ─────────────────────────────────────────────────────────────────────────────
  HIGH        DNSSEC not validated — AD flag not set                  DNSSEC
  HIGH        No DNSKEY records found                                 DNSSEC
  MEDIUM      No DS records — chain of trust broken                   DNSSEC
  MEDIUM      No MTA-STS or TLS-RPT records                          MTA-STS
  MEDIUM      No CAA records — any CA can issue certs                 CAA
  MEDIUM      DKIM RSA key below recommended (2048 < 4096)            DKIM
  LOW         SPF soft fail (~all) — consider -all                    SPF
  LOW         Relaxed DKIM alignment (adkim=r)                        DMARC
  LOW         Relaxed SPF alignment (aspf=r)                          DMARC
  LOW         Low nameserver diversity (all Cloudflare)               NS
  LOW         No BIMI record — eligible with p=reject                 BIMI
  LOW         No TLS-RPT record                                       TLSRPT
  INFO        SPF delegates to shared platform: Google Workspace      SPF
  INFO        DMARC properly configured (p=reject, sp=reject)         DMARC
  INFO        MX records found (5 records)                            MX
  INFO        Inbound provider: Google Workspace                      MX
  INFO        HTTPS + HSTS properly configured                        SSL
```

**What this means.** Anthropic has strong email authentication — DMARC is set to `reject`, SPF and DKIM are present, Google Workspace handles mail. Because DMARC enforcement is strong, the shared-platform SPF delegation to Google stays informational rather than being flagged as a risk. The main gap is DNSSEC (DNS responses aren't cryptographically signed) and hardening opportunities around CAA, MTA-STS, and BIMI.

Run `explain_finding` on any result for plain-English remediation.

</details>

<details>
<summary><b>Protocol</b></summary>

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/mcp` | JSON-RPC 2.0 tool/protocol requests (single or batch) |
| `GET` | `/mcp` | SSE stream for server notifications (requires session) |
| `DELETE` | `/mcp` | Session termination |
| `GET` | `/mcp/sse` | Legacy SSE bootstrap stream |
| `POST` | `/mcp/messages` | Legacy message delivery (requires `?sessionId=`) |
| `GET` | `/health` | Health probe |
| `POST` | `/internal/tools/call` | Service binding: single tool call (no auth/rate limits) |
| `POST` | `/internal/tools/batch` | Service binding: bulk scan up to 500 domains |

Supported methods: `initialize`, `ping`, `tools/list`, `tools/call`, `resources/list`, `resources/read`, `prompts/list`, `prompts/get`.

7 pre-built prompts guide common workflows: `full-security-audit`, `email-auth-check`, `policy-compliance-check`, `remediation-workflow`, `email-hardening-guide`, `provider-benchmark`, `attack-surface-assessment`.

</details>

<details>
<summary><b>Architecture</b></summary>

```
  MCP Client
      │
      │  POST /mcp (JSON-RPC 2.0)
      │
  ┌───▼──────────────────────┐
  │  Cloudflare Worker       │
  │                          │
  │  Hono ─► Origin check    │
  │       ─► Auth            │
  │       ─► Rate limiting   │
  │       ─► Session mgmt    │
  └───┬──────────────────────┘
      │
  ┌───▼──────────────────────┐
  │  Tool Handlers           │
  │  16 checks in parallel   │
  └───┬──────────────────────┘
      │
  ┌───▼──────────────────────┐
  │  Cloudflare DoH          │
  │  DNS-over-HTTPS          │
  └──────────────────────────┘
```

- Input sanitation and domain validation
- Optional bearer-token authentication
- Per-IP rate limiting (KV + in-memory fallback)
- `check_lookalikes` capped at 20/day per IP with 60-min caching
- `scan_domain` capped at 75/day per IP (results cached 5 min)
- Scan result caching (KV + in-memory fallback)
- Adaptive scoring via Durable Object telemetry (graceful fallback to static weights)
- Intelligence layer: score histograms, provider cohort benchmarks, hourly trend snapshots (ProfileAccumulator DO)
- Category interaction scoring: correlated weaknesses receive additional penalties
- Context-optimized schemas: tool descriptions, prompts, and resources tuned for minimal LLM token consumption
- Structured JSON logging

Implementation details in `CLAUDE.md`.

</details>

<details>
<summary><b>Security</b></summary>

Full details in `CLAUDE.md` (security and observability sections).

- Domain inputs validated and sanitized before execution
- IP literals rejected (standard and alternate numeric forms)
- SSRF protections block unsafe/private targets
- Error responses sanitized — only known validation errors surface
- DNS via Cloudflare DoH with optional secondary confirmation
- Constant-time auth comparison (XOR accumulation on SHA-256 digests)
- DNS data sanitized at ingestion — HTML/markdown injection stripped before findings are created
- Outbound response body caps (64 KB for tool checks, 1 MB for provider signatures)
- Tool parameter validation with allowlists and per-element type/length checks
- Rate limits: `50/min` and `300/hr` per IP for `tools/call` (free tier; Pro and Enterprise bypass)
- Control-plane traffic: `60/min` and `600/hr` per IP
- Global daily cap: `500,000` unauthenticated tool calls/day (cost ceiling)
- Authenticated requests: per-tier daily quotas keyed by API key hash (see [Pricing](#pricing))
- Session creation: `60/min` per IP (enforced on both modern and legacy transports)
- Session TTL: 2 hours idle, dual-write (KV + in-memory) for cross-isolate resilience
- SSE notification stream exempt from rate limiting (prevents `mcp-remote` reconnection storms)
- Client IPs redacted in structured logs

**Natural-language convenience:**
`tools/call` supports `scan` as an alias for `scan_domain`. In chat clients, say `scan example.com`. Raw JSON-RPC expects `params.name` to be `scan` or `scan_domain`.

</details>

<details>
<summary><b>Provider detection</b></summary>

`check_mx` and `scan_domain` infer managed email providers.

- **Inbound** — MX host matching
- **Outbound** — SPF include/redirect signals + DKIM selector hints
- Metadata: `detectionType`, `providers`, `providerConfidence` (0.0-1.0), `signatureSource`, `signatureVersion`
- Fallback order: runtime source -> stale cache -> built-in signatures

Optional configuration:

| Variable | Purpose |
|---|---|
| `PROVIDER_SIGNATURES_URL` | Runtime provider-signature JSON source |
| `PROVIDER_SIGNATURES_SHA256` | Required pinned digest |
| `PROVIDER_SIGNATURES_ALLOWED_HOSTS` | Hostname allowlist |

</details>

---

## Development

```bash
git clone https://github.com/MadaBurns/bv-mcp.git
cd bv-mcp
npm install
npm run dev       # localhost:8787/mcp
```

```bash
npm test          # 1456 tests
npm run typecheck
```

<details>
<summary><b>Private deployment</b></summary>

```bash
cp wrangler.private.example.jsonc .dev/wrangler.deploy.jsonc
# replace KV namespace IDs and analytics dataset in .dev/wrangler.deploy.jsonc
npm run deploy:private
```

The checked-in [wrangler.jsonc](wrangler.jsonc) stays generic for open source use. Real KV IDs, session storage, and Analytics Engine dataset names should live only in the ignored `.dev/wrangler.deploy.jsonc` file.

</details>

Manual request examples and failure modes in `docs/troubleshooting.md`.

---

## Docs

| Document | Path |
|---|---|
| Client setup | `docs/client-setup.md` |
| Scoring | `docs/scoring.md` |
| Troubleshooting | `docs/troubleshooting.md` |
| Style guide | `docs/style-guide.md` |

---

## Why

Most DNS and email security tools are paywalled dashboards or CLI scripts that need local setup. Neither works inside an AI assistant where you want to check a domain mid-conversation.

One endpoint URL. No install. No API key. Point any MCP client at `https://dns-mcp.blackveilsecurity.com/mcp` and know where you stand.

---

<div align="center">

Built and maintained by [**BLACKVEIL**](https://blackveilsecurity.com) — NZ-owned cybersecurity consultancy.

Featured in [SecurityBrief](https://securitybrief.co.nz/story/exclusive-how-cybersecurity-startup-blackveil-is-targetting-ai-driven-threats) · [NZ Herald](https://www.nzherald.co.nz/video/herald-now/ryan-bridge-today/cybersecurity-medimap-hack/OMLGW3OMXOVSSJ3RLFXPMAVGKE/) · [Modern Cyber](https://www.youtube.com/watch?v=W4aJHpfB5rY)

Want continuous monitoring? [BLACKVEIL](https://blackveilsecurity.com) provides real-time alerting and Buck AI to help you fix what this scanner finds.

BUSL-1.1 License (converts to MIT on 2030-03-17)

</div>
