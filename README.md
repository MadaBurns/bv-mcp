<div align="center">

# BLACK**V**EIL DNS

**Know where you stand.**

Open-source DNS & email security scanner for Claude, Cursor, VS Code, and any MCP client.

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare%20Workers-F38020?logo=cloudflare&logoColor=white)](https://workers.cloudflare.com/)
[![MCP](https://img.shields.io/badge/MCP-2025--03--26-blue)](https://modelcontextprotocol.io/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.5-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Tests](https://img.shields.io/badge/Tests-630%2B-brightgreen)](https://github.com/MadaBurns/bv-mcp/actions)
[![Coverage](https://img.shields.io/badge/Coverage-~95%25-brightgreen)](https://github.com/MadaBurns/bv-mcp/actions)

</div>

---

Point any MCP client at a single URL and scan any domain. No install. No API key. 60 seconds to clarity.

Every check uses public Cloudflare DNS-over-HTTPS — passive, read-only, no authorization required from the target.

```
  scan_domain("anthropic.com")

  ████████████████████████████████████████░░░░░  85 / 100
  Grade: A  ·  Maturity: Intermediate

  SPF ·········· 80     MTA-STS ····· 85
  DMARC ········ 90     NS ·········· 95
  DKIM ········· 85     CAA ········· 85
  DNSSEC ······· 35     BIMI ········ 95
  SSL ········· 100     TLS-RPT ····· 95
  MX ·········· 100

  2 high · 5 medium · 5 low · 4 info
```

**Email authentication** — SPF, DMARC, DKIM policy, syntax, key strength, alignment | **Trust surface** — detects shared SaaS platforms (Google, M365, SendGrid) that widen spoofing exposure | **Brand protection** — BIMI validation, lookalike/typosquat domain detection with mail probing | **DNS infrastructure** — DNSSEC, NS redundancy, CAA restrictions, wildcard detection | **Transport security** — SSL/TLS, HSTS, MTA-STS enforcement, TLS-RPT | **Threat detection** — subdomain takeover via dangling CNAME across 30+ services | **Provider intelligence** — inbound/outbound email provider inference from MX, SPF, DKIM | **Maturity staging** — Stage 0-4 classification (Unprotected to Hardened) with next steps | **Plain-English remediation** — `explain_finding` turns findings into guidance anyone can understand

---

## Contents

- [Quick Start](#quick-start)
- [Scan: anthropic.com](#scan-anthropiccom)
- [Tools](#tools)
- [Coverage](#coverage)
- [Protocol](#protocol)
- [Architecture](#architecture)
- [Security](#security)
- [Provider Detection](#provider-detection)
- [Docs](#docs)
- [Development](#development)
- [Testing](#testing)
- [Why](#why)
- [License](#license)

---

## Quick Start

```
Endpoint   https://dns-mcp.blackveilsecurity.com/mcp
Transport  Streamable HTTP · JSON-RPC 2.0
Auth       None required
```

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
</details>

<details>
<summary><b>Claude Desktop</b></summary>

`claude_desktop_config.json`

```json
{
  "mcpServers": {
    "blackveil-dns": {
      "url": "https://dns-mcp.blackveilsecurity.com/mcp"
    }
  }
}
```
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
</details>

Full setup and auth details in `docs/client-setup.md`.

---

## Scan: anthropic.com

Real output. No cherry-picking — this is what the scanner returns.

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
  MEDIUM      SPF delegates to shared platform: Google Workspace      SPF
  MEDIUM      No MTA-STS or TLS-RPT records                          MTA-STS
  MEDIUM      No CAA records — any CA can issue certs                 CAA
  MEDIUM      DKIM RSA key below recommended (2048 < 4096)            DKIM
  LOW         SPF soft fail (~all) — consider -all                    SPF
  LOW         Relaxed DKIM alignment (adkim=r)                        DMARC
  LOW         Relaxed SPF alignment (aspf=r)                          DMARC
  LOW         Low nameserver diversity (all Cloudflare)               NS
  LOW         No BIMI record — eligible with p=reject                 BIMI
  LOW         No TLS-RPT record                                       TLSRPT
  INFO        DMARC properly configured (p=reject, sp=reject)         DMARC
  INFO        MX records found (5 records)                            MX
  INFO        Inbound provider: Google Workspace                      MX
  INFO        HTTPS + HSTS properly configured                        SSL
```

**What this means.** Anthropic has strong email authentication — DMARC is set to `reject`, SPF and DKIM are present, Google Workspace handles mail. The main gap is DNSSEC (DNS responses aren't cryptographically signed) and hardening opportunities around CAA, MTA-STS, and BIMI.

Run `explain_finding` on any result for plain-English remediation.

---

## Tools

```
  14 MCP tools

  Email Auth           Infrastructure        Brand & Threats       Meta
 ────────────         ────────────────       ─────────────────    ──────────────
  check_spf            check_dnssec           check_bimi           scan_domain
  check_dmarc          check_ns               check_tlsrpt         explain_finding
  check_dkim           check_caa              check_lookalikes     check_mx
  check_mta_sts        check_ssl

  + check_subdomain_takeover (internal — runs inside scan_domain)
```

**`explain_finding`** takes a finding and returns:

- **What this means** — plain English with everyday analogies (SPF as a "guest list," DKIM as a "wax seal," DNSSEC as a "notarized signature")
- **Potential impact** — what could go wrong
- **Adverse consequences** — real business effects
- **Recommendation** — specific steps to fix it
- **References** — relevant RFCs and documentation

Pass the finding's `details` text for precise explanations (e.g., distinguishing "no MTA-STS records" from "MTA-STS in testing mode").

**Confidence labels:**
`deterministic` — direct protocol/record validation | `heuristic` — signal-based inference, may need manual validation | `verified` — high-confidence validation signal

**Subdomain takeover verification:**
`potential` — DNS signal, requires proof-of-control | `verified` — deprovisioning fingerprint detected | `not_exploitable` — no takeover signal

Scope and limitations in `docs/coverage.md`.

---

## Coverage

57 checks across 13 categories. The full [BLACKVEIL](https://blackveilsecurity.com) platform extends each with deeper analytics.

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
| BIMI | 2 | Record presence, logo URL, VMC | Brand indicator compliance |
| TLS-RPT | 2 | Record presence, reporting URI | Reporting depth |
| Lookalikes | 3 | Typosquat detection, DNS + MX probing | Expanded permutation strategies |

---

## Protocol

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/mcp` | JSON-RPC 2.0 tool/protocol requests |
| `GET` | `/mcp` | SSE stream for server notifications |
| `DELETE` | `/mcp` | Session termination |
| `GET` | `/health` | Health probe |

Supported methods: `initialize`, `ping`, `tools/list`, `tools/call`, `resources/list`, `resources/read`.

Prompt methods (`prompts/list`, `prompts/get`) return `-32601 Method not found`.

---

## Architecture

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
  │  14 checks in parallel   │
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
- `check_lookalikes` capped at 10/day per IP with 60-min caching
- Scan result caching (KV + in-memory fallback)
- Structured JSON logging

Implementation details in `CLAUDE.md`.

---

## Security

Full details in `docs/security-and-observability.md`.

- Domain inputs validated and sanitized before execution
- IP literals rejected (standard and alternate numeric forms)
- SSRF protections block unsafe/private targets
- Error responses sanitized — only known validation errors surface
- DNS via Cloudflare DoH with optional secondary confirmation
- Rate limits: `30/min` and `200/hr` per IP for `tools/call`
- Control-plane traffic: `60/min` and `600/hr` per IP
- Global daily cap: `10,000` unauthenticated tool calls/day (cost ceiling)
- Session creation: `60/min` per IP

**Natural-language convenience:**
`tools/call` supports `scan` as an alias for `scan_domain`. In chat clients, say `scan example.com`. Raw JSON-RPC expects `params.name` to be `scan` or `scan_domain`.

---

## Provider Detection

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

---

## Docs

| Document | Path |
|---|---|
| Client setup | `docs/client-setup.md` |
| Security & observability | `docs/security-and-observability.md` |
| Scoring | `docs/scoring.md` |
| Coverage & limitations | `docs/coverage.md` |
| Troubleshooting | `docs/troubleshooting.md` |
| Style guide | `docs/style-guide.md` |

---

## Development

```bash
git clone https://github.com/MadaBurns/bv-mcp.git
cd bv-mcp
npm install
npm run dev       # localhost:8787/mcp
```

---

## Testing

```bash
npm test          # 630+ tests, ~95% coverage
npm run typecheck
```

Manual request examples and failure modes in `docs/troubleshooting.md`.

---

## Why

Most DNS and email security tools are paywalled dashboards or CLI scripts that need local setup. Neither works inside an AI assistant where you want to check a domain mid-conversation.

One endpoint URL. No install. No API key. Point any MCP client at `https://dns-mcp.blackveilsecurity.com/mcp` and know where you stand.

Every check uses public Cloudflare DoH — passive, read-only, no authorization required from the target.

---

<div align="center">

Built and maintained by [**BLACKVEIL**](https://blackveilsecurity.com) — NZ-owned cybersecurity consultancy.

Featured in [SecurityBrief](https://securitybrief.co.nz/story/exclusive-how-cybersecurity-startup-blackveil-is-targetting-ai-driven-threats) · [NZ Herald](https://www.nzherald.co.nz/video/herald-now/ryan-bridge-today/cybersecurity-medimap-hack/OMLGW3OMXOVSSJ3RLFXPMAVGKE/) · [Modern Cyber](https://www.youtube.com/watch?v=W4aJHpfB5rY)

Want continuous monitoring? [BLACKVEIL](https://blackveilsecurity.com) provides real-time alerting and Buck AI to help you fix what this scanner finds.

MIT License

</div>
