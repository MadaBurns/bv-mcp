
<div align="center">

```
██████╗ ██╗      █████╗  ██████╗██╗  ██╗██╗   ██╗███████╗██╗██╗
██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝██║   ██║██╔════╝██║██║
██████╔╝██║     ███████║██║     █████╔╝ ██║   ██║█████╗  ██║██║
██╔══██╗██║     ██╔══██║██║     ██╔═██╗ ╚██╗ ██╔╝██╔══╝  ██║██║
██████╔╝███████╗██║  ██║╚██████╗██║  ██╗ ╚████╔╝ ███████╗██║███████╗
╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝╚══════╝
██████╗ ███╗   ██╗███████╗
██╔══██╗████╗  ██║██╔════╝
██║  ██║██╔██╗ ██║███████╗
██║  ██║██║╚██╗██║╚════██║
██████╔╝██║ ╚████║███████║
╚═════╝ ╚═╝  ╚═══╝╚══════╝
```

### DNS & Email Security Scanner for AI

**One URL. No install. No API key. Just point your MCP client and scan.**

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Cloudflare Workers](https://img.shields.io/badge/Runs%20on-Cloudflare%20Workers-F38020?logo=cloudflare)](https://workers.cloudflare.com/)
[![MCP 2025-03-26](https://img.shields.io/badge/MCP-2025--03--26-blue)](https://modelcontextprotocol.io/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.5-3178C6?logo=typescript)](https://www.typescriptlang.org/)
[![Tests](https://img.shields.io/badge/Tests-630%2B-brightgreen)](https://github.com/MadaBurns/bv-mcp/actions)
[![Coverage](https://img.shields.io/badge/Coverage-~95%25-brightgreen)](https://github.com/MadaBurns/bv-mcp/actions)

</div>

---

## What can it do?

Point it at any domain and get back a full security audit — scored 0–100 with a letter grade.

```
  ┌─────────────────────────────────────────────────────────────┐
  │                                                             │
  │   scan_domain("anthropic.com")                              │
  │                                                             │
  │   ██████████████████████████████████████████░░░░░  85/100   │
  │   Grade: A  ·  Maturity: Intermediate                       │
  │                                                             │
  │   SPF ·········· 80   │  MTA-STS ····· 85                   │
  │   DMARC ········ 90   │  NS ·········· 95                   │
  │   DKIM ········· 85   │  CAA ········· 85                   │
  │   DNSSEC ······· 35   │  BIMI ········ 95                   │
  │   SSL ········· 100   │  TLS-RPT ····· 95                   │
  │   MX ·········· 100   │                                     │
  │                                                             │
  │   ▲ 2 high · 3 medium · 5 low · 2 info                     │
  │                                                             │
  └─────────────────────────────────────────────────────────────┘
```

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

---

## Table of Contents

- [Quick Start](#-quick-start)
- [Live Scan: anthropic.com](#-live-scan-anthropiccom)
- [Tool Surface](#-tool-surface)
- [Coverage](#-coverage)
- [Protocol Endpoints](#-protocol-endpoints)
- [Architecture](#-architecture)
- [Security Model](#-security-model)
- [Provider Detection](#-provider-detection)
- [Documentation](#-documentation)
- [Development](#-development)
- [Testing](#-testing)
- [Why this exists](#-why-this-exists)
- [License](#-license)

---

## ⚡ Quick Start

```
Endpoint:  https://dns-mcp.blackveilsecurity.com/mcp
Transport: Streamable HTTP (JSON-RPC 2.0)
Auth:      None required
```

<details>
<summary><b>VS Code / Copilot</b> — <code>.vscode/mcp.json</code></summary>

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
<summary><b>Claude Code</b> — <code>.mcp.json</code> or CLI</summary>

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
</details>

<details>
<summary><b>Claude Desktop</b> — <code>claude_desktop_config.json</code></summary>

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
<summary><b>Cursor</b> — <code>.cursor/mcp.json</code></summary>

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

For full client setup and auth details, see `docs/client-setup.md`.

---

## 🔍 Live Scan: anthropic.com

> Real `scan_domain` output from Blackveil DNS. No cherry-picking — this is what the scanner returns.

```
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                        ║
║   BLACKVEIL DNS — Security Report                                      ║
║   Domain: anthropic.com                                                ║
║                                                                        ║
╠══════════════════════════════════════════════════════════════════════════╣
║                                                                        ║
║   CATEGORY          SCORE   STATUS   KEY FINDINGS                      ║
║   ─────────────────────────────────────────────────────────────────     ║
║   SPF                80/100   ✅     Soft fail (~all), Google shared    ║
║   DMARC              90/100   ✅     p=reject ✓, relaxed alignment     ║
║   DKIM               85/100   ✅     google selector, 2048-bit RSA     ║
║   DNSSEC             35/100   ❌     Not enabled — no DNSKEY/DS        ║
║   SSL/TLS           100/100   ✅     HTTPS + HSTS properly configured  ║
║   MTA-STS            85/100   ✅     No MTA-STS/TLS-RPT records        ║
║   NS                 95/100   ✅     Cloudflare anycast, low diversity  ║
║   CAA                85/100   ✅     No CAA records published          ║
║   MX                100/100   ✅     5 MX records, Google Workspace    ║
║   BIMI               95/100   ✅     Eligible but not published        ║
║   TLS-RPT            95/100   ✅     No TLS-RPT record                 ║
║                                                                        ║
╠══════════════════════════════════════════════════════════════════════════╣
║                                                                        ║
║   ██████████████████████████████████████████░░░░░░  85/100  Grade: A   ║
║                                                                        ║
╚══════════════════════════════════════════════════════════════════════════╝
```

### Findings breakdown

```
 SEVERITY   FINDING                                              CATEGORY
 ────────   ───────────────────────────────────────────────────   ────────
 🔴 HIGH    DNSSEC not validated — AD flag not set                DNSSEC
 🔴 HIGH    No DNSKEY records found                               DNSSEC
 🔶 MEDIUM  No DS records — chain of trust broken                 DNSSEC
 🔶 MEDIUM  SPF delegates to shared platform: Google Workspace    SPF
 🔶 MEDIUM  No MTA-STS or TLS-RPT records                        MTA-STS
 🔶 MEDIUM  No CAA records — any CA can issue certs               CAA
 🔶 MEDIUM  DKIM RSA key below recommended (2048 < 4096)          DKIM
 ⚠️  LOW    SPF soft fail (~all) — consider -all                  SPF
 ⚠️  LOW    Relaxed DKIM alignment (adkim=r)                      DMARC
 ⚠️  LOW    Relaxed SPF alignment (aspf=r)                        DMARC
 ⚠️  LOW    Low nameserver diversity (all Cloudflare)             NS
 ⚠️  LOW    No BIMI record — eligible with p=reject               BIMI
 ⚠️  LOW    No TLS-RPT record                                     TLSRPT
 ℹ️  INFO   DMARC properly configured (p=reject, sp=reject)       DMARC
 ℹ️  INFO   MX records found (5 records)                          MX
 ℹ️  INFO   Inbound provider: Google Workspace                    MX
 ℹ️  INFO   HTTPS + HSTS properly configured                      SSL
```

### What does this mean?

Anthropic has **strong email authentication** — DMARC is set to `reject`, SPF and DKIM are present, and Google Workspace handles mail. The main gap is **DNSSEC** (DNS responses aren't cryptographically signed) and some hardening opportunities like CAA records, MTA-STS, and BIMI. A solid **A** grade.

> Use `explain_finding` on any result to get plain-English remediation guidance with everyday analogies.

---

## 🛠 Tool Surface

```
┌──────────────────────────────────────────────────────────────┐
│                                                              │
│   14 directly callable MCP tools                             │
│                                                              │
│   ┌─ Email Auth ──────────┐  ┌─ Infrastructure ──────────┐  │
│   │  check_spf            │  │  check_dnssec             │  │
│   │  check_dmarc          │  │  check_ns                 │  │
│   │  check_dkim           │  │  check_caa                │  │
│   │  check_mta_sts        │  │  check_ssl                │  │
│   └───────────────────────┘  └───────────────────────────┘  │
│                                                              │
│   ┌─ Brand & Threats ─────┐  ┌─ Meta ────────────────────┐  │
│   │  check_bimi           │  │  scan_domain              │  │
│   │  check_tlsrpt         │  │  explain_finding          │  │
│   │  check_lookalikes     │  │  check_mx                 │  │
│   └───────────────────────┘  └───────────────────────────┘  │
│                                                              │
│   + check_subdomain_takeover (internal, runs in scan_domain) │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

`explain_finding` accepts a `checkType`, `status`, and optional `details` string, and returns a structured explanation with:
- **What this means** — plain-English description using everyday analogies (e.g., SPF as a "guest list," DKIM as a "wax seal," DNSSEC as a "notarized signature")
- **Potential impact** — what could go wrong, in terms anyone can understand
- **Adverse consequences** — real-world business effects
- **Recommendation** — specific technical steps to fix it
- **References** — links to relevant RFCs and documentation

The `details` parameter enables precise explanations: passing the finding's detail text routes to a specific explanation (e.g., distinguishing "no MTA-STS records" from "MTA-STS in testing mode") instead of a generic fallback.

Findings include a confidence label in metadata and rendered reports:
- `deterministic`: direct protocol/record validation with clear evidence.
- `heuristic`: signal-based inference (for example selector probing or takeover indicators) and may require manual validation.
- `verified`: explicit high-confidence validation signal.

Subdomain takeover findings include a verification label in finding metadata and reports:
- `potential`: DNS/signal indicates possible takeover; requires authorized proof-of-control validation.
- `verified`: service deprovisioning fingerprint detected; high-confidence signal pending authorized proof-of-control.
- `not_exploitable`: no takeover signal detected for the checked subdomains.

Internal check executed within `scan_domain`:

- `subdomain_takeover`

Scope and limitations are documented in `docs/coverage.md`.

---

## 📊 Coverage

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

---

## 🌐 Protocol Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/mcp` | JSON-RPC 2.0 tool/protocol requests |
| `GET` | `/mcp` | SSE stream for server notifications |
| `DELETE` | `/mcp` | Session termination |
| `GET` | `/health` | Health probe |

Supported JSON-RPC protocol methods include `initialize`, `ping`, `tools/list`, `tools/call`, `resources/list`, and `resources/read`.

This server does not currently implement prompt APIs such as `prompts/list` or `prompts/get`; those calls return `-32601 Method not found`.

---

## 🏗 Architecture

```
                    ┌─────────────────┐
                    │   MCP Client    │
                    │  (Claude, etc.) │
                    └────────┬────────┘
                             │
                     POST /mcp (JSON-RPC)
                             │
                    ┌────────▼────────┐
                    │  Cloudflare     │
                    │  Worker / Hono  │
                    ├─────────────────┤
                    │ Origin check    │
                    │ Auth middleware  │
                    │ Rate limiting   │
                    │ Session mgmt    │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │  Tool Handlers  │
                    │  (14 checks)    │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │  Cloudflare DoH │
                    │  DNS-over-HTTPS │
                    └─────────────────┘
```

Core subsystems:

- Input sanitation and domain validation
- Optional bearer-token authentication
- Per-IP rate limiting with KV + in-memory fallback
- `check_lookalikes` is additionally capped at `5/day` per IP (unauthenticated) with 60-minute result caching, due to high outbound query volume
- Scan/result caching with KV + in-memory fallback
- Structured JSON logging

For implementation details and conventions, see `CLAUDE.md`.

---

## 🔒 Security Model

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

---

## 🔎 Provider Detection

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

---

## 📖 Documentation

- Client setup: `docs/client-setup.md`
- Security and observability: `docs/security-and-observability.md`
- Scoring details: `docs/scoring.md`
- Coverage and limitations: `docs/coverage.md`
- Troubleshooting: `docs/troubleshooting.md`
- Documentation style guide: `docs/style-guide.md`

---

## 💻 Development

```bash
git clone https://github.com/MadaBurns/bv-mcp.git
cd bv-mcp
npm install
npm run dev       # localhost:8787/mcp
```

---

## 🧪 Testing

```bash
npm test          # 630+ tests, ~95% coverage
npm run typecheck
```

Manual request examples and common failure modes are in `docs/troubleshooting.md`.

---

## 💡 Why this exists

Most DNS and email security tools are either paywalled SaaS dashboards or CLI scripts that require local installation and configuration. Neither works well inside an AI coding assistant where you want to check a domain's security posture mid-conversation.

Blackveil DNS is a remote MCP server — one endpoint URL, no install, no API key required. Point any MCP client at `https://dns-mcp.blackveilsecurity.com/mcp` and start scanning. Every check uses only public Cloudflare DoH APIs, so there's no active reconnaissance and nothing that requires authorization from the target domain.

Built and maintained by [BLACKVEIL Security](https://blackveilsecurity.com), a New Zealand-based cybersecurity consultancy.

Featured in [SecurityBrief](https://securitybrief.co.nz/story/exclusive-how-cybersecurity-startup-blackveil-is-targetting-ai-driven-threats), [NZ Herald](https://www.nzherald.co.nz/video/herald-now/ryan-bridge-today/cybersecurity-medimap-hack/OMLGW3OMXOVSSJ3RLFXPMAVGKE/), and the [Modern Cyber](https://www.youtube.com/watch?v=W4aJHpfB5rY) podcast.

---

<div align="center">

```
    ╔══════════════════════════════════════════════════╗
    ║                                                  ║
    ║   🛡️  Want continuous monitoring?                 ║
    ║                                                  ║
    ║   This tool scans for DNS & email security       ║
    ║   issues. BLACKVEIL provides near real-time      ║
    ║   monitoring, alerting, and Buck AI to help      ║
    ║   you fix them.                                  ║
    ║                                                  ║
    ║   https://blackveilsecurity.com                  ║
    ║                                                  ║
    ╚══════════════════════════════════════════════════╝
```

</div>

---

## 📄 License

MIT. See `LICENSE`.
