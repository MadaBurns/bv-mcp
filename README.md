<div align="center">

# BLACK**V**EIL DNS

**Know where you stand.**

Open-source DNS & email security scanner for Claude, Cursor, VS Code, and MCP clients across Streamable HTTP, stdio, and legacy HTTP+SSE.

[![GitHub stars](https://img.shields.io/github/stars/MadaBurns/bv-mcp?style=flat&logo=github)](https://github.com/MadaBurns/bv-mcp/stargazers)
[![npm version](https://img.shields.io/npm/v/blackveil-dns)](https://www.npmjs.com/package/blackveil-dns)
[![npm downloads](https://img.shields.io/npm/dm/blackveil-dns)](https://www.npmjs.com/package/blackveil-dns)
[![Tests](https://img.shields.io/badge/Tests-2283-brightgreen)](https://github.com/MadaBurns/bv-mcp/actions)
[![Coverage](https://img.shields.io/badge/Coverage-~90%25-brightgreen)](https://github.com/MadaBurns/bv-mcp/actions)
[![BUSL-1.1 License](https://img.shields.io/badge/License-BUSL--1.1-blue.svg)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-2025--03--26-blue)](https://modelcontextprotocol.io/)
[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare%20Workers-F38020?logo=cloudflare&logoColor=white)](https://workers.cloudflare.com/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.5-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)

![DNS Security](https://dns-mcp.blackveilsecurity.com/badge/blackveilsecurity.com)

</div>

---

## Try it in 30 seconds

**Claude Desktop** (one-click install):

Download the [Blackveil DNS extension](https://github.com/MadaBurns/bv-claude-dns/releases/latest/download/bv-claude-dns.mcpb) and open it — all 44 tools available instantly. [Verify your download](https://blackveilsecurity.com/extensions/claude-dns#install).

**Claude Code** (one command):

```bash
claude mcp add --transport http blackveil-dns https://dns-mcp.blackveilsecurity.com/mcp
```

Then ask: `scan anthropic.com`

**Smithery** (one command):

```bash
smithery mcp add MadaBurns/bv-mcp
```

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

---

## What you get

- **80+ checks across 20 categories** — SPF, DMARC, DKIM, DNSSEC, SSL/TLS, MTA-STS, NS, CAA, MX, BIMI, TLS-RPT, subdomain takeover, lookalike domains, HTTP security headers, DANE, shadow domains, TXT hygiene, MX reputation, SRV, zone hygiene
- **Maturity staging** — Stage 0-4 classification (Unprotected to Hardened) with score-based capping to prevent inflated labels
- **Trust surface analysis** — detects shared SaaS platforms (Google, M365, SendGrid) and cross-references DMARC enforcement to determine real exposure
- **Guided remediation** — `generate_fix_plan` produces provider-aware prioritized actions; record generators output ready-to-publish records; `validate_fix` confirms whether a fix was applied successfully
- **Supply chain mapping** — `map_supply_chain` correlates DNS signals to build a full third-party dependency graph with trust levels and risk signals
- **Attack path simulation** — `simulate_attack_paths` enumerates specific paths (spoofing, takeover, hijack) with severity, steps, and mitigations
- **Compliance mapping** — `map_compliance` maps scan findings to NIST 800-177, PCI DSS 4.0, SOC 2, and CIS Controls
- **Self-tuning scoring** — adaptive weights adjust category importance based on patterns seen across scans via Durable Object telemetry
- **Passive and read-only** — all checks use public Cloudflare DNS-over-HTTPS; no authorization required from the target

---

## Tools

```
  44 MCP tools · 7 prompts · 6 resources

  Email Auth           Infrastructure        Brand & Threats       Meta
 ────────────         ────────────────       ─────────────────    ──────────────────────
  check_spf            check_dnssec           check_bimi           scan_domain
  check_dmarc          check_ns               check_tlsrpt         batch_scan
  check_dkim           check_caa              check_lookalikes     compare_domains
  check_mta_sts        check_ssl              check_shadow_domains compare_baseline
  check_mx             check_http_security                         explain_finding
  check_mx_reputation  check_dane             Intelligence
  check_subdomailing   check_dane_https      ──────────────       Remediation
                       check_svcb_https       get_benchmark       ──────────────
  DNS Hygiene          check_srv              get_provider_        generate_fix_plan
 ────────────          check_zone_hygiene       insights           generate_spf_record
  check_txt_hygiene    check_resolver_        assess_spoofability  generate_dmarc_record
                         consistency          map_supply_chain     generate_dkim_config
                                              resolve_spf_chain    generate_mta_sts_policy
                                              discover_subdomains  generate_rollout_plan
                                              map_compliance       validate_fix
                                              simulate_attack_paths
                                              analyze_drift

  + check_subdomain_takeover (internal — runs inside scan_domain)
```

---

## Quality & Reliability

The server is continuously validated using a **comprehensive chaos test suite** (ported from `claude-code-py`) that covers all 9 detected MCP client types:

- **Interactive clients**: `claude_code`, `cursor`, `vscode`, `claude_desktop`, `windsurf` (auto-format: `compact`)
- **Non-interactive clients**: `mcp_remote`, `blackveil_dns_action`, `bv_claude_dns_proxy`, `unknown` (auto-format: `full`)

The test suite ensures session stability, authentication precedence, and transport-specific edge cases across Streamable HTTP and Legacy SSE.

Run the chaos tests locally: `python3 scripts/chaos/chaos-test-clients.py`

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
  │  16 checks in parallel   │
  └───┬──────────────────────┘
      │
  ┌───▼──────────────────────┐
  │  Generic Scoring Engine  │
  │  Three-tier model        │
  └───┬──────────────────────┘
      │
  ┌───▼──────────────────────┐
  │  Cloudflare DoH          │
  │  DNS-over-HTTPS          │
  └──────────────────────────┘
```

- **Generic Scoring Engine**: Architectural core ported from `claude-code-py` for cross-language consistency
- **WASM Policy Engine**: High-performance permission and token checks via `bv-wasm-core`
- **Reliable Sessions**: Hardened tombstone logic prevents race-condition revival of terminated sessions
- **Adaptive Scoring**: Durable Object telemetry adjusts weights based on real-world distributions
- **Client Awareness**: Automatic response formatting (`compact` vs `full`) based on client `User-Agent`

---

## Client setup

The free tier requires no authentication. If you have an API key, you can use either:
- **Header**: `Authorization: Bearer <KEY>`
- **Query Param**: `?api_key=<KEY>`

For full hosted setup examples, stdio usage, and legacy fallback endpoints, see [**docs/client-setup.md**](docs/client-setup.md).

---

## Pricing

| | **Free** | **Pro** | **Enterprise** |
|---|---|---|---|
| **Price** | $0 | $39/mo | [Contact us](https://blackveilsecurity.com) |
| **Scans/day** | 75 | 500 | 10,000+ |
| **Checks/day** | 200 | 5,000 | Unlimited |
| **Rate limit** | 50 req/min | None | None |
| **API access** | Yes | Yes | Yes |
| **MCP access** | Yes | Yes | Yes |

---

<div align="center">

Built and maintained by [**BLACKVEIL**](https://blackveilsecurity.com) — NZ-owned cybersecurity consultancy.

BUSL-1.1 License (converts to MIT on 2030-03-17)

</div>
