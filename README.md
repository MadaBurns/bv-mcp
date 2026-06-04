<div align="center">

# BLACK**V**EIL DNS

**Know where you stand.**

Source-available DNS & email security scanner for Claude, Cursor, VS Code, and MCP clients across Streamable HTTP, stdio, and legacy HTTP+SSE.

[![GitHub stars](https://img.shields.io/github/stars/MadaBurns/bv-mcp?style=flat&logo=github)](https://github.com/MadaBurns/bv-mcp/stargazers)
[![npm version](https://img.shields.io/npm/v/blackveil-dns)](https://www.npmjs.com/package/blackveil-dns)
[![npm downloads](https://img.shields.io/npm/dm/blackveil-dns)](https://www.npmjs.com/package/blackveil-dns)
[![MCP tools](https://img.shields.io/badge/MCP%20tools-79-brightgreen)](https://github.com/MadaBurns/bv-mcp/actions)
[![BUSL-1.1 License](https://img.shields.io/badge/License-BUSL--1.1-blue.svg)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-2025--03--26-blue)](https://modelcontextprotocol.io/)
[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare%20Workers-F38020?logo=cloudflare&logoColor=white)](https://workers.cloudflare.com/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.9-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)

![DNS Security](https://dns-mcp.blackveilsecurity.com/badge/blackveilsecurity.com)

</div>

---

## Try it in 30 seconds

**Claude Desktop** (one-click install):

Download the [Blackveil DNS extension](https://github.com/MadaBurns/bv-claude-dns/releases/latest/download/bv-claude-dns.mcpb) and open it — the current 79-tool surface is available instantly. [Verify your download](https://blackveilsecurity.com/extensions/claude-dns#install).

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

- **79 MCP tools with 19 scoring categories** — SPF, DMARC, DKIM, DNSSEC, SSL/TLS, MTA-STS, NS, CAA, MX, BIMI, TLS-RPT, subdomain takeover, HTTP security headers, DANE, SVCB/HTTPS, subdomailing, reverse DNS (PTR/FCrDNS), brand discovery, and authoritative DNS infrastructure
- **Maturity staging** — Stage 0-4 classification (Unprotected to Hardened) with score-based capping to prevent inflated labels
- **Trust surface analysis** — detects shared SaaS platforms (Google, M365, SendGrid) and cross-references DMARC enforcement to determine real exposure
- **Guided remediation** — `generate_fix_plan` produces provider-aware prioritized actions; record generators output ready-to-publish records; `validate_fix` confirms whether a fix was applied successfully
- **Supply chain mapping** — `map_supply_chain` correlates DNS signals to build a full third-party dependency graph with trust levels and risk signals
- **Attack path simulation** — `simulate_attack_paths` enumerates specific paths (spoofing, takeover, hijack) with severity, steps, and mitigations
- **Compliance mapping** — `map_compliance` maps scan findings to NIST 800-177, PCI DSS 4.0, SOC 2, and CIS Controls
- **Self-tuning scoring** — adaptive weights adjust category importance based on patterns seen across scans via Durable Object telemetry
- **Per-tier analytics** — usage tracking by auth tier with operator API for tier summaries, key-level usage, and daily digests
- **Passive and read-only** — all checks use public Cloudflare DNS-over-HTTPS; no authorization required from the target

---

## Tools

```
  79 MCP tools · 7 prompts · 6 resources

  Email Auth             Infrastructure          Brand & Threats       Meta
 ─────────────          ──────────────          ───────────────       ───────────────
  check_mx              check_dnssec            check_bimi            scan_domain
  check_spf             check_ssl               check_tlsrpt          batch_scan
  check_dmarc           check_ns                check_lookalikes      compare_domains
  check_dkim            check_caa               check_shadow_domains  compare_baseline
  check_mta_sts         check_http_security                           explain_finding
  check_subdomailing    check_dane
  check_mx_reputation   check_dane_https        DNS Hygiene           Remediation
                        check_svcb_https       ─────────────         ───────────────
                        check_ptr               check_txt_hygiene     generate_fix_plan
  Intelligence          check_srv
 ─────────────          check_zone_hygiene                            generate_spf_record
  get_benchmark         check_resolver_         Discovery             generate_dmarc_record
  get_provider_           consistency          ─────────────         generate_dkim_config
    insights                                    discover_brand_       generate_mta_sts_policy
  assess_spoofability   check_dbl                domains             validate_fix
  map_supply_chain      check_rbl               brand_audit_single    generate_rollout_plan
  analyze_drift         cymru_asn               brand_audit_batch_
  resolve_spf_chain     rdap_lookup               start
  discover_subdomains   check_nsec_             brand_audit_status
  map_compliance          walkability           brand_audit_get_
  simulate_attack_paths check_dnssec_chain        report
                        check_fast_flux         list_brand_audit_watches
                        check_dnskey_strength
                        check_authoritative_dns_infra
                        check_root_server_set   register_brand_audit_watch
                                                delete_brand_audit_watch

  + check_subdomain_takeover (standalone tool + internal — runs inside scan_domain)
  + check_authoritative_dns_infra and check_root_server_set (authoritative DNS infrastructure profile)

  Operator-deploy only (BV_RECON binding; degrade to unprovisioned on self-hosted BSL deployments):
  + check_realtime_threat_feed   — curated intel-gateway threat feed lookup
  + scan_buckets_start           — async cloud-bucket discovery scan (start → poll → findings)
  + scan_buckets_status          — poll status of a running bucket scan
  + scan_buckets_findings        — retrieve findings for a completed bucket scan
  + osint_investigate_domain_start          — async domain OSINT investigation (start → poll → report)
  + osint_investigate_infrastructure_start  — async deep-infrastructure OSINT (domain, IP, or org)
  + osint_investigate_supply_chain_start    — async supply-chain OSINT investigation
  + osint_investigate_username_start        — async username OSINT (owner/enterprise tier only)
  + osint_investigate_email_start           — async email OSINT (owner/enterprise tier only)
  + osint_investigation_status   — poll status of any running OSINT investigation
  + osint_investigation_report   — retrieve report for a completed OSINT investigation
```

### Tool discovery metadata (`_meta`)

`tools/list` returns every tool with server-specific discovery metadata under each tool's `_meta` (the MCP-sanctioned extension point), so a client can group or filter the surface without hard-coding tool names:

- `group` — functional group (`email_auth`, `infrastructure`, `brand_threats`, `dns_hygiene`, `intelligence`, `remediation`, `discovery`, `identity_secops`, `meta`).
- `tier` — scoring tier (`core` / `protective` / `hardening`); absent for non-scoring tools.
- `scanIncluded` — `true` when the tool runs inside `scan_domain`'s parallel audit.
- `recommended` — present (`true`) only on the curated **starter set** (`scan_domain`, `explain_finding`, `compare_baseline`); omitted otherwise. A client facing the full surface can lead with `tools.filter(t => t._meta.recommended)` to avoid overwhelming an LLM with all tools flat. Every tool is still listed — this is an additive signal, not a filter.

### Authoritative DNS infrastructure

`check_authoritative_dns_infra` scores authoritative DNS hosting behavior for a hostname. It is designed to consume raw UDP/TCP DNS, authoritative AA/RA behavior, zone-transfer refusal, DNSSEC, abuse-resistance, BGP/RPKI, and multi-vantage evidence from the `BV_INFRA_PROBE` service binding when that worker is provisioned.

`check_root_server_set` validates the DNS root-server set against the embedded official root hints. With `BV_INFRA_PROBE`, it also checks live root priming, glue, parent/child delegation, DNSKEY, and SOA serial evidence across roots.

Self-hosted or local deployments without `BV_INFRA_PROBE` still return structured partial results. The worker-only mode records the embedded root hints and marks live raw-DNS, routing, RPKI, and vantage capabilities as inconclusive rather than pretending they ran.

---

## Quality & Reliability

The server is continuously validated using a **comprehensive chaos test suite** that covers all detected MCP client types:

- **Interactive clients**: `claude_code`, `cursor`, `vscode`, `claude_desktop`, `windsurf` (auto-format: `compact`)
- **Non-interactive clients**: `mcp_remote`, `blackveil_dns_action`, `bv_claude_dns_proxy`, `unknown` (auto-format: `full`)

The `bv_load_test` class identifies internal load/chaos/tranco-scan traffic so it stays out of real-client analytics segments.

The test suite ensures session stability, authentication precedence, format negotiation, and transport-specific edge cases across Streamable HTTP and Legacy SSE. Without an API key it exercises the public/free-tier path; with a valid key exported as `BV_API_KEY`, it also covers `?api_key=` authentication, Bearer precedence, authenticated SSE bootstrap, and authenticated batch behavior.

Run the chaos tests locally: `python3 scripts/chaos/chaos-test-clients.py`

SSOT guardrails are enforced by focused audit tests:

- Tool counts and public resource copy are derived from the `TOOLS` registry.
- Domain-required validation is derived from each tool input schema.
- Scan timeout budgets are resolved from shared runtime config.
- WASM tool permissions are generated from MCP tool annotations.
- Public quota copy is checked against runtime quota config.

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
  │  19 scoring categories   │
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

- **Generic Scoring Engine**: Runtime-agnostic, string-keyed three-tier scoring with configurable weights
- **Infra Probe Binding**: Optional `BV_INFRA_PROBE` service binding supplies raw authoritative DNS, root-server, BGP/RPKI, and vantage evidence for the authoritative DNS infrastructure profile
- **WASM Policy Engine**: High-performance permission and token checks via `bv-wasm-core`
- **Reliable Sessions**: Hardened tombstone logic prevents race-condition revival of terminated sessions
- **Adaptive Scoring**: Durable Object telemetry adjusts weights based on real-world distributions
- **Client Awareness**: Automatic response formatting (`compact` vs `full`) based on client `User-Agent`

### Brand-discovery modes (`discover_brand_domains` / `brand_audit_*`)

The `discovery_mode` argument accepts two values:

- **`classic`** (the default everywhere this repo runs out-of-the-box) — the public, BSL-licensed signal-sweep pipeline. Uses only public-internet data sources (DNS, RDAP, CT logs, MX/TXT inspection). This is the only mode supported for self-hosted deployments and the only mode the open test suite covers end-to-end.
- **`tiered`** — layers a portfolio-aware Tier 0 / infrastructure-graph Tier 1 / declared-evidence Tier 2 pipeline in front of the classic sweep. Tiered mode requires private BlackVeil-internal cross-Worker bindings (`BV_INFRA_GRAPH`, `BV_INTEL_GATEWAY`, `BV_ENTERPRISE`) that are **not packaged with the open distribution** — they live in BlackVeil's production deploy overlay (`.dev/wrangler.deploy.jsonc`) and call into proprietary Workers. Self-hosters cannot enable tiered mode without those bindings.

BlackVeil's hosted production at `dns-mcp.blackveilsecurity.com` flips its runtime default to `tiered` via the env var `BRAND_AUDIT_DISCOVERY_MODE_DEFAULT="tiered"` in the private overlay; the public schema default in `src/schemas/tool-args.ts` stays `'classic'` permanently so anyone building from `main` gets the BSL-licensed behaviour unchanged. An explicit caller-supplied `discovery_mode` always wins over the env default.

---

## Client setup

The free tier requires no authentication. Authenticated requests bypass per-IP rate limits and follow your tier's daily quota. Three authentication methods are supported:

- **Header**: `Authorization: Bearer <KEY>`
- **Query Param**: `?api_key=<KEY>` (for clients that can't send custom headers — Smithery, Claude Code)
- **OAuth 2.1**: optional authorization-code flow with PKCE, enabled only when operators set `ENABLE_OAUTH=true`; owner-key consent is separately gated by `ENABLE_OWNER_OAUTH=true`.

For full hosted setup examples, stdio usage, OAuth setup, and legacy fallback endpoints, see [**docs/client-setup.md**](docs/client-setup.md).

---

## Pricing

|                | **Free**   | **Pro** | **Enterprise**                              |
| -------------- | ---------- | ------- | ------------------------------------------- |
| **Price**      | $0         | $39/mo  | [Contact us](https://blackveilsecurity.com) |
| **Scans/day**  | 25         | 500     | 10,000+                                     |
| **Checks/day** | Tool-specific limits | Tool-specific limits | Contract limits                  |
| **Rate limit** | 50 req/min | None    | None                                        |
| **API access** | Yes        | Yes     | Yes                                         |
| **MCP access** | Yes        | Yes     | Yes                                         |

---

## Example prompts

These demonstrate core functionality — paste any of them into Claude with the Blackveil DNS connector enabled:

| Prompt                                                       | What it does                                             |
| ------------------------------------------------------------ | -------------------------------------------------------- |
| `Scan blackveilsecurity.com and tell me what needs fixing`   | Full security audit — score, grade, prioritized findings |
| `Compare the email security of google.com and microsoft.com` | Side-by-side comparison of two domains' postures         |
| `Generate a DMARC record for example.com with reject policy` | Produces a ready-to-publish DNS record                   |
| `What attack paths exist for example.com?`                   | Enumerates spoofing, takeover, and hijack vectors        |
| `Map example.com's compliance against NIST 800-177`          | Maps findings to compliance framework controls           |

---

## Support

- **Bug reports & feature requests:** [GitHub Issues](https://github.com/MadaBurns/bv-mcp/issues)
- **Security vulnerabilities:** [security@blackveilsecurity.com](mailto:security@blackveilsecurity.com) (see [SECURITY.md](SECURITY.md))
- **General questions:** [GitHub Discussions](https://github.com/MadaBurns/bv-mcp/discussions)

---

## Responsible use

This tool is intended for **authorized security assessments** of domains you own or have explicit permission to test. Do not use it for unauthorized reconnaissance, harassment, or any activity that violates applicable laws. Findings from attack simulation, spoofability, and subdomain discovery tools should be used to **improve your own security posture**, not to exploit others.

If you discover a vulnerability in a third-party domain, please follow [coordinated disclosure](https://www.cisa.gov/coordinated-vulnerability-disclosure-process) practices.

---

<div align="center">

Built and maintained by [**BLACKVEIL**](https://blackveilsecurity.com) — NZ-owned cybersecurity consultancy.

[Privacy Policy](https://www.blackveilsecurity.com/privacy) · [License](LICENSE) (BUSL-1.1 → MIT on 2030-03-17)

</div>
