# MCP Directory Submissions

Submission copy for MCP tool directories. Each entry is tailored to the directory's format and audience.

---

## 1. Smithery (smithery.ai)

**Name:** blackveil-dns

**Short description:** DNS and email security scanner -- 57 checks across 13 categories via a single MCP endpoint. No install, no API key.

**Long description:**
Blackveil DNS is an open-source DNS and email security scanner exposed as an MCP server on Cloudflare Workers. It performs 57 checks across 13 categories including SPF, DMARC, DKIM, DNSSEC, SSL/TLS, MTA-STS, NS, CAA, MX, BIMI, TLS-RPT, subdomain takeover, and lookalike domain detection. All queries use Cloudflare DNS-over-HTTPS and are passive and read-only. Results include per-check scores, severity-rated findings, maturity staging (Stage 0-4), trust surface analysis for shared SaaS platforms, and plain-English remediation via the explain_finding tool. 14 callable tools, 630+ tests, MIT licensed. Works with Claude, Cursor, VS Code, and any MCP-compatible client.

**Category:** Security

**Tags:** dns, email-security, spf, dmarc, dkim, ssl, dnssec, cloudflare-workers, security-scanner

---

## 2. mcp.run

**Name:** blackveil-dns

**Description:** Open-source DNS and email security scanner running on Cloudflare Workers. Provides 14 MCP tools covering SPF, DMARC, DKIM, DNSSEC, SSL/TLS, MTA-STS, CAA, MX, BIMI, TLS-RPT, subdomain takeover, and lookalike domains. Zero install -- connect any MCP client to one URL. Passive, read-only checks via Cloudflare DoH. Returns scored results with severity-rated findings and remediation guidance.

**URL:** https://dns-mcp.blackveilsecurity.com/mcp

**Category:** Security

---

## 3. Glama.ai

**Name:** blackveil-dns

**One-liner:** DNS and email security scanner with 57 checks, zero install, exposed as a single MCP endpoint on Cloudflare Workers.

**Description:**
Blackveil DNS gives any MCP client access to comprehensive DNS and email security scanning through one endpoint URL. It covers 13 categories -- SPF, DMARC, DKIM, DNSSEC, SSL/TLS, MTA-STS, NS, CAA, MX, BIMI, TLS-RPT, subdomain takeover, and lookalike domains -- with 57 individual checks. Built on Cloudflare Workers for low-latency global execution, all DNS resolution goes through Cloudflare DoH. Features include domain maturity staging, trust surface analysis for shared email platforms, provider detection, and an explain_finding tool that produces actionable remediation steps. No API key required. Open source, MIT licensed.

**URL:** https://github.com/MadaBurns/bv-mcp

---

## 4. mcpservers.org

**Name:** blackveil-dns

**Description:** Open-source DNS and email security scanner available as a remote MCP server. Runs 57 passive checks across 13 categories (SPF, DMARC, DKIM, DNSSEC, SSL/TLS, MTA-STS, NS, CAA, MX, BIMI, TLS-RPT, subdomain takeover, lookalikes) using Cloudflare DNS-over-HTTPS. No installation or API key needed -- point any MCP client at the endpoint. Returns scored results, maturity staging, and plain-English remediation. 630+ tests, MIT licensed, built on Cloudflare Workers with Hono v4.

**URL:** https://github.com/MadaBurns/bv-mcp

**Tags:** security, dns, email, cloudflare-workers, remote-server

---

## 5. Awesome MCP Servers (GitHub)

### Awesome list entry

```
- [blackveil-dns](https://github.com/MadaBurns/bv-mcp) - DNS and email security scanner with 57 checks across 13 categories (SPF, DMARC, DKIM, DNSSEC, SSL/TLS, and more). Remote MCP server on Cloudflare Workers -- no install, no API key.
```

### PR title

Add blackveil-dns -- DNS and email security scanner

### PR description

Adds [blackveil-dns](https://github.com/MadaBurns/bv-mcp), an open-source DNS and email security scanner exposed as a remote MCP server on Cloudflare Workers.

- **57 checks** across 13 categories: SPF, DMARC, DKIM, DNSSEC, SSL/TLS, MTA-STS, NS, CAA, MX, BIMI, TLS-RPT, subdomain takeover, lookalike domains
- **14 MCP tools** via Streamable HTTP (JSON-RPC 2.0)
- **Zero install** -- single endpoint URL, no API key required
- Passive and read-only (all queries via Cloudflare DNS-over-HTTPS)
- 630+ tests, ~95% coverage, MIT licensed
- Works with Claude, Cursor, VS Code, and any MCP client

Endpoint: `https://dns-mcp.blackveilsecurity.com/mcp`
npm: [blackveil-dns](https://www.npmjs.com/package/blackveil-dns)
