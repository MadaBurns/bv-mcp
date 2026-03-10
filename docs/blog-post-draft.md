---
title: "I Built an AI-Native DNS Security Scanner That Runs 57 Checks From a Single URL"
published: false
description: "Blackveil DNS is an open-source DNS and email security scanner exposed via the Model Context Protocol. One endpoint, no install, no API key. Works with Claude, Cursor, VS Code, and any MCP client."
tags: security, dns, opensource, ai
---

# I Built an AI-Native DNS Security Scanner That Runs 57 Checks From a Single URL

Over 90% of cyberattacks start with email. Phishing, business email compromise, domain spoofing -- they all depend on the same thing: weak DNS configuration. Missing SPF records, unenforced DMARC policies, dangling CNAMEs waiting for subdomain takeover. The building blocks of email security are all public DNS records, and most organisations have no idea what theirs actually say.

I kept running into this problem while doing security assessments. I would need to check a domain's email authentication posture, and the workflow was always the same: open five different tools, copy the domain into each one, mentally stitch the results together, then try to explain what it all means to someone who does not live in DNS.

So I built something better.

## The problem with existing tools

DNS security tooling is fragmented. You have MXToolbox for MX lookups, dmarcian for DMARC, SSLLabs for certificates, and a dozen CLI scripts for everything else. Each tool covers one slice. None of them talk to each other. None of them give you a unified score or tell you what to fix first.

And none of them work inside an AI assistant.

That last point matters more than it might seem. AI coding tools like Claude, Cursor, and VS Code Copilot are becoming the place where developers actually work. If you are reviewing infrastructure, triaging a security alert, or onboarding a new client, you want to check a domain right there in your conversation -- not context-switch to a browser tab, paste results back, and hope the AI can parse the output.

## What I built

**Blackveil DNS** is an open-source DNS and email security scanner built as a Cloudflare Worker, exposed via the [Model Context Protocol](https://modelcontextprotocol.io/) (MCP). One endpoint URL. No install. No API key.

```
Endpoint   https://dns-mcp.blackveilsecurity.com/mcp
Transport  Streamable HTTP (JSON-RPC 2.0)
Auth       None required
```

It runs **57 checks across 13 categories**: SPF, DMARC, DKIM, DNSSEC, SSL/TLS, MTA-STS, NS, CAA, MX, BIMI, TLS-RPT, subdomain takeover, and lookalike domain detection. Each check produces structured findings with severity levels, confidence labels, and plain-English remediation guidance.

The scanner exposes 14 MCP tools. You can run individual checks (`check_spf`, `check_dmarc`, etc.) or use `scan_domain` to run everything in parallel and get a scored report with a maturity classification from Stage 0 (Unprotected) through Stage 4 (Hardened).

A few things that make it different from the usual DNS lookup tools:

- **Trust surface analysis** -- it detects shared SaaS platforms (Google Workspace, SendGrid, Mailchimp) in your SPF includes and cross-references your DMARC enforcement to determine whether that shared infrastructure is actually a risk or just noise.
- **Non-mail domain awareness** -- if a domain has no MX records, the scanner checks the parent domain's DMARC policy and adjusts severity accordingly. A missing SPF record on a subdomain that inherits `sp=reject` from the parent is not the same as a missing SPF record on your primary mail domain.
- **Provider intelligence** -- inbound and outbound email provider inference from MX records, SPF includes, and DKIM selectors.
- **`explain_finding`** -- pass any finding back to this tool and it returns what it means, why it matters, what could go wrong, specific steps to fix it, and the relevant RFCs.

## Real output

Here is what `scan_domain("anthropic.com")` actually returns:

```
  BLACKVEIL DNS                                          anthropic.com
 --------------------------------------------------------------------------

  CATEGORY          SCORE    STATUS    KEY FINDINGS
 --------------------------------------------------------------------------
  SPF                80/100    PASS    Soft fail (~all), Google shared
  DMARC              90/100    PASS    p=reject, relaxed alignment
  DKIM               85/100    PASS    google selector, 2048-bit RSA
  DNSSEC             35/100    FAIL    Not enabled -- no DNSKEY/DS
  SSL/TLS           100/100    PASS    HTTPS + HSTS configured
  MTA-STS            85/100    PASS    No MTA-STS/TLS-RPT records
  NS                 95/100    PASS    Cloudflare anycast
  CAA                85/100    PASS    No CAA records published
  MX                100/100    PASS    5 MX records, Google Workspace
  BIMI               95/100    PASS    Eligible but not published
  TLS-RPT            95/100    PASS    No TLS-RPT record
 --------------------------------------------------------------------------

  ----------------------------------------           85 / 100    Grade: A

  2 high   4 medium   5 low   5 info
```

Every finding includes a severity, a confidence label (`deterministic`, `heuristic`, or `verified`), and the category it belongs to. The AI assistant receiving this output can reason about it, prioritise fixes, and explain the results in context.

## How it works

The architecture is straightforward. A Cloudflare Worker running [Hono](https://hono.dev/) handles incoming JSON-RPC 2.0 requests over Streamable HTTP. When a scan request comes in, the worker:

1. Validates and sanitizes the domain input (with SSRF protection against internal IPs, blocked TLDs, and DNS rebinding services)
2. Runs all 13 check categories in parallel using `Promise.all`
3. Each check queries Cloudflare's DNS-over-HTTPS resolver
4. A scoring engine weights findings by category importance and severity, applies an email authentication bonus when SPF/DKIM/DMARC are all present, and computes a 0-100 score
5. Results are cached for 5 minutes (KV-backed with in-memory fallback)

Rate limiting is built in: 30 requests per minute, 200 per hour per IP for tool calls. Protocol methods (initialize, ping, tools/list) are exempt. The lookalike domain checker, which generates around 100 DoH queries per invocation, has its own separate daily quota.

Everything is passive and read-only. The scanner only queries public DNS records via Cloudflare DoH. No authorization is needed from the target domain.

## Try it yourself

**Claude Code** -- one command, takes 10 seconds:

```bash
claude mcp add --transport http blackveil-dns https://dns-mcp.blackveilsecurity.com/mcp
```

Then ask: "scan yourdomain.com"

**VS Code / Copilot** -- add to `.vscode/mcp.json`:

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

**Cursor** -- add to `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "blackveil-dns": {
      "url": "https://dns-mcp.blackveilsecurity.com/mcp"
    }
  }
}
```

There is also an **npm package** if you want to call the scanner programmatically:

```bash
npm install blackveil-dns
```

```ts
import { scanDomain, formatScanReport } from 'blackveil-dns';

const result = await scanDomain('example.com');
console.log(formatScanReport(result));
```

## What is next

A few things on the roadmap:

- **Badge endpoint** -- embeddable DNS security grade badges for READMEs and websites (like the coverage badges you already know)
- **GitHub Action** -- run Blackveil DNS as part of your CI pipeline to catch DNS misconfigurations before they become incidents
- **More checks** -- deeper DANE/TLSA validation, extended subdomain enumeration, and certificate transparency log analysis

This is an open-source project and contributions are welcome. The codebase has 630+ tests with roughly 95% coverage, strict TypeScript, and a clear pattern for adding new checks.

## Give it a try

Run a scan on your own domain. See what comes back. I have been surprised by what even well-configured domains are missing.

- **GitHub**: [github.com/MadaBurns/bv-mcp](https://github.com/MadaBurns/bv-mcp) -- star it if you find it useful
- **npm**: [npmjs.com/package/blackveil-dns](https://www.npmjs.com/package/blackveil-dns)
- **Web scanner**: [blackveilsecurity.com](https://blackveilsecurity.com)

If you find a bug, have a feature request, or want to add a new check category, open an issue on GitHub. The contribution path is documented: create the check module, add the tool schema, write tests using the DNS mock helper, and submit a PR.

---

*Built and maintained by [BLACKVEIL](https://blackveilsecurity.com) -- NZ-owned cybersecurity consultancy.*
