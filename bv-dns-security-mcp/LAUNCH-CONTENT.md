# Launch Content — dns-security-mcp

Prepared for Adam Burns, BLACKVEIL Group.
All content below is ready for review and posting on launch day.

---

## 1. LinkedIn Post

> **760,000 domain scans. Same problems everywhere.**
>
> Over the past year we've scanned more than three quarters of a million domains for DNS and email security. The pattern is depressingly consistent: no DMARC policy, oversized SPF records, DNSSEC disabled, MTA-STS nowhere to be found.
>
> These aren't advanced threats. They're the basics. And most organisations — including ones spending serious money on security — get them wrong.
>
> MCP changed the equation. Your AI assistant can now run the same checks our platform uses, right inside the conversation where you're already working. No dashboard. No CLI. No account. Just ask.
>
> Today we're open sourcing the scanner.
>
> **dns-security-mcp** is a standalone MCP server that runs on Cloudflare Workers. Ten tools covering SPF, DMARC, DKIM, DNSSEC, SSL/TLS, MTA-STS, nameservers, and CAA records. Full domain sweep with an overall score. Plain-English explanations for every finding.
>
> MIT licensed. Zero dependencies on our platform. Deploy your own in one command or use our hosted endpoint.
>
> We built it because the scanning data shouldn't be locked behind a login. The remediation — that's where we earn our keep.
>
> Link in first comment.
>
> Cheers,
> Adam
>
> #cybersecurity #MCP #opensource #DNS #AI

---

## 2. Hacker News — Show HN

**Title:** Show HN: Open source MCP server for DNS/email security scanning (scan any domain from Claude)

**Body:**

We've been running DNS security scans at BLACKVEIL for a year — 760K domains scanned. Today we're open sourcing the scanner as an MCP server. It runs on Cloudflare Workers and exposes 10 tools (SPF, DMARC, DKIM, DNSSEC, SSL, MTA-STS, NS, CAA, full domain sweep, finding explainer) that any MCP-compatible AI client can call. No auth required. Deploy your own with `npx wrangler deploy` or hit the hosted endpoint. MIT licensed.

One stat from the dataset: over 60% of domains we scanned had no DMARC enforcement policy. Their email can be spoofed and they'd never know.

GitHub: https://github.com/blackveil/dns-security-mcp

---

## 3. Twitter/X Thread (@BlackveilSec)

**Tweet 1:**
Over 60% of domains have no DMARC enforcement policy. Their email can be spoofed right now and they'd never know.

We scanned 760,000 of them to be sure.

Thread 🧵

**Tweet 2:**
Today we're open sourcing the scanner.

dns-security-mcp — an MCP server that lets Claude, Cursor, or any MCP client scan any domain for DNS and email security issues.

10 tools. Full domain sweep. Letter grades.

https://github.com/blackveil/dns-security-mcp

**Tweet 3:**
Here's what it looks like. Ask Claude to scan a domain and you get SPF, DMARC, DKIM, DNSSEC, SSL, MTA-STS, NS, and CAA checks — all in one shot.

[SCREENSHOT — Claude Desktop running scan_domain]

**Tweet 4:**
From 760K scans, the biggest surprises:

→ 60%+ have no DMARC enforcement
→ ~40% fail DNSSEC validation
→ SPF record bloat (>10 lookups) is endemic
→ MTA-STS adoption is still under 5%

These aren't edge cases. This is the baseline.

**Tweet 5:**
Get started in 60 seconds:

1. Clone the repo
2. `npm install && npx wrangler deploy`
3. Add the endpoint to Claude Desktop config

Or skip all that and use our hosted version — no setup:
https://dns-mcp.blackveil.co.nz/mcp

**Tweet 6:**
This tool tells you what's broken.

Want it fixed automatically? That's what @BlackveilSec does.

https://blackveil.co.nz

---

## 4. SecurityBrief NZ Pitch Email

**Subject:** NZ founder open sources scanner behind 760,000 domain security checks — first MCP security tool

**Body:**

Hi [journalist name],

Following our previous coverage, wanted to share a new angle. Today we're publicly releasing the DNS security scanner that powered the 760,000 domain scans behind our NZ Security Index — as the first open source MCP (Model Context Protocol) security tool.

dns-security-mcp lets any AI assistant (Claude, Cursor, VS Code Copilot) run comprehensive DNS and email security scans on any domain, directly inside the AI conversation. It runs on Cloudflare Workers, requires no account or API key, and is MIT licensed.

MCP was named the #1 AI security story of 2026 by F5 Labs and NCC Group. This is the first security-focused MCP server with real scanning data behind it. Happy to provide an exclusive if timing suits — embargo lifted Tuesday morning.

Repo: https://github.com/blackveil/dns-security-mcp
Hosted endpoint: https://dns-mcp.blackveil.co.nz/mcp

Cheers,
Adam Burns
BLACKVEIL Group
