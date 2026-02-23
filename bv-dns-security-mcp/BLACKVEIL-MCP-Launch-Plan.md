
BLACKVEIL GROUP
Open Source MCP Scanner — Launch Plan

For execution by Claude Code
February 2026  •  Confidential

Executive Summary
BLACKVEIL's bv-mcp-scanner worker is a production-grade MCP (Model Context Protocol) server that exposes the DNS security scanning engine to any AI assistant. This plan details how to strip the private Cloudflare service bindings, rebuild it as a fully standalone open source tool, write a viral-ready README, and launch it into the global developer community on Tuesday 3 March 2026.

Why This, Why Now
MCP is the dominant AI tooling standard in 2026 — F5 Labs, NCC Group, and Clearance Jobs all named it the #1 security story of the year.
OpenClaw peaked Jan 30. The wave is still running. You have ~4 weeks before the cycle cools.
No security-focused MCP server with real scanning data exists yet. First-mover advantage is real.
760,000 scans = credibility no 20-minute clone can fake. The tool is the proof of legitimacy.
Every GitHub star is a funnel entry point into BLACKVEIL's paid platform.

1. What We're Building
1.1 The Product: dns-security-mcp
A standalone, MIT-licensed MCP server that lets any Claude, Cursor, or VS Code Copilot user run comprehensive DNS and email security scans on any domain — directly inside their AI chat. No dashboard. No account. One command to install.

Core capabilities (all eight tools ship):
•	scan_domain — Full 45+ check sweep, scored threat level, categorised findings
•	check_spf — SPF record validation and syntax analysis
•	check_dmarc — DMARC policy enforcement level and recommendations
•	check_dkim — DKIM selector probing and key strength check
•	check_ssl — Certificate validity, expiry, and cipher suite warnings
•	check_dnssec — DNSSEC chain-of-trust validation
•	check_mta_sts — MTA-STS policy enforcement status
•	explain_finding — AI-powered plain-English explanation of any finding

What ships vs. what stays private:
FILE / COMPONENT	WHAT CHANGES
src/tools/*.ts (all 8 tools)	Ships — rewritten to use Cloudflare DNS-over-HTTPS directly, no internal binding
src/handlers/tools.ts	Ships — tool definitions and routing, cleaned of internal references
src/handlers/resources.ts	Ships — domain report and threat level resources
src/resources/check-docs.ts	Ships — the 17-check documentation library (huge SEO and community value)
src/lib/sanitize.ts	Ships — unchanged, useful utility
src/middleware/security.ts	Ships — simplified, INTERNAL_API_KEY removed
src/index.ts	Ships — cleaned entry point
DNS_WORKER service binding	STAYS PRIVATE — replaced with public Cloudflare DoH API
INTERNAL_API_KEY	STAYS PRIVATE — removed entirely
RATE_LIMITER KV binding	STAYS PRIVATE — replaced with simple in-memory limiter
19GB scan database	STAYS PRIVATE — not exposed, never referenced
Buck AI / bv-ai-security-agent-v2	STAYS PRIVATE — this is the moat

2. Technical Build Plan for Claude Code
The following is a precise, ordered set of tasks Claude Code should execute. Each task includes the file path, what to change, and the implementation approach. Work in a fresh directory: ~/projects/dns-security-mcp/

2.1 Project Scaffold
Task 1: Initialise the repo
1.	Create directory: mkdir -p ~/projects/dns-security-mcp/src/{tools,handlers,resources,lib,middleware}
2.	Copy source files from the bv-mcp-scanner worker codebase into src/
3.	Create wrangler.toml with no private bindings (see spec below)
4.	Create package.json — TypeScript, Hono, Wrangler, Vitest
5.	Create tsconfig.json targeting workers runtime

wrangler.toml spec (open source version)
name = "dns-security-mcp"
compatibility_date = "2025-01-01"
main = "src/index.ts"

[vars]
MCP_PROTOCOL_VERSION = "2024-11-05"
WORKER_VERSION = "1.0.0"

# No private bindings. No KV. No service bindings. No secrets.
# The whole point is it runs standalone.

2.2 The Core Refactor: Replace DNS_WORKER Binding
This is the critical technical task. Every tool currently calls env.DNS_WORKER.fetch() with an internal URL. Replace with direct Cloudflare DNS-over-HTTPS resolution.

Task 2: Create src/lib/dns-resolver.ts
This new module is the drop-in replacement for the internal DNS_WORKER. It should:
•	Query Cloudflare's public DoH endpoint: https://cloudflare-dns.com/dns-query
•	Accept record type (TXT, MX, A, CNAME) and domain as parameters
•	Return raw DNS records in a consistent format matching what the internal worker returns
•	Handle errors gracefully — NXDOMAIN, SERVFAIL, timeouts all return structured errors
•	Support querying _dmarc.domain, selector._domainkey.domain, _mta-sts.domain patterns

// Example signature
export async function resolveDNS(domain: string, type: string): Promise<DNSResult>
export async function resolveTXT(domain: string): Promise<string[]>
export async function resolveMX(domain: string): Promise<MXRecord[]>

Task 3: Rewrite each tool in src/tools/
For each of the 8 tool files, replace the env.DNS_WORKER.fetch() call with direct calls to the new dns-resolver module. The tool logic, scoring, and response format stays identical.

FILE / COMPONENT	WHAT CHANGES
src/tools/scan-domain.ts	Replace DNS_WORKER call with: parallel calls to resolveTXT, resolveMX, checkSSL, then aggregate results and score
src/tools/check-spf.ts	Replace with: resolveTXT(domain) → filter for 'v=spf1' record → parse and validate
src/tools/check-dmarc.ts	Replace with: resolveTXT('_dmarc.' + domain) → parse policy, pct, rua fields
src/tools/check-dkim.ts	Replace with: probe common selectors (google, default, k1, dkim, mail, smtp) via resolveTXT(selector + '._domainkey.' + domain)
src/tools/check-ssl.ts	Replace with: fetch('https://' + domain, {method:'HEAD'}) → inspect response headers and certificate info via CF Workers TLS metadata
src/tools/check-dnssec.ts	Replace with: DoH query with DO=1 flag, check AD (Authenticated Data) bit in response
src/tools/check-mta-sts.ts	Replace with: resolveTXT('_mta-sts.' + domain) + fetch('https://mta-sts.' + domain + '/.well-known/mta-sts.txt')
src/tools/explain-finding.ts	Replace env.AI.run() with: call user-configured LLM endpoint (Claude, OpenAI, or Cloudflare AI via user's own API key in wrangler.toml vars)

2.3 Clean the Middleware
Task 4: Simplify src/middleware/security.ts
•	Remove INTERNAL_API_KEY check entirely
•	Replace KV-based rate limiter with a simple in-memory Map with sliding window
•	Keep origin validation — it's useful and shows security-first thinking
•	Default rate limit: 30 scans/hour per IP (generous enough for dev use)

Task 5: Clean src/index.ts
•	Remove all references to env.INTERNAL_API_KEY
•	Remove DNS_CACHE KV references (caching via in-memory Map instead, 5 min TTL)
•	Keep all 8 tools and resource handlers
•	Add a GET /mcp endpoint that returns server capabilities (useful for MCP discovery)

2.4 Tests
Task 6: Write Vitest unit tests
•	test/dns-resolver.test.ts — mock DoH responses, test TXT/MX/CNAME parsing
•	test/tools/check-spf.test.ts — test SPF scoring logic with sample records
•	test/tools/check-dmarc.test.ts — test policy extraction (none/quarantine/reject)
•	test/integration/scan-domain.test.ts — end-to-end scan against a real domain (blackveil.co.nz) in CI
Aim for >80% coverage on the scoring logic. The tests double as documentation for contributors.

3. The README (Exact Structure for Claude Code to Write)
The README is the product. OpenClaw got 157K stars because its README created an instant 'I need this' moment. Follow this structure exactly.

3.1 README.md Structure
Opening (first 20 lines — must hook immediately)
•	Repo name: dns-security-mcp
•	Tagline: 'The open source MCP server for DNS and email security. Scan any domain from inside Claude, Cursor, or any MCP-compatible AI.'
•	Immediately below: ONE screenshot — a real Claude conversation showing scan_domain('blackveil.co.nz') returning a threat report. This image is mandatory. Adam should generate it before launch.
•	Badges: MIT License | Cloudflare Workers | MCP 2024-11-05 | TypeScript

Quick Start (lines 21-50 — must work in under 60 seconds)
# Option 1: Run on Cloudflare Workers (recommended)
npx wrangler deploy

# Option 2: Run locally for development
npm install && npm run dev

# Option 3: Use the hosted version (no setup)
# MCP endpoint: https://dns-mcp.blackveil.co.nz/mcp

Claude Desktop config block (copy-paste ready)
{
  "mcpServers": {
    "dns-security": {
      "url": "https://dns-mcp.blackveil.co.nz/mcp"
    }
  }
}

What It Does section
•	Plain English list of all 8 tools with one-line descriptions
•	No jargon. 'Check if your domain can be spoofed' not 'validate DMARC policy enforcement'

Example Conversations section
•	3 screenshots or code blocks showing real Claude conversations using the tools
•	Example 1: 'Is my startup's domain safe?' → scan_domain result
•	Example 2: 'Why are our emails going to spam?' → check_spf + check_dmarc diagnosis
•	Example 3: 'Explain this DNSSEC finding to me' → explain_finding

Why We Built This section
•	One paragraph from Adam's voice — 760,000 scans, same mistakes everywhere, decided to give the scanner to the world
•	No corporate speak. Raw and direct.

Want Autonomous Remediation? (CTA — bottom of README)
•	One sentence: 'This tool finds problems. BLACKVEIL fixes them automatically.'
•	Link to blackveil.co.nz — nothing else, no pricing, no hard sell

4. Launch Sequence
4.1 Full Timeline
TIMING	TASK	DETAIL
Today (D-10)	Start build	Claude Code executes Sections 2.1–2.4 of this plan. Target: working standalone scanner.
D-8	Hosted endpoint	Deploy the open source version to dns-mcp.blackveil.co.nz via Cloudflare Workers. Test all 8 tools end-to-end.
D-7	Repo goes public	Push to github.com/blackveil/dns-security-mcp as public. No announcement yet. Let GitHub index it.
D-5	Screenshot	Adam: open Claude Desktop with the MCP server configured, run a real scan, screenshot the output. This image is the hook.
D-4	Write content	Claude Code writes: README.md (per Section 3), LinkedIn post, HN Show submission, 6-tweet Twitter thread.
D-3	Review	Adam reviews all content. Adjust voice. Confirm screenshot is good. Prep email to SecurityBrief NZ journalist.
D-1 (Mon)	Final checks	Verify hosted endpoint is live. Test Claude Desktop config. Check GitHub README renders correctly.
Launch (Tue 3 Mar)	FIRE	7am NZ time: LinkedIn post live. 9am US Eastern: Hacker News Show HN. 2pm NZ: Twitter thread. 5pm NZ: Email to SecurityBrief NZ.
D+1	Amplify	Post to r/netsec, r/selfhosted, r/MachineLearning. Respond to every HN comment personally.
D+3	Follow up	Blog post on blackveil.co.nz: 'Why I open sourced our DNS scanner'. Links back to repo. Pitched to NZ Herald tech desk.
D+7	Capitalise	Email every company that scored below 50 in the NZ Security Index with a personal note + link to the tool.

5. Launch Content (Claude Code to Write)
5.1 LinkedIn Post
Word count: 200-280 words. Adam's voice — direct, no-nonsense, punchy. Structure:
•	Hook (1 line): Something provocative about DNS security or MCP
•	The story (3-4 short paragraphs): 760K scans, same mistakes, built the fix, now giving it away
•	The CTA: 'Link in first comment' (GitHub repo)
•	Hashtags (max 5): #cybersecurity #MCP #opensource #DNS #AI

Tone reference — use Adam's existing voice:
Short sentences. No corporate jargon.
Comfortable saying what the industry gets wrong.
'Cheers' as a sign-off.
Dry humour is fine. Hyperbole is not.
Talks to builders and founders, not enterprise procurement teams.

5.2 Hacker News — Show HN Submission
Title: 'Show HN: Open source MCP server for DNS/email security scanning (scan any domain from Claude)'
Body (4-6 sentences max): What it is, why you built it, one surprising stat from 760K scans, link. Do not pitch. HN hates pitch.

5.3 Twitter Thread (@BlackveilSec)
•	Tweet 1 (hook): Stat or provocative statement about DNS security + 'Thread 🧵'
•	Tweet 2: What the tool does in one sentence + the GitHub link
•	Tweet 3: Screenshot of Claude using the tool
•	Tweet 4: The surprising finding from 760K scans
•	Tweet 5: How to install in 60 seconds
•	Tweet 6: 'Want it fixed, not just found? @BlackveilSec'

5.4 SecurityBrief NZ Pitch Email
One paragraph pitch to the journalist who wrote the exclusive. New angle: 'NZ founder open sources the scanner behind 760,000 domain checks — the first MCP security tool.' Embargo lifted launch day morning.

6. Repository Name & Metadata
GitHub Repository Spec
Repo name: dns-security-mcp
Org: blackveil (or personal account for launch velocity — org can be transferred later)
Description: 'Open source MCP server for DNS and email security. Scan any domain from Claude, Cursor, or any MCP-compatible AI.'
Topics: mcp, dns, email-security, dmarc, spf, dkim, cloudflare-workers, typescript, cybersecurity, ai-tools
License: MIT
Homepage: https://dns-mcp.blackveil.co.nz
Social preview image: the Claude conversation screenshot

7. What Not To Do
Hard rules for the launch:
DO NOT mention pricing anywhere in the README or launch content. Not even 'free tier'.
DO NOT call it BLACKVEIL DNS Scanner or any branded name. The tool is dns-security-mcp. Brand comes second.
DO NOT launch on a Friday or Monday.
DO NOT submit to HN before LinkedIn. LinkedIn warms the crowd, HN converts it.
DO NOT respond defensively to HN criticism. Thank, acknowledge, fix if valid.
DO NOT open source the scoring weights or the 19GB dataset.
DO NOT add a waitlist or email capture to the README. It kills momentum.
DO NOT over-explain. One screenshot is worth 500 words of documentation.

8. Success Metrics
Week 1 targets
•	200+ GitHub stars (minimum for credibility)
•	HN front page or top 10 on Show HN day
•	1 media pickup (SecurityBrief NZ minimum)
•	50+ installs via the hosted endpoint

Month 1 targets
•	1,000+ GitHub stars
•	3+ media mentions across ANZ/global tech press
•	10+ inbound consulting inquiries directly attributed to the tool
•	BLACKVEIL platform signups visibly uplift in the week following launch


Prepared by Claude for Adam Burns, BLACKVEIL Group
February 2026  •  Confidential — Internal Use Only
