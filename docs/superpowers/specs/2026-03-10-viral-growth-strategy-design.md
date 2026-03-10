# Viral Growth Strategy — Design Spec

## Goal

Maximize adoption of Blackveil DNS across developers, security professionals, and enterprise teams with high-leverage, low-effort plays suitable for a solo founder.

## Strategy: "Sharp Wedge"

Ship 2-3 features that create natural sharing moments, then blanket every discovery channel.

---

## Features

### 1. Badge Endpoint (`/badge/{domain}`)

Dynamic SVG badge at `GET /badge/{domain}` returning a shields.io-style shield with the domain's DNS security grade.

- Color: green (A/A+), yellow (B/C), red (D/F)
- Cached (reuse existing scan cache, 5-min TTL)
- Markdown-embeddable: `![DNS Security](https://dns-mcp.blackveilsecurity.com/badge/example.com)`
- No auth required, rate limited same as unauthenticated requests
- Route added to existing Hono app in `src/index.ts`
- Calls `scan_domain` internally (or reads from cache), extracts grade, renders SVG

**SVG spec**: shields.io flat style, label "DNS Security", value is the grade letter, ~200 bytes.

### 2. GitHub Action

Published as `MadaBurns/blackveil-dns-action@v1` in a separate repo.

- Uses the npm package (`blackveil-dns`) or calls hosted endpoint
- Inputs: `domain` (required), `minimum-grade` (default: `C`), `endpoint` (default: hosted URL)
- Outputs: `score`, `grade`, `maturity`, `passed` (boolean)
- Posts job summary with grade, score, maturity, top findings
- Fails the step if grade < minimum-grade
- Composite action or Node.js-based

### 3. Slack/Discord Webhook Recipe

Documented recipe (not a full Slack app) using Cloudflare Cron Trigger:

- Cron runs weekly, scans configured domain
- POSTs formatted message to Slack/Discord webhook URL
- Shows grade, score, any new findings since last scan
- Documented in README and docs/, with a copy-paste wrangler config

---

## Distribution Plan

### Tier 1: MCP Directories (Week 1)
- Smithery (verify existing listing)
- mcp.run, Glama.ai, mcpservers.org, Awesome MCP Servers (GitHub PR)

### Tier 2: Community Launch (Week 2)
- Hacker News "Show HN" (Tuesday-Thursday, 9am US Eastern)
- Reddit: r/netsec, r/cybersecurity, r/selfhosted
- Twitter/Bluesky thread with live scan demo
- Cloudflare community/discord
- One canonical blog post (DEV.to or Hashnode)

### Tier 3: Press (Week 2-3)
- SecurityBrief / NZ Herald follow-up pitch

---

## Repo Optimization

1. GitHub topics: `mcp`, `mcp-server`, `dns-security`, `email-security`, `dmarc`, `spf`, `dkim`, `cloudflare-workers`, `ai-tools`, `security-scanner`, `model-context-protocol`
2. Repo description: "Open-source DNS & email security scanner. One MCP endpoint, 57 checks, zero install. Cloudflare Workers."
3. Terminal demo GIF (asciinema/vhs) at top of README
4. README restructure: one-liner + badges, 30-sec quickstart, GIF, features, details
5. Social preview image (1280x640)
6. "Scan your domain" CTA linking to blackveilsecurity.com scanner
7. Dogfood own badge in README

---

## Execution Sequence

| Week | Tasks |
|------|-------|
| 1 | Repo polish (topics, description, README restructure, demo GIF, social preview) + badge endpoint |
| 2 | MCP directory submissions + blog post + HN/Reddit/social launch |
| 3 | GitHub Action + Slack/Discord recipe + press pitch |
| Ongoing | Scan notable domains on social, respond to issues, retweet badge adopters |

---

## Success Metrics

- GitHub stars (target: 500 in first month)
- npm weekly downloads
- Badge adoption (grep GitHub for badge URL)
- MCP directory click-throughs (if analytics available)
- HN upvotes / front page
