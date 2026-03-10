# Show HN Draft

**Title:** Show HN: Open-source DNS security scanner as an MCP server -- 57 checks, one URL

---

**Body:**

Blackveil DNS is an open-source DNS and email security scanner that runs as a single MCP (Model Context Protocol) endpoint on Cloudflare Workers -- no install, no API key, no local tooling.

I built this because existing DNS security tools are either paywalled dashboards or CLI scripts that need local setup. Neither works when you're inside an AI assistant and want to check a domain mid-conversation. MCP gives you a standard way to expose tools to LLMs, so I put the scanner behind one URL that any MCP client can call.

It runs 57 checks across 13 categories: SPF, DMARC, DKIM, DNSSEC, SSL/TLS, MTA-STS, NS, CAA, MX, BIMI, TLS-RPT, subdomain takeover, and lookalike domains. All queries go through Cloudflare DNS-over-HTTPS -- passive and read-only. The test suite has 630+ tests at ~95% coverage.

Try it in Claude Code:

    claude mcp add --transport http blackveil-dns https://dns-mcp.blackveilsecurity.com/mcp

Then: `scan anthropic.com`

For VS Code or Cursor, paste the endpoint URL into your MCP config. Details in the README.

GitHub: https://github.com/MadaBurns/bv-mcp
npm: https://www.npmjs.com/package/blackveil-dns

MIT licensed. Written in TypeScript, runs on Cloudflare Workers (Hono v4). Contributions welcome -- especially new check categories and client integrations.
