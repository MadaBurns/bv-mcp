# Blackveil DNS

Open-source DNS & email security scanner — MCP server for AI-powered domain analysis.

[![CI](https://github.com/MadaBurns/bv-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/MadaBurns/bv-mcp/actions/workflows/ci.yml)
[![Release](https://github.com/MadaBurns/bv-mcp/actions/workflows/release.yml/badge.svg)](https://github.com/MadaBurns/bv-mcp/actions/workflows/release.yml)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Cloudflare Workers](https://img.shields.io/badge/runtime-Cloudflare%20Workers-F38020.svg)](https://workers.cloudflare.com)
[![MCP 2024-11-05](https://img.shields.io/badge/MCP-2024--11--05-green.svg)](https://modelcontextprotocol.io)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178C6.svg)](https://www.typescriptlang.org)

## Quick Start

### Deploy to Cloudflare Workers

```bash
npx wrangler deploy
```

### Run locally

```bash
npm install && npm run dev
```

### Use the hosted version

No setup required — point your MCP client at:

```
https://dns-mcp.blackveilsecurity.com/mcp
```

#### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "blackveil-dns": {
      "type": "streamable-http",
      "url": "https://dns-mcp.blackveilsecurity.com/mcp"
    }
  }
}
```

#### VS Code / GitHub Copilot

Add to `.vscode/mcp.json`:

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

#### Cursor

Add to `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "blackveil-dns": {
      "url": "https://dns-mcp.blackveilsecurity.com/mcp"
    }
  }
}
```

## What It Does

| Tool | What it does |
|------|-------------|
| `scan_domain` | Run a full security scan and get an overall score and grade |
| `check_spf` | Check if your domain can be spoofed via email |
| `check_dmarc` | See if spoofed emails get rejected or just observed |
| `check_dkim` | Verify your outgoing emails are digitally signed |
| `check_dnssec` | Check if your DNS is protected from tampering |
| `check_ssl` | Test if your site uses HTTPS properly |
| `check_mta_sts` | See if your incoming email connections are encrypted |
| `check_ns` | Analyze your nameserver setup for reliability |
| `check_caa` | Check which certificate authorities can issue certs for your domain |
| `check_mx` | Look at your mail server configuration |
| `explain_finding` | Get a plain-English explanation of any finding and what to do about it |

## Example Conversations

### "Is my domain secure?"

```
User: Is example.com secure?

Claude: I'll run a full security scan.

→ scan_domain({ "domain": "example.com" })

Your domain scored 72/100 (C+). Key issues:
- No DMARC record (critical)
- DNSSEC not enabled (high)
- No CAA records (medium)
```

### "Why are our emails going to spam?"

```
User: Our emails from acme.com keep landing in spam. What's wrong?

Claude: Let me check your email authentication setup.

→ check_spf({ "domain": "acme.com" })
→ check_dmarc({ "domain": "acme.com" })

Your SPF record uses ~all (soft fail) instead of -all (hard fail),
and your DMARC policy is set to "none" — mailbox providers have
no reason to trust your emails. Here's how to fix both.
```

### "Explain this finding"

```
User: What does "DMARC policy set to none" actually mean?

Claude: Let me explain that finding.

→ explain_finding({ "checkType": "DMARC", "status": "warning" })

DMARC with p=none means you're only monitoring — spoofed emails
still get delivered normally. Upgrade to p=quarantine or p=reject
after reviewing your DMARC reports to confirm legitimate senders.
```

## Why We Built This

We've run 760,000+ scans and see the same mistakes everywhere — missing DMARC policies, permissive SPF records, no DNSSEC. Most teams don't know these problems exist until something goes wrong. So we decided to give the scanner to the world and let anyone check their domain security right from their AI assistant.

## Want Autonomous Remediation?

This tool finds problems. [BLACKVEIL](https://blackveilsecurity.com) fixes them automatically.

## License

MIT
