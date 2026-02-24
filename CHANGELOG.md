# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-02-24

### Added

- 10 MCP tools: `scan_domain`, `check_spf`, `check_dmarc`, `check_dkim`, `check_dnssec`, `check_ssl`, `check_mta_sts`, `check_ns`, `check_caa`, `explain_finding`
- 3 static MCP resources: security checks guide, scoring methodology, DNS record types
- MCP Streamable HTTP transport (JSON-RPC 2.0) with SSE support
- Weighted scoring engine aligned with BLACKVEIL scanner (50 checks, 8 categories)
- Email authentication bonus (up to 5 points) when SPF + DKIM + DMARC all pass
- DNS-over-HTTPS via Cloudflare DoH — no direct DNS resolution
- KV-backed per-IP rate limiting (10 req/min, 50 req/hr) with in-memory fallback
- KV-backed scan result cache (5-min TTL) with in-memory fallback
- Per-check caching in `tools/call` handler
- Optional bearer token authentication (open mode when `BV_API_KEY` is empty)
- Constant-time token comparison for auth
- SSRF protection: blocks private IPs, reserved TLDs, DNS rebinding services
- Input validation per RFC 1035 (domain length, label rules)
- Error sanitization — only known validation errors surface to clients
- Request body size limit (10 KB)
- Session management with cryptographic session IDs
- Health endpoint at `/health`
- Landing page at `/`
- 253 tests with ~95% line coverage
- CI/CD via GitHub Actions (test on PR, auto-deploy on push to main)
- Standalone subpackage at `bv-dns-security-mcp/` for separate distribution
- Smithery marketplace manifest
- Copilot instructions and CLAUDE.md agent documentation

### Security

- IP sourcing uses only `cf-connecting-ip` — never `x-forwarded-for`
- Auth uses constant-time XOR comparison to prevent timing side-channel attacks
