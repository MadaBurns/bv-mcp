# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- `check_subdomain_takeover` now runs known subdomain probe flow in parallel to reduce worst-case `scan_domain` latency.
- Provider signature loading now uses a short-lived in-isolate cache (5 minutes) when `PROVIDER_SIGNATURES_URL` is configured.
- `check_spf` now performs RFC-aware DNS lookup budget analysis with explicit near-limit signaling at 9/10 lookups.
- `check_dkim` now probes an expanded set of common provider selectors (`selector`, `s1024`, `s2048`, `amazonses`, `mandrill`, `mailjet`, `zoho`) for better detection depth.

### Added

- Provider signature cache behavior tests in `test/provider-signatures.spec.ts`.
- A dedicated `scan_domain` latency troubleshooting section in `docs/troubleshooting.md`.
- SPF regression test for lookup-budget near-limit warning behavior in `test/check-spf.spec.ts`.

## [1.0.2] - 2026-03-04

### Removed

- `upgrade_cta` from scan output — conversion hook belongs in README, not tool output

### Added

- HSTS header validation and HTTP→HTTPS redirect check in `check_ssl`
- Null MX (RFC 7505), IP address detection, redundancy check in `check_mx`
- SSL and MX explanation entries for `explain_finding`

### Changed

- `explain_finding` status enum expanded to include all severity levels (critical, high, medium, low, info)
- "No MX records found" severity from `high` to `medium`
- `CATEGORY_DEFAULTS` renamed to `CATEGORY_DISPLAY_WEIGHTS` for clarity

### Fixed

- CHANGELOG rate limit typo (50 → 100 req/hr)
- Static resources updated to reflect 10 checks (was "8 category checks")

## [1.0.0] - 2026-02-24

### Added

- 12 MCP tools: `scan_domain`, `check_spf`, `check_dmarc`, `check_dkim`, `check_mx`, `check_ssl`, `check_dnssec`, `check_mta_sts`, `check_ns`, `check_caa`, `check_subdomain_takeover`, `explain_finding`
- 3 static MCP resources: security checks guide, scoring methodology, DNS record types
- MCP Streamable HTTP transport (JSON-RPC 2.0) with SSE support
- Weighted scoring engine aligned with BLACKVEIL scanner (50 checks, 8 categories)
- Email authentication bonus (up to 5 points) when SPF + DKIM + DMARC all pass
- DNS-over-HTTPS via Cloudflare DoH — no direct DNS resolution
- KV-backed per-IP rate limiting (10 req/min, 100 req/hr) with in-memory fallback
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
- 245+ tests with ~95% line coverage
- CI/CD via GitHub Actions (test on PR, auto-deploy on push to main)
- Smithery marketplace manifest
- CLAUDE.md agent documentation

### Security

- IP sourcing uses only `cf-connecting-ip` — never `x-forwarded-for`
- Auth uses constant-time XOR comparison to prevent timing side-channel attacks
