# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [2.0.8] - 2026-03-27

### Security

- `BV_API_KEY` static fallback comparison in `tier-auth.ts` changed from `===` (timing-unsafe) to SHA-256 hash comparison (constant-time). Primary auth paths (KV cache, service binding) were already safe.

### Fixed

- README license badge updated from MIT to BUSL-1.1 to match actual license.
- README test count updated from 800+ to 1090+, coverage from ~95% to ~90%.
- README tools table updated from 15 to 22 tools, coverage table from 13 to 20 categories.
- Broken documentation links removed (`docs/coverage.md`, `docs/security-and-observability.md`).
- MCP resource content (`resources.ts`) updated from 50 checks / 10 categories to 57+ checks / 20 categories.
- CONTRIBUTING.md test count updated.
- SUPPORT.md broken link to non-existent `docs/coverage.md` removed.

## [2.0.3] - 2026-03-25

### Fixed

- **Scoring: missing controls no longer pass security checks.** `buildCheckResult` now sets `passed = false` when findings indicate a missing security control — via `scoreIndicatesMissingControl()` (critical/high severity + deterministic/verified confidence) or explicit `missingControl: true` metadata. Previously, a domain with no SPF record (critical, -40) still scored 60/100 and passed.
- **Scoring: hardening tier uses `result.passed` instead of raw score.** The hardening tier bonus calculation now respects the `passed` flag from `buildCheckResult` rather than checking `score >= 50` directly. This prevents checks with absent controls (BIMI, DANE, TLS-RPT) from contributing hardening bonus points.
- **BIMI: validates DMARC enforcement when record exists.** BIMI check now queries DMARC policy regardless of whether a BIMI record is present. When DMARC is not enforcing (p=none), BIMI scores as failed with a medium-severity finding, since mail clients will not display the logo. Previously, a valid BIMI record with DMARC p=none scored 100/100.
- **BIMI/DANE/TLS-RPT: "not found" findings carry `missingControl: true` metadata.** Ensures these hardening-tier checks do not pass when their underlying control is absent, even though their severity (info/low/medium) is below the confidence-gate threshold in `scoreIndicatesMissingControl()`.
- `scoreIndicatesMissingControl()` moved from `scoring/engine.ts` to `scoring/model.ts` to allow `buildCheckResult` to use it without circular dependencies. Re-exported from engine for backward compatibility.

## [1.5.0] - 2026-03-18

### Added

- **MCP prompts support**: agent-led growth optimizations for MCP discoverability.
- **Tier-based rate limiting**: API key authentication resolves to tiers (free, agent, developer, enterprise) with per-tier daily quotas via Durable Objects.
- **Analytics observability**: MCP client detection from user-agent, country/client/tier context threading, session lifecycle events, SQL query builders for Analytics Engine, webhook alerting for Slack/Discord, cron-based alerting.
- **Performance**: scan-scoped DNS query cache to deduplicate redundant queries, batched sensitive subdomain probes (max concurrency 5), increased adaptive weight fetch timeout (50ms → 200ms).

### Fixed

- Service binding URL path corrected from `/internal/validate-key` to `/internal/validate-key`.
- Tier-auth debug logging removed; `Headers.entries()` TypeScript error fixed.
- Rate-limit test updated to expect tier-based quota headers for authenticated requests.

## [1.4.0] - 2026-03-17

### Added

- **5 new MCP tools** (17 → 22 total):
  - `check_http_security`: HTTP security header audit (CSP, X-Frame-Options, COOP, CORP, Permissions-Policy, Referrer-Policy, X-Content-Type-Options).
  - `check_dane`: DANE/TLSA record validation for MX and HTTPS certificate pinning.
  - `check_mx_reputation`: Mail server DNSBL lookup and PTR/FCrDNS validation.
  - `check_srv`: SRV record discovery for email, calendar, messaging, and other services.
  - `check_zone_hygiene`: SOA serial consistency and sensitive subdomain exposure detection.
- `scan_domain` now runs **14 checks** in parallel (was 12), adding HTTP Security and DANE.
- DNS library additions: PTR and SRV query helpers, TLSA record parser.

### Changed

- License changed from MIT to Business Source License 1.1 (BUSL-1.1).
- Test SPDX headers updated to BUSL-1.1.

### Security

- Error output sanitized and IPv4 validation added for new tools.
- Undici CVEs patched via npm override (7.18.2 → 7.24.4).

## [1.3.0] - 2026-03-15

### Added

- **2 new MCP tools** (15 → 17 total):
  - `check_shadow_domains`: Alternate-TLD variant discovery with email spoofing risk assessment.
  - `check_txt_hygiene`: TXT record audit for stale verifications, SaaS exposure, and cross-domain trust.
- Public-suffix library for brand name extraction.
- Shadow domains and TXT hygiene added to `CheckCategory` scoring system.
- Pre-commit hook to block committing sensitive directory paths.

### Changed

- Two-phase DNS probing for `check_lookalikes` and `check_shadow_domains`: Phase 1 NS existence filter reduces unnecessary queries.

### Fixed

- MCP session recovery after expiry for Claude Desktop.
- Lookalike variant generation dot mismatch and TXT hygiene DNS failure handling.

### Security

- Defense-in-depth hardening from DevSecOps review.

## [1.2.0] - 2026-03-13

### Added

- **Universal MCP transport support**: three first-party transports — Streamable HTTP, native stdio, and legacy HTTP+SSE — all driven by a single shared executor.
- **Shared MCP executor** (`src/mcp/execute.ts`): transport-neutral request processing layer (validation, rate limiting, session management, dispatch, analytics) consumed by all transports.
- **Native stdio transport** (`src/stdio.ts`): first-party `blackveil-dns-mcp` CLI binary for local-only MCP clients (Claude Desktop, etc.) via the `blackveil-dns` npm package.
- **Legacy HTTP+SSE compatibility**: `GET /mcp/sse` bootstrap stream and `POST /mcp/messages?sessionId=...` message endpoint for older MCP clients that have not migrated to Streamable HTTP.
- **JSON-RPC batch request support**: `POST /mcp` accepts JSON arrays of requests, returning a JSON array of responses (non-streaming) per the JSON-RPC 2.0 specification.
- Legacy SSE stream management module (`src/lib/legacy-sse.ts`) with heartbeat keepalive and graceful cleanup.
- `SERVER_VERSION` single source of truth (`src/lib/server-version.ts`) used by all transports.
- Comprehensive tests for batch requests (4 cases), stdio transport (5 cases), and legacy HTTP+SSE (2 cases).

### Changed

- `src/index.ts` refactored from monolithic transport handler into a thin HTTP adapter delegating to the shared executor.
- `src/mcp/dispatch.ts` now accepts `createSessionOnInitialize` and `existingSessionId` options for transport-specific session semantics.
- `src/mcp/request.ts` batch parsing: non-empty JSON arrays now succeed as `isBatch: true` instead of being rejected.
- `tsup.config.ts` emits a second `stdio` entry point alongside the existing `index` entry.
- `package.json` adds `bin` field (`blackveil-dns-mcp`), `exports.stdio` sub-path, and `mcp:stdio` script.
- `GET /mcp` now strictly requires `Mcp-Session-Id` header (returns 400 without it) — legacy SSE bootstrap moved to dedicated `/mcp/sse`.
- `DELETE /mcp` accepts session ID from both `Mcp-Session-Id` header and `?sessionId=` query parameter for cross-transport compatibility.

### Fixed

- Empty JSON-RPC batch arrays now correctly return a JSON-RPC error (-32600 Invalid Request) instead of being silently rejected.

## [1.1.0] - 2026-03-13

### Changed

- MX IP-target and DNS-query-failure findings downgraded from `high` to `medium` to match MX zero-importance scoring weight.
- `MX_HIGH` explanation entry severity updated to `medium` for consistency.
- `check_spf` now treats shared-platform SPF trust-surface findings as informational by default and only elevates them when weak DMARC enforcement and relaxed alignment corroborate the exposure.
- Free-tier daily quotas raised: `scan_domain` 25 → 75/day, `check_lookalikes` 10 → 20/day, `compare_baseline` 100 → 150/day per IP.

### Added

- Context-aware scoring profiles for `scan_domain`: five named profiles (`mail_enabled`, `enterprise_mail`, `non_mail`, `web_only`, `minimal`) that adapt importance weights based on detected domain purpose. Phase 1: auto-detection runs and is reported in the structured result (`scoringProfile`, `scoringSignals`), but only explicit `profile` parameter values activate different weights. New types `DomainProfile` and `DomainContext` exported from the public package API.
- `scan_domain` now returns a second content block containing machine-readable structured JSON (`score`, `grade`, `passed`, `maturityStage`, `maturityLabel`, `categoryScores`, `findingCounts`, `timestamp`, `cached`) wrapped in `<!-- STRUCTURED_RESULT -->` delimiters. CI/CD consumers can parse this reliably instead of regex-matching the text report.
- `buildStructuredScanResult()` and `StructuredScanResult` type exported from `src/tools/scan/format-report.ts` and the public package API.
- Publishable ESM npm package metadata, bundled public API entrypoint, and `prepack` build flow for consuming the scanner core as `blackveil-dns`.
- Public package exports for reusable scanner functions (`scanDomain`, `check*`, `explainFinding`, scoring helpers, validation helpers) without exposing Worker transport internals.
- Package API regression coverage in `test/package-api.spec.ts`.
- Private deployment override workflow via `wrangler.private.example.jsonc`, ignored `.dev/wrangler.deploy.jsonc`, and `npm run deploy:private` so real Cloudflare KV and Analytics bindings stay out of the public repo.
- Regression coverage for DMARC-aware SPF trust-surface severity in `test/check-spf.spec.ts`, `test/spf-trust-surface.spec.ts`, and `test/handlers-tools.spec.ts`.
- Dangling MX detection: MX hostnames that do not resolve to A or AAAA records are flagged as `medium` severity.

### Fixed

- Profile detection now correctly handles Null MX (RFC 7505) domains as `non_mail`/`web_only` instead of `mail_enabled`.
- Profile detection now defaults to `mail_enabled` when MX DNS query fails, instead of misclassifying as `non_mail`/`web_only`.
- `scan_domain` error path now preserves explicit profile override instead of silently dropping it.
- `scan_domain` tool schema description now lists all 12 checks including BIMI and TLS-RPT.
- MCP resource documentation corrected: "50+ checks in 13 categories" (was "50 checks in 10 categories").
- README check counts corrected for BIMI (2→1), TLS-RPT (2→1), Lookalikes (3→1).
- Scoring documentation (CLAUDE.md, docs/scoring.md, resources.ts) updated to reflect actual importance weights (Subdomain Takeover=3, NS=0, CAA=0) and added scoring profile documentation.
- Critical penalty documentation updated to reflect verified-confidence-only condition introduced in v1.0.3.
- Source file references in docs/scoring.md updated from barrel re-export to actual implementation files.
- Merged duplicate `### Added` section in CHANGELOG v1.0.3 entry.

## [1.0.3] - 2026-03-07

### Changed

- `check_subdomain_takeover` now reports unresolved third-party CNAME takeover signals as `high` (potential) instead of `critical`.
- Global scan critical penalty now applies only when at least one `critical` finding is confidence-qualified as `verified`.
- `check_dkim` now consolidates duplicate selector-probe key-strength findings across selectors to reduce repeated scoring penalties for identical key profiles.

### Added

- Regression coverage for takeover potential-severity behavior in `test/check-subdomain-takeover.spec.ts`.
- Regression coverage for verified-critical global penalty behavior in `test/scoring.spec.ts`.
- Regression coverage for DKIM duplicate key-strength consolidation in `test/check-dkim.spec.ts`.
- Cloudflare Analytics Engine dataset binding support (`MCP_ANALYTICS`) for request and tool usage telemetry.
- `/health` response now includes analytics runtime status (`analytics.enabled`) for operational verification.

### Fixed

- Analytics Engine payload schema now uses a single index per data point to match platform limits and prevent `writeDataPoint(): Maximum of 1 indexes supported` warnings.
- Reduced in-isolate KV rate limiter race amplification by serializing per-IP `get/check/put` updates.
- Added unauthenticated session-creation throttling (`30/min` per IP) for `initialize` and new SSE session bootstrap.
- Bounded in-memory session fallback with LRU eviction (`2000` max active sessions) to reduce memory-pressure abuse risk.
- Domain validation now rejects IPv4 literals across standard and alternate numeric forms (short-form, octal, hex, dword), including public-IP and dotted-numeric payloads (for example `8.8.8.8`, `0x8.0x8.0x8.0x8`, and `999.999.999.999`).

### Changed

- `check_subdomain_takeover` now runs known subdomain probe flow in parallel to reduce worst-case `scan_domain` latency.
- Provider signature loading now uses a short-lived in-isolate cache (5 minutes) when `PROVIDER_SIGNATURES_URL` is configured.
- `check_spf` now performs RFC-aware DNS lookup budget analysis with explicit near-limit signaling at 9/10 lookups.
- `check_dkim` now probes an expanded set of common provider selectors (`selector`, `s1024`, `s2048`, `amazonses`, `mandrill`, `mailjet`, `zoho`) for better detection depth.
- `check_dkim` now validates RSA key strength using base64 length heuristic (512/1024/2048/4096-bit detection) with critical/high/medium severity based on estimated bits.
- `check_dkim` now validates presence of `v=DKIM1` tag (medium severity if missing).
- `check_dmarc` now validates `sp` strictness against parent `p` policy, validates `fo` options, and validates `pct` range handling.
- `check_dmarc` now validates `rua=` and `ruf=` URI formats (must use `mailto:` scheme with valid email).
- `check_dmarc` now checks `adkim=` and `aspf=` alignment modes with low-severity warnings for relaxed alignment (default).
- `check_dmarc` "properly configured" info finding now displays even with low-severity alignment warnings.

### Added

- Provider signature cache behavior tests in `test/provider-signatures.spec.ts`.
- A dedicated `scan_domain` latency troubleshooting section in `docs/troubleshooting.md`.
- SPF regression test for lookup-budget near-limit warning behavior in `test/check-spf.spec.ts`.
- DMARC regression tests for `sp` downgrade detection, `fo` validation, and invalid `pct` handling in `test/check-dmarc.spec.ts`.
- DKIM RSA key strength validation tests covering all severity levels (critical, high, medium, info) in `test/check-dkim.spec.ts`.
- DKIM `v=` tag validation test in `test/check-dkim.spec.ts`.
- DMARC URI validation tests for `rua=` and `ruf=` tags in `test/check-dmarc.spec.ts`.
- DMARC third-party aggregator detection (dmarcian, valimail, agari, returnpath, postmarkapp, dmarcanalyzer, mimecast, proofpoint, 250ok, easydmarc).
- DMARC alignment mode validation tests for `adkim=` and `aspf=` tags in `test/check-dmarc.spec.ts`.
- 18 new DMARC test cases and 5 new DKIM test cases.
- Rate limiter regression test for concurrent KV requests (`test/rate-limiter.spec.ts`).
- Session creation limiter tests in `test/session.spec.ts`.
- Initialize throttling integration test in `test/index.spec.ts`.
- `tools/call` alias support for `scan` -> `scan_domain`.
- Alias coverage tests in `test/handlers-tools.spec.ts` and `test/index.spec.ts`.
- Domain-validation regressions for alternate IPv4 host literals in `test/sanitize.spec.ts`.
- `tools/call` integration coverage for short-form and octal loopback rejection in `test/index.spec.ts`.

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
- Email authentication bonus (up to 8 points) when SPF + DKIM + DMARC all pass
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
