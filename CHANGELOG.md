# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [2.7.0] - 2026-04-14

### Added
- **7 new intelligence tools** inspired by [mclose/dns-mcp](https://github.com/mclose/dns-mcp), adapted for Cloudflare Workers:
  - `check_rbl` — Check MX server IP reputation against 8 DNS-based Real-time Blocklists (Spamhaus ZEN, SpamCop, UCEProtect L1/L2, Mailspike, Barracuda, PSBL, SORBS)
  - `check_dbl` — Check domain reputation against Spamhaus DBL, URIBL, and SURBL with bitmask return code decoding
  - `cymru_asn` — Map domain IPs to Autonomous System Numbers via Team Cymru DNS service with high-risk ASN flagging
  - `rdap_lookup` — Fetch domain registration data via RDAP (modern WHOIS) with IANA bootstrap, domain age calculation, and newly-registered domain detection
  - `check_fast_flux` — Detect fast-flux DNS behavior via multi-round DoH queries comparing IP rotation and TTLs
  - `check_dnssec_chain` — Walk the DNSSEC chain of trust from root to target domain, reporting DS/DNSKEY linkage and algorithm strength at each zone level
  - `check_nsec_walkability` — Assess zone walkability risk by analyzing NSEC3PARAM configuration (iterations, salt, opt-out)
- **Shared IP utilities** (`src/lib/ip-utils.ts`) — IPv4/IPv6 reversal and private IP detection for RBL/ASN lookups
- **NSEC3PARAM record type** (type 51) added to DoH query layer
- **Explanation templates** for all 7 new tool categories in `explain_finding`

### Fixed
- **CI `contract` job** — replaced hardcoded `/Users/adam/.cargo/bin/wasm-pack` path with PATH-resolved `wasm-pack` in `build:wasm` script, fixing CI failures across all PRs

## [2.6.7] - 2026-04-10

### Added
- **Score Stability layers** — three targeted mitigations for transient upstream variance that was causing repeat scans of the same domain to occasionally return different scores:
  - **DNSSEC AD flag confirmation probe** (`src/tools/check-dnssec.ts`): when the primary Cloudflare resolver reports "DNSSEC validation failing" (AD=false with DNSKEY+DS records present), a confirmation query is fired to Google DoH. If Google confirms AD=true, the check re-runs with the corrected flag. Resolves the observed edge-node flapping between score 100 (passing) and 75 (failing) on the same domain.
  - **HTTP security dual-fetch with header union** (`src/tools/check-http-security.ts`): two parallel HEAD requests are fired per domain and the 8 browser security headers are merged using union semantics before analysis. Eliminates score variance from CDN edge nodes returning different header sets within a single request.
  - **Transient zero retry in `scanDomain()`** (`src/tools/scan-domain.ts`): any check that returns `checkStatus='error'` with `score=0` (a thrown DNS or HTTPS exception caught by `safeCheck()`) is retried once with a fresh DNS query cache. Max 3 retries per scan, capped at 3 seconds of the 12-second scan budget, 2.5s per-retry timeout. Eliminates the worst-case multi-check zero-out swings (observed Δ52 on keenetic.io, Δ30 on vkuserphoto.ru, Δ20 on reddit.com pre-fix).
- **`scripts/chaos/score-stability-test.py`** — parameterized chaos test for measuring cross-request score stability. Scans N domains across R rounds with `force_refresh` and compares scores category-by-category. Supports loading domains from Tranco JSON files via `--from`. Measured stability: 0% drift at 20 domains, ~5% at 100 domains, ~6.5% at 200 domains (all at concurrency=3).
- **Score Stability section in `docs/scoring.md`** — documents per-request determinism, cross-request variance sources, the three mitigation layers, observed drift rates, and remaining variance sources for users who need consistent scoring.

### Fixed
- **`degradedStatuses` cleanup on successful retry**: when a retry recovers a previously-errored check, its category is now removed from the `degradedStatuses` map so post-processing does not re-apply the zero score to the recovered result.

## [2.1.20] - 2026-04-01

### Added
- **Authentication Hardening** — added `REQUIRE_AUTH` toggle to strictly enforce API key usage. When enabled, the server rejects all unauthenticated requests with 401 Unauthorized, providing a "private mode" for sensitive deployments.
- **Freemium Quota Visibility** — anonymous users now receive `x-quota-tier: free` and other quota-tracking headers in tool responses, aligning the developer experience for free and paid tiers.
- **Enhanced Permission Mapping** — refactored the Wasm policy engine to use an explicit tool-to-mode mapping for all 27+ tools, replacing pattern-based matching with strict architectural enforcement.

### Fixed
- **Git Secret Hygiene** — added `UNLIMITED_KEY_DO_NOT_COMMIT.txt` and `.mcp.json` to `.gitignore` to prevent accidental leakage of sensitive local configuration and master keys.

## [2.1.19] - 2026-04-01

### Added
- **Generic Scoring Engine** — ported core architectural logic from `claude-code-py` for cross-language consistency. The engine is now decoupled from concrete DNS checks, using string-keyed categories and a three-tier pure functional formula.
- **WASM Policy Engine** — integrated `bv-wasm-core` for high-performance, tamper-resistant permission checks and token estimation.
- **Modernized Documentation** — completely rewritten README.md, CLAUDE.md, and scoring docs to reflect the new architecture and client-aware formatting.

### Fixed
- **Session revival race condition** — hardened tombstone logic in both memory and KV stores to prevent terminated sessions from being incorrectly revived after a DELETE request.

## [2.1.18] - 2026-04-01

### Added
- **`scripts/chaos/chaos-test-clients.py`** — comprehensive chaos test covering all 9 detected MCP client types
 (`claude_code`, `cursor`, `vscode`, `claude_desktop`, `windsurf`, `mcp_remote`, `blackveil_dns_action`, `bv_claude_dns_proxy`, `unknown`). 56 assertions across 10 sections: session lifecycle per client, format auto-detection (interactive → compact / non-interactive → full), explicit format override, `api_key` query param auth, Bearer vs `api_key` precedence, 9-client concurrent burst, legacy SSE per UA, session edge cases (missing, revival, tombstone, malformed), protocol guards (Content-Type, body size, GET without Accept), and batch JSON-RPC.

## [2.1.17] - 2026-04-01

### Changed
- CLAUDE.md: documented `?api_key=` query param auth, SPF `~all` soft-fail downgrade rule, and Smithery listing/configSchema integration.

## [2.1.16] - 2026-04-01

### Changed
- Documentation: updated Claude Code API key setup to use `?api_key=` query parameter as primary method; added Smithery connection instructions; updated test count.

## [2.1.15] - 2026-04-01

### Added
- **`api_key` query parameter auth** — bearer token can now be passed as `?api_key=` in the URL, enabling auth for clients that only support URL configuration (Smithery, URL-only MCP configs). Header takes precedence when both are present.
- **MCP tool annotations** — every tool definition now includes `group` (`email_auth` | `infrastructure` | `brand_threats` | `dns_hygiene` | `intelligence` | `remediation` | `meta`), `tier` (`core` | `protective` | `hardening`), and `scanIncluded` flag. Fields are included in `tools/list` responses and backward-compatible.
- **npm package exports** — `McpTool`, `TOOLS`, and `TOOL_SCHEMA_MAP` now exported from `blackveil-dns` for consumers who need the tool definitions at build time.
- **Smithery configSchema** — `smithery.yaml` now declares the `apiKey` parameter with `x-to: {query: api_key}` for seamless Smithery Connect integration.

### Fixed
- **SPF `~all` soft-fail downgraded when DMARC enforces** — SPF soft-fail (`~all`) findings are now lowered to `info` severity when the domain has an enforcing DMARC policy (`p=quarantine` or `p=reject`). The RFC-recommended `~all` posture was being incorrectly flagged as a risk in deployments where DMARC already prevents spoofing.
- **DMARC `pct` parameter parsed correctly** — `pct=<100` is now parsed from DMARC records when checking SPF enforcement context. Previously the `pct` check was missed on records that include the percentage tag.

### Changed
- **CI publishes `@blackveil/dns-checks` sub-package** — the `publish.yml` release workflow now publishes `packages/dns-checks` to npm alongside the root package on every version tag.

## [2.1.0] - 2026-03-30

### Added
- **`map_supply_chain`** — Map third-party service dependencies from DNS records. Correlates SPF includes, NS delegates, TXT verifications (39 SaaS patterns), SRV services, and CAA issuers into a unified dependency graph with trust level classification and risk signals (stale integrations, shadow services, insecure protocols, security tooling exposure)
- **`analyze_drift`** — Compare current security posture against a previous baseline; classifies drift as improving/stable/regressing/mixed with per-category deltas
- **`validate_fix`** — Re-check a specific control after applying a fix; returns fixed/partial/not_fixed verdict with propagation hints
- **`generate_rollout_plan`** — Generate phased DMARC enforcement timeline with exact DNS records per phase (aggressive/standard/conservative timelines)
- **`resolve_spf_chain`** — Recursively resolve the full SPF include chain with tree visualization, DNS lookup counting against RFC 7208 10-lookup limit, and detection of circular includes, void lookups, and redundant paths
- **`discover_subdomains`** — Discover subdomains via Certificate Transparency logs. Uses `bv-certstream-worker` service binding for cached data with crt.sh fallback. Detects shadow IT, expired services, wildcard exposure, and multi-CA sprawl
- **`map_compliance`** — Map scan findings to compliance frameworks: NIST 800-177, PCI DSS 4.0, SOC 2 Trust Services Criteria, CIS Controls v8. Shows pass/fail/partial status per control with related findings
- **`simulate_attack_paths`** — Analyze current DNS posture and enumerate 9 specific attack paths (email spoofing, subdomain takeover, DNS hijack, TLS stripping, XSS, clickjacking, cert misissuance, DKIM key compromise) with severity, feasibility, steps, and mitigations
- **Provider-aware fix plans** — `generate_fix_plan` now detects Google Workspace, Microsoft 365, Cloudflare, AWS, and 9 other providers to emit exact step-by-step console instructions with dependency-aware ordering
- Provider knowledge base (`provider-guides.ts`) — extensible static map of 13 provider detection signals and fix guides
- TXT hygiene analysis module (`txt-hygiene-analysis.ts`) — shared constants for 39 SaaS verification patterns and SPF cross-reference data

### Fixed
- Domain validation errors for IP addresses and label length now surface descriptive messages instead of generic "An unexpected error occurred"
- crt.sh queries now use `&exclude=expired` to prevent HTTP 503 on popular domains with large certificate histories

### Changed
- Tool count: 33 → 41 (8 new tools)

## [2.0.11] - 2026-03-28

### Fixed

- **HTTP security headers false negatives on redirecting domains.** `checkHTTPSecurity` used `redirect: 'manual'` without following redirects, causing it to analyze headers on 301/302 responses instead of the final destination. Domains like `nist.gov` (which 301s to `www.nist.gov`) were incorrectly reported as missing CSP, X-Frame-Options, and other headers that the final destination actually serves. Added `followRedirects()` to traverse up to 3 hops, including Cloudflare Workers opaque redirect responses (status 0).
- **2048-bit RSA DKIM keys incorrectly flagged as "below recommended."** `analyzeKeyStrength` in `dkim-analysis.ts` classified all keys with < 550 base64 chars as `strength: 'medium'`, which mapped to a "Below recommended RSA key" finding. A standard 2048-bit RSA key is ~392 chars and falls in this range. Split the threshold so keys below ~380 chars (sub-2048-bit) remain `'medium'`, while actual 2048-bit keys (380-549 chars) are classified as `'info'` — meeting the current minimum standard.

## [2.0.10] - 2026-03-27

### Security

- Hardened release baseline with incremental security safeguards and validation cleanups.

### Documentation

- Refined release documentation and metadata notes for clearer operator guidance.

## [2.0.9] - 2026-03-27

### Added

- MCP tool metadata: every tool definition in `tool-schemas.ts` now includes `group` (`email_auth` | `infrastructure` | `brand_threats` | `dns_hygiene` | `intelligence` | `remediation` | `meta`), `tier` (`core` | `protective` | `hardening`, omitted for non-scoring tools), and `scanIncluded` (boolean indicating participation in `scan_domain` parallel orchestration). Fields are included in `tools/list` responses and are backward-compatible — older clients ignore them.
- New exported types `ToolGroup` and `ToolTier` in `tool-schemas.ts`.
- `test/tool-schemas.spec.ts`: 10-test suite validating metadata completeness, type validity, and scan-inclusion consistency for all 33 tools.

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

- Service binding URL path corrected for tier-auth validation endpoint.
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
