# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is this?

Blackveil DNS — open-source DNS & email security scanner, built as a Cloudflare Worker.
Exposes 33 tools via MCP Streamable HTTP (JSON-RPC 2.0) at `https://dns-mcp.blackveilsecurity.com/mcp`.
An additional check (`check_subdomain_takeover`) runs only inside `scan_domain` and is not directly callable by clients.

**Version**: 2.0.4 — keep `SERVER_VERSION` in `src/lib/server-version.ts` and `version` in `package.json` in sync.

## Commands

```bash
npm install                            # Install deps (includes workspace packages)
npm test                               # Vitest + Istanbul coverage (Workers runtime)
npx vitest run test/check-spf.spec.ts  # Run a single test file
npm run build                          # tsup build (npm package + stdio CLI bundle)
npm run dev                            # Local dev at localhost:8787
npm run typecheck                      # tsc --noEmit
npm run lint                           # ESLint
npm run lint:fix                       # ESLint with auto-fix
git config core.hooksPath .githooks    # Enable pre-commit hooks (one-time setup)
```

## Tech

- **Runtime**: Cloudflare Workers — no Node.js APIs (only `fetch`, `crypto`, Web APIs)
- **Framework**: Hono v4
- **TypeScript**: strict, ES2024 target, Bundler resolution, `isolatedModules: true`
- **Testing**: Vitest + `@cloudflare/vitest-pool-workers` (tests execute inside Workers runtime)
- **Linter**: ESLint + typescript-eslint
- **Formatter**: Prettier (tabs, single quotes, semi, 140 width)
- **Package manager**: npm

## Architecture

### Monorepo structure

This is an npm workspace monorepo. The root is a Cloudflare Worker; `packages/dns-checks` (`@blackveil/dns-checks`) is a separately publishable runtime-agnostic package exporting check implementations and scoring logic for non-Worker consumers.

**Entrypoint distinction**: `src/index.ts` is the Cloudflare Worker entrypoint (Hono app). `src/package.ts` is the npm package entrypoint (built by tsup → `dist/index.js`). The tsup build also bundles `src/stdio.ts` → `dist/stdio.js` with a `cloudflare:workers` shim plugin so it can run in Node.js.

```bash
# Workspace commands
npm -w packages/dns-checks run build      # Build sub-package
npm -w packages/dns-checks run test       # Test sub-package
npm -w packages/dns-checks run typecheck  # Typecheck sub-package
```

### Source layout

```
src/index.ts              — Hono app, HTTP routes, middleware wiring (delegates to shared executor)
src/package.ts            — npm package entrypoint (re-exports for non-Worker consumers)
src/internal.ts           — Internal service binding routes (direct tool access, no MCP overhead)
src/stdio.ts              — Native stdio MCP transport (CLI entrypoint: blackveil-dns-mcp)
src/scheduled.ts          — Cron Trigger handler for analytics alerting (queries Analytics Engine SQL API)

src/mcp/execute.ts        — Transport-neutral shared MCP request executor (validation, rate limiting, dispatch, analytics)
src/mcp/dispatch.ts       — JSON-RPC method → handler routing (initialize, tools/*, resources/*, prompts/*, ping)
src/mcp/request.ts        — Request body reading, JSON-RPC parsing/validation (batch support), header normalization, Content-Type validation
src/mcp/route-gates.ts    — Pre-dispatch guards (rate limits, session validation)

src/handlers/tools.ts     — tools/list + tools/call dispatch
src/handlers/tool-schemas.ts — TOOLS array (MCP tool definitions)
src/handlers/tool-args.ts — Domain/argument extraction and validation (extractRecordType, extractIncludeProviders, extractMxHosts)
src/handlers/tool-formatters.ts — mcpError/mcpText/formatCheckResult helpers
src/handlers/tool-execution.ts — Tool logging helpers
src/handlers/resources.ts — resources/list + resources/read (static docs)
src/handlers/prompts.ts   — prompts/list + prompts/get (pre-built agent workflows)

src/tools/check-*.ts      — Individual DNS checks (SPF, DMARC, DKIM, MX, SSL, BIMI, TLS-RPT, lookalikes, shadow domains, TXT hygiene, HTTP security, DANE, MX reputation, SRV, zone hygiene)
src/tools/*-analysis.ts   — Analysis helpers extracted from check modules
src/tools/spf-trust-surface.ts — SPF trust surface analysis (multi-tenant SaaS platform detection)
src/tools/lookalike-analysis.ts — Lookalike/typosquat domain permutation generator
src/tools/scan-domain.ts  — Parallel orchestrator for all checks → ScanScore + MaturityStage
src/tools/scan/           — Scan sub-helpers (format-report.ts, post-processing.ts, maturity-staging.ts)
src/tools/check-shadow-domains.ts — Shadow domain TLD variant discovery and email auth risk classification
src/tools/check-txt-hygiene.ts — TXT record hygiene auditing and platform exposure mapping
src/tools/check-http-security.ts — HTTP security header analysis (CSP, X-Frame-Options, Permissions-Policy, etc.)
src/tools/check-dane.ts   — DANE/TLSA certificate verification for MX and HTTPS
src/tools/check-mx-reputation.ts — Mail server DNSBL & PTR/FCrDNS validation
src/tools/check-srv.ts    — SRV service discovery audit
src/tools/check-zone-hygiene.ts — Zone consistency (SOA) & sensitive subdomain detection
src/tools/explain-finding.ts — Static explanation generator

src/lib/scoring.ts        — Re-export facade for scoring subsystem
src/lib/scoring-config.ts — Runtime scoring configuration (ScoringConfig type, defaults, parser)
src/lib/scoring-model.ts  — Types (Finding, CheckResult, ScanScore, CheckCategory, Severity) + buildCheckResult/createFinding
src/lib/scoring-engine.ts — IMPORTANCE_WEIGHTS, computeScanScore, scoreToGrade
src/lib/context-profiles.ts — DomainProfile, DomainContext, PROFILE_WEIGHTS, detectDomainContext
src/lib/adaptive-weights.ts — EMA-based adaptive weight computation, blending, bounds
src/lib/profile-accumulator.ts — Durable Object for per-profile telemetry aggregation (SQLite-backed)
src/lib/json-rpc.ts       — JSON-RPC 2.0 types, error codes, response builders
src/lib/session.ts        — KV-backed (optional) + in-memory session management with dual-write (create writes both, validate checks in-memory first)
src/lib/auth.ts           — Bearer token validation (constant-time XOR comparison)
src/lib/sse.ts            — SSE event formatting and Accept header checking
src/lib/legacy-sse.ts     — Legacy HTTP+SSE stream lifecycle (open, enqueue, close, heartbeat)
src/lib/server-version.ts — Single source of truth for SERVER_VERSION
src/lib/dns.ts            — DNS-over-HTTPS facade (re-exports from dns-transport, dns-records, dns-types); queryTxtRecords concatenates multi-string values per RFC 7208 §3.3 and iteratively unescapes RFC 1035 §5.1 backslash sequences (max 2 passes; handles DoH providers that double-escape). Primary: Cloudflare DoH; secondary confirmation: bv-dns (configurable via BV_DOH_ENDPOINT env var) → Google DoH fallback
src/lib/sanitize.ts       — Domain validation, SSRF protection
src/lib/config.ts         — Centralized SSRF constants, DNS tuning, rate limit quotas (FREE_TOOL_DAILY_LIMITS, GLOBAL_DAILY_TOOL_LIMIT, TIER_DAILY_LIMITS, TIER_TOOL_DAILY_LIMITS, McpApiKeyTier)
src/lib/cache.ts          — KV-backed + in-memory TTL cache, INFLIGHT dedup map, cacheSetDeferred()
src/lib/rate-limiter.ts   — KV-backed + in-memory per-IP rate limiting (delegates to rate-limiter-memory.ts); exports `withIpKvLock()` for intra-isolate KV counter serialization
src/lib/quota-coordinator.ts — Durable Objects-based distributed rate limiting across isolates
src/lib/analytics.ts      — Cloudflare Analytics Engine integration (fail-open telemetry, 4 event types); `domainFingerprint()` for stable aggregate grouping (FNV-1a, not a privacy control)
src/lib/analytics-queries.ts — Pre-built SQL queries for Analytics Engine metrics
src/lib/alerting.ts       — Webhook alerting for Slack/Discord (fail-open delivery, HTTPS-only validation)
src/lib/client-detection.ts — MCP client type detection from User-Agent headers
src/lib/badge.ts          — SVG badge generator for /badge/:domain endpoint
src/lib/audit.ts          — Audit logging
src/lib/output-sanitize.ts — Markdown/HTML syntax sanitization for text output + `sanitizeDnsData()` for finding detail ingestion
src/lib/provider-signatures.ts — Email provider database and MX pattern matching
src/lib/provider-signature-source.ts — Runtime provider signature fetching/validation
src/lib/public-suffix.ts  — Curated PSL subset for brand name extraction (shadow domains, TXT hygiene)
src/lib/log.ts            — Structured JSON logging (logEvent, logError)

test/                     — One spec per source file
test/helpers/dns-mock.ts  — Shared fetch mock for DNS-over-HTTPS queries

packages/dns-checks/     — @blackveil/dns-checks (runtime-agnostic check + scoring library)
  src/checks/            — Portable check implementations (no Worker APIs)
  src/scoring/           — Scoring engine, types, category weights
  src/__tests__/         — Sub-package tests
```

### Request flow

**Streamable HTTP** (modern):
```
MCP Client → POST /mcp → Origin check → Auth middleware → Body parse → JSON-RPC validate
  → mcp/execute.ts (shared executor: rate limit + session + dispatch + analytics)
  → handlers/tools.ts → src/tools/check-*.ts → lib/dns.ts → Cloudflare DoH
    (empty answers → bv-dns secondary → Google DoH fallback)
```

**Native stdio** (`blackveil-dns-mcp` CLI):
```
stdin (newline-delimited JSON-RPC) → src/stdio.ts → mcp/execute.ts (shared executor)
  → handlers/tools.ts → src/tools/check-*.ts → stdout (JSON-RPC responses)
```

**Legacy HTTP+SSE** (deprecated clients):
```
GET /mcp/sse → opens SSE bootstrap stream
POST /mcp/messages?sessionId=... → mcp/execute.ts → response enqueued to SSE stream
```

**Internal service binding** (Worker-to-Worker):
```
Service binding fetch → POST /internal/tools/call → guard middleware (reject public)
  → handlers/tools.ts → src/tools/check-*.ts → JSON response (no MCP framing)

Service binding fetch → POST /internal/tools/batch → guard middleware (reject public)
  → validate/sanitize domains → concurrent chunks → handlers/tools.ts per domain
  → JSON response: { results: [{domain, result, isError}], summary: {total, succeeded, failed} }
```

### scan_domain orchestration

`scan_domain` runs **16 checks** in parallel via `Promise.allSettled`: SPF, DMARC, DKIM, DNSSEC, SSL, MTA-STS, NS, CAA, BIMI, TLS-RPT, subdomain takeover, HTTP security, DANE, DANE HTTPS, SVCB HTTPS, and MX. Each has its own cache key (`cache:<domain>:check:<name>`), plus a top-level `cache:<domain>` key for the full scan result. Results are cached for 5 minutes. After scoring, `computeMaturityStage()` classifies the domain into a maturity stage (0-4: Unprotected → Hardened) based on SPF/DMARC/MTA-STS/DNSSEC presence and enforcement. Stage 3 (Enforcing) does not require DKIM. Stage 4 (Hardened) hardening signals include CAA and DKIM-discovered (in addition to BIMI/DANE/MTA-STS strict).

**Partial results on timeout**: When the 12s scan timeout fires, completed checks are preserved and missing checks receive a timeout finding. This avoids discarding work from checks that finished in 1-2s. Individual per-check timeouts are 8s. In scan context, secondary DNS confirmation (Google DNS fallback for empty results) is skipped for speed — individual checks retain it for accuracy.

**Non-mail domain adjustment**: After all checks complete, if `check_mx` finds no MX records, `scan_domain` queries the parent domain's DMARC `sp=`/`p=` tag and then calls `adjustForNonMailDomain()` to downgrade critical/high email-auth findings (SPF, DMARC, DKIM, MTA-STS) to `info` severity. This significantly affects scores for non-mail domains.

**No-send domain adjustment**: After all checks complete, if SPF has `noSendPolicy` metadata (indicating `v=spf1 -all` or `v=spf1 ~all` with no authorizing mechanisms), `applyScanPostProcessing()` calls `adjustForNoSendDomain()` to downgrade critical/high missing-record findings in DKIM, MTA-STS, and BIMI to `info` severity. This is separate from the non-mail adjustment (which triggers on missing MX). A domain can have MX records (for receiving) but still be a no-send domain.

**Structured result output**: `scan_domain` returns MCP content blocks: (1) the human-readable text report via `formatScanReport()`, and (2) for non-interactive clients only, a machine-readable JSON block via `buildStructuredScanResult()` wrapped in `<!-- STRUCTURED_RESULT ... STRUCTURED_RESULT -->` comment delimiters. The structured block is conditionally omitted for known LLM IDE clients (Claude Code, Cursor, VS Code, etc.) to reduce context consumption. CI/CD consumers (e.g., `blackveil-dns-action`) still receive it via `mcp_remote`/unknown client types or the internal batch endpoint.

### Output format control

All tools accept an optional `format` parameter (`full` | `compact`) controlling response verbosity. When omitted, the format is auto-detected from the MCP client type via `src/lib/client-detection.ts`:

- **Interactive LLM clients** (`claude_code`, `cursor`, `vscode`, `claude_desktop`, `windsurf`) → default `compact`
- **Non-interactive/unknown** (`mcp_remote`, `unknown`) → default `full`

**Compact mode** — all tool formatters respect the `format` parameter:
- **Check results** (`formatCheckResult`): Single-line findings `[SEVERITY] title — detail`, no emoji icons, no impact narratives
- **Scan report** (`formatScanReport`): Omits maturity description/nextStep, scoring profile/notes, `<!-- STRUCTURED_RESULT -->` block
- **Explain finding** (`formatExplanation`): Title + truncated explanation + recommendation only; omits impact, consequences, references
- **Fix plan** (`formatFixPlan`): One-liner actions, max 5 shown; omits dependencies, impact labels, markdown headings
- **Generated records** (`formatGeneratedRecord`): Record type/name/value + warnings; omits instructions section
- **Spoofability** (`formatSpoofability`): Single line with scores; omits summary narrative and interaction effects
- **Benchmark** (`formatBenchmark`): Summary line with mean/median + top failures + trend direction; omits ASCII chart, snapshots, freshness
- **Provider insights** (`formatProviderInsights`): Single line with score/scans/percentile; omits freshness
- **Resolver consistency** (`formatResolverConsistency`): Summary + non-info findings only; omits per-resolver answer breakdowns
- **Baseline** (`formatBaselineResult`): Terse pass/fail with violation count; omits markdown headings

**Full mode**: Original verbose output with emoji severity icons, multi-line findings, impact narratives via `resolveImpactNarrative()`, and structured JSON block.

Format resolution: `extractFormat(args)` in `tool-args.ts` → explicit parameter wins → else `resolveFormat()` in `tools.ts` auto-detects from `clientType`. The `OutputFormat` type is exported from `tool-args.ts`.

## Conventions

- `createFinding()` + `buildCheckResult()` from `lib/scoring-model.ts` (re-exported via `lib/scoring.ts`) — never construct findings manually. `createFinding()` auto-sanitizes `detail` via `sanitizeDnsData()` to prevent HTML/markdown injection from DNS-sourced data
- `validateDomain()` + `sanitizeDomain()` from `lib/sanitize.ts` for all domain inputs
- `mcpError()` / `mcpText()` from `handlers/tool-formatters.ts` for MCP response formatting
- `cacheGet()` / `cacheSet()` / `cacheSetDeferred()` from `lib/cache.ts` — supports KV and in-memory; `cacheSetDeferred()` wraps writes in `ctx.waitUntil()` to avoid blocking responses
- JSDoc (`/** */`) on exported functions
- `import type { ... }` for type-only imports
- All tool functions return `Promise<CheckResult>` (follow pattern in `check-spf.ts`) and accept an optional `dnsOptions?: QueryDnsOptions` parameter for scan-context optimizations (e.g., `skipSecondaryConfirmation`)
- `check_mx` is dynamically imported in `handlers/tools.ts` (for test mock isolation — unlike other checks which are statically imported)
- MCP server key name is `"blackveil-dns"` across all client configs (README, docs, `.mcp.json`) — keep consistent
- `tools/call` accepts `scan` as an alias for `scan_domain` — chat clients can say `scan example.com`
- SSRF config constants live in `src/lib/config.ts`, not `sanitize.ts` — edit there when modifying blocked TLDs, IP patterns, DNS tuning (`DNS_TIMEOUT_MS` 3s, `DNS_RETRIES` 1, `DNS_RETRY_BASE_DELAY_MS` 75ms, `HTTPS_TIMEOUT_MS` 4s, `DOH_EDGE_CACHE_TTL`, `INFLIGHT_CLEANUP_MS`), etc.
- `sanitize.ts` imports `punycode/` (trailing slash = npm package, not Node.js built-in) for IDN/Unicode domain support

### Error surfacing convention

Both `index.ts` and `handlers/tools.ts` sanitize errors. Only messages starting with specific prefixes pass through to clients:
- `'Missing required'`, `'Invalid'` (both files)
- `'Resource not found'` (index.ts only)
- `'Domain validation failed'` (tools.ts only)

All other errors become generic messages. New validation errors that need to reach clients **must start with one of these exact prefixes**.

**Rate limit errors**: All rate limit responses (per-IP, per-tool, per-tier, global daily, control plane) use HTTP 200 with a JSON-RPC error body (`code: -32029`), not HTTP 429. This follows the MCP spec convention where transport-level HTTP status is 200 and application-level errors are in the JSON-RPC envelope. The `retry-after` header is still set for client backoff.

## Scoring

`computeScanScore()` uses a three-tier category model. `CATEGORY_DISPLAY_WEIGHTS` exists for display/registry purposes and is unused in scoring.

### Three-Tier Category Model

Categories are classified into three tiers with distinct scoring mechanics:

**Core (70% of score)** — Controls whose absence creates direct, exploitable risk:

| Category | Weight |
|----------|--------|
| DMARC | 22 |
| DKIM | 16 |
| SPF | 10 |
| DNSSEC | 7 |
| SSL | 5 |

> Production overrides code defaults via `SCORING_CONFIG` env var in `.dev/wrangler.deploy.jsonc`. Code defaults: DMARC 16, DKIM 10, DNSSEC 8, SSL 8.

`scoreIndicatesMissingControl()` applies within Core but only for `deterministic`/`verified` confidence findings (confidence gate).

**Protective (20% of score)** — Active defenses against known attack vectors:

| Category | Weight |
|----------|--------|
| Subdomain Takeover | 4 |
| HTTP Security | 3 |
| MTA-STS | 3 |
| MX | 2 |
| CAA | 2 |
| NS | 2 |
| Lookalikes | 2 |
| Shadow Domains | 2 |

**Hardening (10% of score)** — Bonus-only defense-in-depth: DANE, BIMI, TLS-RPT, TXT Hygiene, MX Reputation, SRV, Zone Hygiene. Each passed category adds ~1.4 points. Never subtracts.

**Email bonus**: SPF score >= 57, DKIM not deterministically missing, DMARC present → DMARC >= 90: +5pts, >= 70: +3pts, else: +2pts.

**SPF trust-surface scoring**: Shared-platform SPF findings (e.g., Google Workspace, SendGrid) are informational by default. They are elevated to `medium`/`high` only when weak DMARC enforcement or relaxed alignment corroborates the exposure.

**Confidence gate**: `scoreIndicatesMissingControl()` only fires for `deterministic`/`verified` confidence findings. Heuristic DKIM "not found" (selector probing) no longer zeros the category.

**Provider-informed DKIM**: When a known DKIM-signing provider is detected (via MX/SPF) but selector probing finds nothing, the HIGH finding is downgraded to MEDIUM. Provider context is applied as a post-processing step after parallel checks complete.

**Per-finding severity penalties**: Critical −40, High −25, Medium −15, Low −5, Info 0.

**`passed` flag**: `score >= 50 && !hasMissingControl` in `buildCheckResult`. A check fails if the score is below 50, if `scoreIndicatesMissingControl()` detects a missing control (critical/high + deterministic/verified confidence), or if any finding carries explicit `missingControl: true` metadata. When `hasMissingControl` is true, score is zeroed (`hasMissingControl ? 0 : score`); penalty-based failures (score < 50 without missing control) retain their numeric score. Checks using `missingControl: true`: CAA, DNSSEC, HTTP Security, MTA-STS, MX, SVCB-HTTPS, NS, Zone Hygiene, BIMI, DANE, TLS-RPT.

**Grades**: A+ (92+), A (87–91), B+ (82–86), B (76–81), C+ (70–75), C (63–69), D+ (56–62), D (50–55), F (<50).

### Scoring Profiles

`computeScanScore()` accepts an optional `DomainContext` that adapts weights based on domain purpose. Five profiles exist: `mail_enabled` (default/today's weights), `enterprise_mail`, `non_mail`, `web_only`, `minimal`. Defined in `src/lib/context-profiles.ts`.

**Phase 1 (current):** `scan_domain` auto-detects the profile from check results (MX presence, provider detection, SSL/CAA) and reports it in the structured result (`scoringProfile`, `scoringSignals`), but `auto` mode uses `mail_enabled` weights (identical to pre-profile behavior). Only explicit `profile` parameter values activate different weights and cache keys (`cache:<domain>:profile:<profile>`).

**Detection priority:** `non_mail`/`web_only` (no MX or Null MX) → `mail_enabled` (MX DNS failure — safe fallback) → `enterprise_mail` (MX + known provider + hardening signal) → `mail_enabled` (MX, default) → `minimal` (>50% checks failed override).

**Profile-aware scoring:** When context is provided, `computeScanScore` uses `context.weights` instead of `IMPORTANCE_WEIGHTS`, `PROFILE_CRITICAL_CATEGORIES[profile]` for gap ceiling, and `PROFILE_EMAIL_BONUS_ELIGIBLE[profile]` for email bonus eligibility.

### Adaptive Weights

The adaptive weights system uses telemetry from previous scans to adjust importance weights per profile+provider combination. Implemented across two key files:

- `src/lib/adaptive-weights.ts` — Pure computation: EMA-based weight adjustment, maturity-gated blending, bound clamping, and scoring note generation
- `src/lib/profile-accumulator.ts` — Durable Object with SQLite storage that collects per-category failure rates and serves adaptive weights

**Pipeline:** After each `scan_domain` completes, telemetry (category scores, profile, provider) is sent to the `ProfileAccumulator` DO via `waitUntil()` (non-blocking). On subsequent scans, the DO returns EMA-smoothed failure rates which `computeAdaptiveWeight()` converts to adjusted weights. `blendWeights()` gates the adjustment behind a maturity threshold (`MATURITY_THRESHOLD = 200` samples) so weights stay close to static until enough data accumulates.

**Fallback chain:** If the `PROFILE_ACCUMULATOR` DO binding is unavailable or the DO request fails, `scan_domain` gracefully falls back to static profile weights (no adaptive adjustment). This is a soft dependency — the server operates identically to pre-adaptive behavior without the binding.

**Binding:** `PROFILE_ACCUMULATOR` (Durable Object) — threaded from `index.ts` → `dispatch.ts` → `handlers/tools.ts` → `scanDomain()` via the `profileAccumulator` field in runtime options. The `waitUntil` callback (`c.executionCtx.waitUntil`) is threaded alongside it for non-blocking telemetry writes.

## Security

- **SSRF protection**: `config.ts` defines blocked IPs/TLDs/rebinding services; `sanitize.ts` enforces them. Wrangler uses `global_fetch_strictly_public` compatibility flag. All outbound fetches in tool checks (MTA-STS policy, SSL probe, subdomain takeover probe) use `redirect: 'manual'` to prevent redirect-based SSRF — redirect targets are never followed blindly.
- **Secondary DoH (bv-dns)**: When `BV_DOH_ENDPOINT` is configured, empty-result secondary confirmation tries bv-dns first (with `X-BV-Token` auth header if `BV_DOH_TOKEN` is set), then falls back to Google DoH. The bv-dns fetch does not use `cf: { cacheTtl }` since it targets an external origin (Oracle Cloud). `global_fetch_strictly_public` ensures SSRF safety for this external fetch. If bv-dns is down/slow, it fails silently and Google takes over.
- **Auth**: optional bearer token (`BV_API_KEY`), constant-time XOR comparison in `lib/auth.ts`. Tier-auth resolution (`lib/tier-auth.ts`) cascades: KV cache (5-min TTL) → bv-web service binding → static `BV_API_KEY` fallback (maps to `enterprise` tier). Negative results (revoked/unknown keys) are cached in KV to prevent repeated service binding calls. Five tiers: `free`, `agent`, `developer` (Pro), `enterprise`, `partner`.
- **Rate limiting**: 50 req/min, 300 req/hr per IP via KV (in-memory fallback) for unauthenticated users. Authenticated tier users bypass per-IP rate limits; per-tier daily quotas apply instead (keyed by API key hash). Only `tools/call` counts against rate limits — protocol methods (`initialize`, `tools/list`, `resources/*`, `prompts/*`, `ping`, `notifications/*`) are exempt. `check_lookalikes` and `check_shadow_domains` each have a separate daily quota of 20/day per IP (unauthenticated) with 60-minute result caching, due to high outbound query volume (~100 DoH queries per invocation). Response headers: `x-ratelimit-limit`/`x-ratelimit-remaining`/`x-ratelimit-reset` (minute window), `x-quota-limit`/`x-quota-remaining`/`x-quota-reset`/`x-quota-tier` (daily quotas).
- **Per-tool daily quotas**: `FREE_TOOL_DAILY_LIMITS` in `config.ts` caps unauthenticated usage per tool (e.g., `scan_domain`: 75/day, `check_lookalikes`: 20/day, `check_shadow_domains`: 20/day, `check_mx_reputation`: 20/day, `compare_baseline`: 150/day, `check_txt_hygiene`: 200/day, individual checks: 200/day). Global daily cap of 500k requests/day across all unauthenticated IPs (`GLOBAL_DAILY_TOOL_LIMIT`). Distributed via Durable Objects (`QuotaCoordinator`).
- **Content-Type validation**: POST endpoints (`/mcp`, `/mcp/messages`) require `Content-Type: application/json` (with optional parameters like `charset=utf-8`). Missing Content-Type is allowed for client compatibility. Non-JSON Content-Types (`text/plain`, `application/xml`, `multipart/form-data`, etc.) are rejected with HTTP 415 Unsupported Media Type. Validated via `validateContentType()` in `mcp/request.ts`.
- **Request body max**: 10 KB on `/mcp`
- **IP sourcing**: only `cf-connecting-ip` — never `x-forwarded-for`
- **Error sanitization**: only known validation errors surface; unexpected → generic message. Fallback `console.warn()` messages in KV/DO error paths use generic descriptions without leaking error details.
- **Origin validation**: MCP spec-compliant; rejects browser requests with unauthorized `Origin` header; configurable via `ALLOWED_ORIGINS` env var. Missing `Origin` header results in empty CORS (no wildcard `*`), allowing non-browser clients through without granting cross-origin access.
- **Output sanitization**: SVG badge output (`lib/badge.ts`) XML-escapes all interpolated values and validates `color` against a hex regex. DNS-over-HTTPS responses (`lib/dns-transport.ts`) are validated for expected schema before casting. All finding `detail` strings are sanitized via `sanitizeDnsData()` in `createFinding()` to strip HTML/markdown injection from attacker-controlled DNS data. The `unescapeDnsTxt()` loop is capped at 2 iterations to prevent multi-layer decode attacks.
- **Response body limits**: Outbound HTTP fetches to untrusted servers (MTA-STS policy, subdomain takeover probe, provider signatures) enforce body size caps (64 KB for tool checks per RFC 8461, 1 MB for provider signatures) via content-length pre-check and post-read validation.
- **Log sanitization**: Client IP addresses are redacted in structured JSON logs via `SENSITIVE_KEY_PATTERN` in `lib/log.ts`.
- **Sessions**: idle TTL (2 hours), sliding refresh on validate, optional KV-backed storage via `SESSION_STORE` with in-memory fallback + dual-write (both KV and in-memory on create, in-memory-first on validate for cross-isolate resilience). Missing session → 400; expired/terminated session → 404 (per MCP spec, triggers client re-initialization). Session creation is rate-limited to 30/min per IP across both modern (`initialize`) and legacy (`GET /mcp/sse`) transports. `DELETE /mcp` accepts session ID only via the `Mcp-Session-Id` header (not query string). `GET /mcp` SSE notification stream is exempt from control plane rate limiting to prevent `mcp-remote` reconnection storms from burning through the budget.
- **Input validation**: Tool parameters with array types (`include_providers`, `mx_hosts`) are validated per-element for type, length (≤253 chars), and content (no whitespace/control chars in `mx_hosts`). The `record_type` parameter is validated against an allowlist. All validation errors use the `'Invalid'` prefix to pass through error sanitization.
- **Rate limit serialization**: All KV-backed rate limit counters (per-IP, per-tool, global daily, session-create) are serialized within each isolate via `withIpKvLock()` to prevent intra-isolate read-modify-write races.
- **Alerting**: Webhook URLs must use `https:` protocol; non-HTTPS and malformed URLs are silently skipped.
- **Internal routes**: `/internal/*` is guarded by `cf-connecting-ip` header detection. Cloudflare only sets this header on public internet requests — service binding calls (Worker-to-Worker) never carry it. Public requests to `/internal/*` receive a 404. This allows other Workers in the same Cloudflare account to call tool handlers directly without MCP protocol overhead, auth, rate limiting, or session management.

## Adding a New Tool

1. Create `src/tools/check-<name>.ts` → export async fn returning `CheckResult`
2. Add the `CheckCategory` value to the union type in `src/lib/scoring-model.ts` + `CATEGORY_DISPLAY_WEIGHTS`
3. Add to `IMPORTANCE_WEIGHTS` in `src/lib/scoring-engine.ts`
4. Add to `DEFAULT_SCORING_CONFIG` weights, profileWeights (all 5 profiles), and baselineFailureRates in `src/lib/scoring-config.ts`
5. Add to all 5 `PROFILE_WEIGHTS` maps in `src/lib/context-profiles.ts`
6. Register in `src/handlers/tool-schemas.ts` (TOOLS array) + `src/handlers/tools.ts` (import + TOOL_REGISTRY)
7. Add to `FREE_TOOL_DAILY_LIMITS` in `src/lib/config.ts`
8. Add explanation templates in `src/tools/explain-finding-data.ts`
9. If the new check is part of `scan_domain`, add it to the parallel orchestration in `src/tools/scan-domain.ts` (use static import there, not dynamic)
10. Add `test/check-<name>.spec.ts` using the `dns-mock` helper pattern
11. Update README tools table

## Testing

- DNS mocked via `test/helpers/dns-mock.ts` — key helpers: `setupFetchMock()`, `mockTxtRecords()`, `createDohResponse()`, `mockFetchResponse()`, `mockFetchError()`
- Each spec must call `restore()` in `afterEach` to reset the fetch mock
- **Dynamic imports are required** in test functions for mock isolation — e.g. `const { checkSpf } = await import('../src/tools/check-spf')` inside each test helper
- Clear scan cache between cases when testing tool dispatch — both `cache:<domain>:check:<name>` (per-check) and `cache:<domain>` (full scan)
- `tsconfig.json` `types` must be under `compilerOptions` (not top-level) — Vitest pool requires this
- Config file is `vitest.config.mts` (not `.ts`) — global test timeout is 15s, `isolatedStorage: false`
- TXT record mocking: `mockTxtRecords()` wraps values in quotes (as Cloudflare DoH does); pass unquoted strings. To test DNS backslash escaping (e.g. `\;`), use `createDohResponse()` directly with raw `data` fields containing the escaped form

### Pre-commit hook

The `.githooks/pre-commit` hook blocks staging of sensitive paths: internal docs (`docs/plans/`, `docs/code-review/`, `docs/superpowers/`, select draft files), `.dev/`, `*.env`, `*.env.*`. Public docs (`docs/client-setup.md`, `docs/scoring.md`, `docs/troubleshooting.md`, `docs/style-guide.md`) are tracked and committable. Enable with `git config core.hooksPath .githooks`. Override with `git commit --no-verify` when intentional.

## CI/CD

- `.github/workflows/ci.yml`: typecheck + lint + test on PRs and pushes to `main`
- `.github/workflows/security.yml`: Gitleaks secret/PII scan + `npm audit` dependency check on PRs and pushes to `main` (**required checks**)
- `.github/workflows/dns-security.yml`: weekly DNS security scan of blackveilsecurity.com via blackveil-dns-action
- `.gitleaks.toml`: custom rules for email addresses, real IP addresses, phone numbers, Cloudflare credentials; allowlists for test fixtures (`@example.com`, RFC 5737 IPs, private ranges)

**Branch protection** (configure in GitHub Settings → Branches → `main`): require PR reviews, require `build-and-test`, `Secret & PII scan`, and `Dependency audit` status checks to pass before merge, disable direct pushes to `main`.

### Runtime Scoring Configuration

All scoring weights, thresholds, grade boundaries, and baseline failure rates are configurable via the `SCORING_CONFIG` environment variable (JSON string). When absent, built-in defaults are used (identical to the values documented above). Any subset of values can be overridden — unspecified values fall back to defaults.

```jsonc
{
  "weights": { "spf": 10, "dmarc": 16, ... },           // base importance weights
  "profileWeights": {                                     // per-profile weight overrides
    "enterprise_mail": { "dmarc": 30, ... }
  },
  "thresholds": {
    "emailBonusImportance": 8,
    "spfStrongThreshold": 57,
    "criticalOverallPenalty": 15,
    "criticalGapCeiling": 64
  },
  "grades": { "aPlus": 90, "a": 85, ... },              // grade boundaries
  "baselineFailureRates": { "dmarc": 0.40, ... }         // adaptive weight baselines
}
```

Parsed once per request in `index.ts` and `internal.ts` via `parseScoringConfig()`, then threaded through the call chain. Invalid JSON or non-numeric values fall back to defaults silently. The `ScoringConfig` type and `DEFAULT_SCORING_CONFIG` are in `src/lib/scoring-config.ts` (re-exported via `src/lib/scoring.ts`).

## Service Binding Integration

bv-mcp can be consumed as a **Cloudflare service binding** by other Workers in the same account. This provides sub-millisecond, zero-overhead access to all tool handlers without MCP protocol framing, auth, rate limiting, or session management.

### How it works

The `/internal/tools/call` route (`src/internal.ts`) accepts plain JSON and returns raw tool results:

```typescript
// Consuming Worker's wrangler config — add service binding:
// { "services": [{ "binding": "BV_MCP", "service": "bv-dns-security-mcp" }] }

// Single tool call:
const response = await env.BV_MCP.fetch(
  new Request('https://internal/internal/tools/call', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: 'scan_domain', arguments: { domain: 'example.com' } }),
  })
);
const result = await response.json();
// result: { content: [{ type: 'text', text: '...' }], isError?: boolean }
```

### Batch endpoint

`POST /internal/tools/batch` executes the same tool across multiple domains with controlled concurrency:

```typescript
const response = await env.BV_MCP.fetch(
  new Request('https://internal/internal/tools/batch', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domains: ['a.com', 'b.com'], tool: 'scan_domain', concurrency: 10 }),
  })
);
const body = await response.json();
// body: { results: [{ domain, result, isError }], summary: { total, succeeded, failed } }
```

- **Max 500 domains**, max 256 KB request body, concurrency 1–50 (default 10)
- `tool` defaults to `scan_domain` if omitted
- `?format=structured` returns raw `CheckResult` per domain (via `resultCapture`) instead of MCP-framed content — but `scan_domain` does not trigger `resultCapture` (not in `TOOL_REGISTRY`), so its results come as MCP content with `<!-- STRUCTURED_RESULT {json} STRUCTURED_RESULT -->` delimiters in the second content block
- Invalid domains are returned immediately as errors without consuming concurrency slots
- Each domain validates through `validateDomain()` + `sanitizeDomain()` before execution

### What gets bypassed vs preserved

| Layer | Public `/mcp` | Internal `/internal/*` |
|-------|:---:|:---:|
| CORS, Origin validation | Yes | No |
| Auth (bearer token) | Yes | No |
| Rate limiting (all tiers) | Yes | No |
| Session management | Yes | No |
| JSON-RPC framing | Yes | No |
| Body size limit (10 KB) | Yes | No |
| **Tool execution + caching** | Yes | **Yes** |
| **Analytics telemetry** | Yes | **Yes** |
| **Adaptive weight scoring** | Yes | **Yes** |
| **SSRF protection** | Yes | **Yes** |

### Security

The guard middleware in `src/internal.ts` rejects any request with a `cf-connecting-ip` header (which Cloudflare sets on all public internet requests). Service binding calls are Worker-to-Worker over Cloudflare's internal network and never carry this header. Public requests to `/internal/*` receive a 404.

### Service binding consumers

- **bv-web** (`blackveil-web`) — Admin bulk scanner page (`/admin/batch`) calls `POST /internal/tools/batch` with up to 500 domains. Individual check pages use `POST /internal/tools/call` via `mcpClient` service client.
- Other Workers in the same Cloudflare account can consume bv-mcp via service binding for DNS/email security checks without MCP protocol overhead.

## Deployment

The public `wrangler.jsonc` has placeholder KV bindings (commented out). Real deployments use a gitignored private config:

```bash
npm run deploy:private     # uses .dev/wrangler.deploy.jsonc
```

**First-time setup:**
1. Create KV namespaces: `npx wrangler kv namespace create "RATE_LIMIT"` (repeat for `SCAN_CACHE`, `SESSION_STORE`)
2. Copy `wrangler.jsonc` to `.dev/wrangler.deploy.jsonc`, uncomment the `kv_namespaces` block, and replace placeholder IDs with the real ones from step 1
3. Deploy: `npm run deploy:private`

**Important:** KV bindings are required for production. Without them, sessions are per-Worker-isolate and MCP clients will get intermittent 404 "session expired" errors when requests hit different isolates. With KV, sessions are dual-written (in-memory + KV on create, in-memory-first on validate) to mitigate KV eventual consistency lag across isolates. Session TTL is 2 hours.

## Bindings

| Binding | Type | Purpose |
|---------|------|---------|
| `BV_API_KEY` | Secret/var | Optional bearer auth (open when empty) |
| `ALLOWED_ORIGINS` | var | Comma-separated allowed Origin headers (optional; same-origin allowed by default) |
| `RATE_LIMIT` | KV Namespace | Per-IP rate counters (**required in production**; in-memory fallback for dev) |
| `SCAN_CACHE` | KV Namespace | 5-min TTL result cache (**required in production**; in-memory fallback for dev) |
| `SESSION_STORE` | KV Namespace | Session state for cross-isolate continuity (**required in production**; in-memory fallback for dev) |
| `QUOTA_COORDINATOR` | Durable Object | Distributed rate limiting across isolates |
| `PROFILE_ACCUMULATOR` | Durable Object | Adaptive weight telemetry collection and EMA computation (optional; static weights fallback) |
| `MCP_ANALYTICS` | Analytics Engine | Telemetry dataset (fail-open; optional) |
| `PROVIDER_SIGNATURES_URL` | var | Optional URL for runtime email provider signatures |
| `BV_DOH_ENDPOINT` | var | Custom secondary DoH resolver URL (e.g. `https://secondary-doh.example.com/dns-query`); optional — falls back to Google DoH when absent |
| `BV_DOH_TOKEN` | Secret | Auth token sent as `X-BV-Token` header to bv-dns (optional; set via `npx wrangler secret put BV_DOH_TOKEN`) |
| `SCORING_CONFIG` | var | JSON string overriding scoring weights, thresholds, and grade boundaries (optional; built-in defaults when absent) |
| `CF_ACCOUNT_ID` | var | Cloudflare account ID (required for analytics alerting) |
| `CF_ANALYTICS_TOKEN` | Secret | API token with Account Analytics Read (required for analytics alerting) |
| `ALERT_WEBHOOK_URL` | var | Slack/Discord webhook URL for anomaly alerts (optional) |
| `ALERT_ERROR_THRESHOLD` | var | Error rate % trigger (default: 5) |
| `ALERT_P95_THRESHOLD` | var | P95 latency ms trigger (default: 10000) |
| `ALERT_RATE_LIMIT_THRESHOLD` | var | Rate limit hits trigger per interval (default: 50) |
| `ALERT_LOOKBACK_MINUTES` | var | Alerting query window in minutes (default: 15) |

## Analytics & Observability

### Event schema

Four event types are emitted to the `MCP_ANALYTICS` Analytics Engine dataset:

- **`mcp_request`** — every JSON-RPC request (method, transport, status, auth, country, client type, tier, session hash, duration)
- **`tool_call`** — every tool execution (tool name, status, domain fingerprint, country, client type, tier, cache status, duration, score)
- **`rate_limit`** — every rate limit rejection (limit type, tool name, country, tier, limit, remaining)
- **`session`** — session lifecycle (created/terminated, country, client type, tier)

### Querying metrics

Pre-built SQL queries are in `src/lib/analytics-queries.ts`. Run via CLI:

```bash
npx wrangler analytics-engine sql --dataset MCP_ANALYTICS --query "$(cat <<'SQL'
SELECT blob1 AS tool, SUM(_sample_interval) AS calls
FROM MCP_ANALYTICS WHERE index1 = 'tool_call'
AND timestamp > NOW() - INTERVAL '1' DAY
GROUP BY tool ORDER BY calls DESC
SQL
)"
```

### Alerting

The scheduled handler (`src/scheduled.ts`) runs every 15 minutes via Cron Trigger. It queries Analytics Engine SQL API for anomalies and sends Slack/Discord webhook alerts. All alerting is optional — without `CF_ACCOUNT_ID` + `CF_ANALYTICS_TOKEN` + `ALERT_WEBHOOK_URL`, the cron handler is a no-op.

### Client detection

`src/lib/client-detection.ts` parses User-Agent headers to identify MCP clients: `claude_code`, `cursor`, `vscode`, `claude_desktop`, `windsurf`, `mcp_remote`, `unknown`. Used for analytics segmentation and output format auto-detection — never for security decisions.

## False Positive Reduction

Several checks use contextual signals to reduce false positives:

- **MX Reputation** (`mx-reputation-analysis.ts`): `detectSharedMxProvider()` identifies shared email provider IPs (Google, Microsoft 365, Proofpoint, Mimecast, etc.) via MX hostname suffixes. DNSBL listings for shared provider IPs are downgraded to `info` severity since per-domain reputation is managed at the account level, not the IP level. Dedicated/self-hosted MX hosts retain `high` severity.

- **Lookalikes** (`check-lookalikes.ts`): After discovering active lookalike domains, queries their NS records and compares with the primary domain's NS. Shared nameservers (≥1 overlap) indicate defensive registration by the same owner → downgraded to `info` with `sharedNs: true` metadata. Falls back to original classification if primary NS query fails.

- **Shadow Domains** (`check-shadow-domains.ts`): `sharesNsWithPrimary()` compares variant NS against primary domain NS (≥2 overlap). Shared NS downgrades: fully spoofable critical→high, lacks DMARC high→medium, DMARC not enforcing high→medium. Detail text annotated with ownership signal.

- **TXT Hygiene** (`check-txt-hygiene.ts`): Record accumulation severity tiered: 25+ records→medium, 15-24→low, 10-14→low. Duplicate verification records consolidated into a single `low` finding listing all providers (e.g., "Google Search Console 6x") instead of one medium per provider.

- **Non-mail SPF** (`check-mx.ts`): When no MX records are found, `check_mx` also queries TXT records to verify the domain has `v=spf1 -all`. Missing SPF→medium, non-reject SPF→low.
