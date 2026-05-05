# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is this?

Blackveil DNS — open-source DNS & email security scanner, built as a Cloudflare Worker.
Exposes 51 tools via MCP Streamable HTTP (JSON-RPC 2.0) at `https://dns-mcp.blackveilsecurity.com/mcp`.
An additional check (`check_subdomain_takeover`) runs only inside `scan_domain` and is not directly callable by clients.
**Version**: 2.9.2 — keep `SERVER_VERSION` in `src/lib/server-version.ts` and `version` in `package.json` in sync. Listed on the [MCP Registry](https://registry.modelcontextprotocol.io) as `com.blackveilsecurity/dns`.

## Commands

```bash
npm install                            # Install deps (includes workspace packages)
npm test                               # Vitest + Istanbul coverage (Workers runtime)
npx vitest run test/check-spf.spec.ts  # Run a single test file
python3 scripts/chaos/chaos-test-clients.py          # Chaos test: all 9 client types (v2.1.17+)
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
- **Chaos Testing**: Python-based multi-client/multi-session validation
- **TypeScript**: strict, ES2024 target, Bundler resolution, `isolatedModules: true`
- **Testing**: Vitest + `@cloudflare/vitest-pool-workers` (tests execute inside Workers runtime)
- **Linter**: ESLint + typescript-eslint
- **Formatter**: Prettier (tabs, single quotes, semi, 140 width)
- **Package manager**: npm
- **Tooling Node.js**: Node 22+ for CI/dev/deploy workflows because Wrangler 4.87+ hard-fails on Node <22

## Architecture

### Monorepo structure

npm workspace monorepo. Root is a Cloudflare Worker; `packages/dns-checks` (`@blackveil/dns-checks`) is a separately publishable runtime-agnostic package.

**Entrypoints**: `src/index.ts` (Worker/Hono app), `src/package.ts` (npm package → `dist/index.js`), `src/stdio.ts` (CLI → `dist/stdio.js` with `cloudflare:workers` shim), `src/internal.ts` (service binding routes), `src/scheduled.ts` (Cron Trigger alerting).

```bash
npm -w packages/dns-checks run build      # Build sub-package
npm -w packages/dns-checks run test       # Test sub-package
npm -w packages/dns-checks run typecheck  # Typecheck sub-package
```

### Source layout

```
src/index.ts              — Hono app, HTTP routes, middleware wiring
src/package.ts            — npm package entrypoint
src/internal.ts           — Internal service binding routes (no MCP overhead)
src/stdio.ts              — Native stdio MCP transport (CLI)
src/scheduled.ts          — Cron Trigger handler for analytics alerting

src/mcp/                  — MCP protocol layer
  execute.ts              — Transport-neutral shared executor (validation, rate limiting, dispatch, analytics)
  dispatch.ts             — JSON-RPC method → handler routing
  request.ts              — Body parsing, JSON-RPC validation (batch support), Content-Type validation
  route-gates.ts          — Pre-dispatch guards (rate limits, session validation)

src/schemas/              — Centralized Zod validation schemas
  primitives.ts           — Shared schemas: Domain, SessionId, enums (Profile, Format, Grade, Tier)
  tool-args.ts            — Per-tool argument Zod schemas + TOOL_SCHEMA_MAP
  tool-definitions.ts     — TOOLS array with inputSchema derived from Zod via z.toJSONSchema()
  json-rpc.ts             — JSON-RPC 2.0 request/batch validation
  internal.ts             — Internal route request body schemas
  dns.ts                  — DoH response + parsed record type schemas (CAA, TLSA, MX, SRV)
  session.ts              — Session KV record schema
  auth.ts                 — Tier cache entry + service binding response schemas

src/handlers/             — MCP method handlers
  tools.ts                — tools/list + tools/call dispatch
  tool-schemas.ts         — Re-exports TOOLS/McpTool from schemas/tool-definitions.ts
  tool-args.ts            — Domain extraction, Zod validation dispatch, format resolution
  tool-formatters.ts      — mcpError/mcpText/formatCheckResult helpers
  tool-execution.ts       — Tool logging helpers
  resources.ts            — resources/list + resources/read
  prompts.ts              — prompts/list + prompts/get

src/tools/                — Individual DNS checks + orchestrator
  check-*.ts              — Individual checks (SPF, DMARC, DKIM, MX, SSL, BIMI, etc.)
  *-analysis.ts           — Analysis helpers extracted from check modules
  scan-domain.ts          — Parallel orchestrator → ScanScore + MaturityStage
  scan/                   — Scan sub-helpers (format-report, post-processing, maturity-staging)
  explain-finding-data.ts — Static explanation generator
  explain-finding.ts      — Static explanation generator
  resolve-spf-chain.ts    — Recursive SPF include tree with lookup counting
  discover-subdomains.ts  — CT log subdomain discovery (certstream binding + crt.sh fallback)
  map-supply-chain.ts     — Third-party dependency graph (SPF/NS/TXT/SRV/CAA correlation)
  map-compliance.ts       — Compliance framework mapping (NIST/PCI/SOC2/CIS)
  simulate-attack-paths.ts — Attack path enumeration from DNS posture
  analyze-drift.ts        — Baseline comparison with drift classification
  validate-fix.ts         — Targeted re-check with fix verdict
  generate-rollout-plan.ts — Phased DMARC enforcement timeline
  provider-guides.ts      — Static provider detection rules and fix guide guides
  txt-hygiene-analysis.ts — Shared TXT verification patterns and SPF cross-reference

src/lib/                  — Shared infrastructure
  scoring.ts              — Re-export facade for scoring subsystem
  scoring-model.ts        — Types (Finding, CheckResult, ScanScore) + buildCheckResult/createFinding
  scoring-engine.ts       — IMPORTANCE_WEIGHTS, computeScanScore, scoreToGrade (bridge to generic engine)
  scoring-config.ts       — Runtime scoring configuration (ScoringConfig type, defaults, parser)
  context-profiles.ts     — DomainProfile, DomainContext, PROFILE_WEIGHTS, detectDomainContext
  adaptive-weights.ts     — EMA-based adaptive weight computation
  profile-accumulator.ts  — Durable Object for per-profile telemetry (SQLite-backed)
  dns.ts                  — DNS-over-HTTPS facade; queryTxtRecords concatenates per RFC 7208 §3.3, unescapes RFC 1035 §5.1 (max 2 passes)
  sanitize.ts             — Domain validation, SSRF protection (imports `punycode/` — trailing slash = npm package)
  config.ts               — SSRF constants, DNS tuning, rate limit quotas
  session.ts              — KV + in-memory session management with dual-write
  cache.ts                — KV + in-memory TTL cache, INFLIGHT dedup, cacheSetDeferred()
  rate-limiter.ts         — KV + in-memory per-IP rate limiting; withIpKvLock() for serialization
  json-rpc.ts             — JSON-RPC 2.0 types, error codes, response builders
  auth.ts                 — Bearer token validation (constant-time XOR)
  analytics.ts            — Analytics Engine integration (fail-open, 4 event types)
  log.ts                  — Structured JSON logging with sanitization

test/                     — One spec per source file
test/helpers/dns-mock.ts  — Shared fetch mock for DNS-over-HTTPS queries
test/schemas/             — Unit tests for Zod schemas

packages/dns-checks/     — @blackveil/dns-checks (runtime-agnostic core library)
  src/scoring/           — Generic scoring engine
    generic.ts           — String-keyed three-tier scoring implementation
    engine.ts            — computeScanScore bridge and scoring defaults
    model.ts             — Finding/CheckResult types and missing-control rules
    profiles.ts          — DomainProfile weight sets and context detection
    config.ts            — ScoringConfig parser and defaults
  src/checks/            — Individual check implementations (SPF, DMARC, etc.)
  src/schemas/           — Zod schemas for all check results and findings

```

### Packages & Releases

**Layered Architecture**: The project uses a layered design separating runtime-agnostic business logic from infrastructure concerns:

- **`packages/dns-checks/`** (`@blackveil/dns-checks`): Runtime-agnostic core library containing DNS validation logic. No Cloudflare dependencies. Contains 16 core check functions (SPF, DMARC, DKIM, etc.) and scoring engine. Published as separate npm package for reuse in other environments.

- **`src/tools/`**: MCP protocol wrappers with Cloudflare infrastructure. Contains 51 MCP tools including the 16 check wrappers plus orchestration tools (scan_domain, explain_finding, etc.). Depends on `@blackveil/dns-checks` package.

**When to Add to Each Layer**:
- **dns-checks package**: New DNS validation logic, scoring algorithms, or check implementations that could be reused outside Cloudflare Workers
- **src/tools layer**: MCP API endpoints, orchestration logic, or tools that require Cloudflare-specific features (KV, Durable Objects, service bindings)

**Release Coordination**: Both packages are published together via CI/CD on version tags. The main package depends on `@blackveil/dns-checks` via npm, so releases must maintain backward compatibility. Version numbers are synchronized in `package.json` and `src/lib/server-version.ts`.

**Deployment Strategy**: Cloudflare Workers deployment publishes the main package. The dns-checks package is consumed via npm dependency, not bundled. Service bindings allow live updates without downstream npm installs.

### Request flow

**Streamable HTTP**: `POST /mcp → Origin check → Auth → Body parse → JSON-RPC validate → mcp/execute.ts → handlers/tools.ts → src/tools/check-*.ts → lib/dns.ts → Cloudflare DoH (empty → bv-dns → Google fallback)`

**Native stdio**: `stdin (JSON-RPC) → src/stdio.ts → mcp/execute.ts → handlers/tools.ts → stdout`

**Legacy HTTP+SSE** (deprecated): `GET /mcp/sse → SSE bootstrap; POST /mcp/messages?sessionId=... → mcp/execute.ts → SSE stream`

**Internal service binding**: `POST /internal/tools/call → guard (reject public) → handlers/tools.ts → JSON (no MCP framing)`
`POST /internal/tools/batch → validate/sanitize → concurrent chunks → JSON: { results, summary }`

### scan_domain orchestration

Runs **16 checks** in parallel via `Promise.allSettled`. Each has cache key `cache:<domain>:check:<name>`, plus top-level `cache:<domain>`. Results cached 5 min (respects `cacheTtlSeconds` override). `force_refresh` propagates via `skipCache` in `runWithCache()`.

**Maturity staging**: `computeMaturityStage()` classifies 0-4 (Unprotected → Hardened). Stage 3 doesn't require DKIM. Stage 4 hardening signals: CAA, DKIM-discovered, BIMI, DANE, MTA-STS strict. `capMaturityStage()` caps by score: F (<50) → max Stage 2, D/D+ (<63) → max Stage 3.

**Partial results on timeout**: 12s scan timeout preserves completed checks; missing get timeout findings. Per-check timeouts 8s. Scan context skips secondary DNS confirmation for speed.

**Post-processing adjustments**:
- **Non-mail**: No MX → queries parent DMARC `sp=`/`p=` → downgrades email-auth findings to `info`
- **No-send**: SPF `noSendPolicy` metadata → downgrades DKIM/MTA-STS/BIMI missing-record findings to `info`
- **BIMI**: Rewritten for non-mail domains

**Structured output**: Returns (1) human-readable text via `formatScanReport()`, (2) for non-interactive clients only, `<!-- STRUCTURED_RESULT ... -->` JSON block. Omitted for known LLM IDE clients to reduce context.

### Output format control

All tools accept optional `format` parameter (`full` | `compact`). Auto-detected from client type: interactive LLM clients → `compact`, non-interactive/unknown → `full`.

**Compact mode** strips emoji icons, impact narratives, and verbose sections across all formatters. **Full mode** includes emoji severity icons, multi-line findings, and structured JSON blocks.

Resolution: `extractFormat(args)` in `tool-args.ts` → explicit param wins → else `resolveFormat()` auto-detects from `clientType`. `OutputFormat` type exported from `tool-args.ts`.

## Conventions

- **Zod schemas**: All input validation uses centralized schemas in `src/schemas/`. Tool `inputSchema` (MCP tools/list) derived from Zod via `z.toJSONSchema()` (Zod v4 built-in). Runtime validation via `validateToolArgs()` in `tool-args.ts`. Schemas use `.passthrough()` (no property stripping) and `.transform().pipe()` for case-insensitive enum normalization.
- `createFinding()` + `buildCheckResult()` from `lib/scoring-model.ts` (re-exported via `lib/scoring.ts`) — never construct findings manually. `createFinding()` auto-sanitizes `detail` via `sanitizeDnsData()`
- `validateDomain()` + `sanitizeDomain()` from `lib/sanitize.ts` for all domain inputs — runs after Zod shape validation for SSRF/blocklist protection
- `mcpError()` / `mcpText()` from `handlers/tool-formatters.ts` for MCP response formatting
- `cacheGet()` / `cacheSet()` / `cacheSetDeferred()` / `runWithCache()` from `lib/cache.ts`; `cacheSetDeferred()` wraps in `ctx.waitUntil()`; `runWithCache()` accepts `skipCache` for `force_refresh`
- JSDoc (`/** */`) on exported functions; `import type { ... }` for type-only imports
- All tool functions return `Promise<CheckResult>` (follow `check-spf.ts` pattern) and accept optional `dnsOptions?: QueryDnsOptions`
- **DNS-failure resilience**: wrappers around `@blackveil/dns-checks` that are called directly by clients (not just from `scan_domain`'s `safeCheck`) should catch top-level DNS errors and return a `CheckResult` with a `missingControl: true` finding instead of throwing. Follow `check-spf.ts` as the reference — it distinguishes `errorKind: 'timeout' | 'dns_error'` based on regex match of the error message. Inside `scan_domain`, `safeCheck()` already handles this for you; the pattern matters for direct `tools/call` invocations where error rates get counted against the tool in analytics.
- **Total-budget caps**: tools that spawn multiple sequential external fetches (e.g. `check_http_security` does dual-fetch + WAF body + package probe) should wrap the whole thing in a single `Promise.race` against a `TOTAL_BUDGET_MS` timer so package-internal sequentiality can't compound into a Worker-CPU-ceiling outage. Current caps: `check_http_security` = 10s.
- **`batch_scan` budget**: `batch-scan.ts` enforces `budgetMs` (default 25s) + `concurrency` (default 3) with per-domain `Promise.race` timeouts. Items that exhaust the budget return `error: 'batch_budget_exceeded'`. Both options are exposed via `BatchScanOptions` for tests; production callers should use defaults.
- `check_mx` is dynamically imported in `handlers/tools.ts` (for test mock isolation)
- MCP server key name is `"blackveil-dns"` across all configs — keep consistent
- `tools/call` accepts `scan` as alias for `scan_domain`
- SSRF config constants live in `src/lib/config.ts`, not `sanitize.ts`

### Error surfacing convention

`sanitizeErrorMessage()` in `lib/json-rpc.ts` controls which error messages reach clients. Only messages starting with these `SAFE_ERROR_PREFIXES` pass through:
- `'Missing required'` — missing tool arguments
- `'Invalid'` — validation failures (format, selector, check name)
- `'Domain '` — domain validation errors (e.g., `'Domain validation failed: ...'`, `'Domain uses a DNS rebinding service...'`)
- `'Resource not found'` — unknown resources
- `'Rate limit exceeded'` — quota/rate limit errors

All other errors return a generic fallback message. New validation errors that need to reach clients **must start with one of these exact prefixes**.

**Rate limit errors**: Use HTTP 200 with JSON-RPC error body (`code: -32029`), not HTTP 429 — follows MCP spec. `retry-after` header still set.

## Scoring

`computeScanScore()` uses a three-tier category model. `CATEGORY_DISPLAY_WEIGHTS` exists for display only, unused in scoring.

### Three-Tier Category Model

**Core (70%)** — Direct, exploitable risk:

| Category | Weight |
|----------|--------|
| DMARC | 16 |
| DKIM | 10 |
| SPF | 10 |
| DNSSEC | 8 |
| SSL | 8 |

> Production may override code defaults via `SCORING_CONFIG` env var in `.dev/wrangler.deploy.jsonc`.

**Protective (20%)** — Active defenses: Subdomain Takeover (4), HTTP Security (3), MTA-STS (3), MX (2), CAA (2), NS (2), Lookalikes (2), Shadow Domains (2).

**Hardening (10%)** — Bonus-only: DANE, BIMI, TLS-RPT, TXT Hygiene, MX Reputation, SRV, Zone Hygiene. ~1.4 pts each. Never subtracts.

### Scoring rules

- **Email bonus**: SPF ≥57, DKIM not deterministically missing, DMARC present → +5/+3/+2 pts based on DMARC score
- **SPF trust-surface**: Shared-platform findings informational by default; elevated to medium/high only when weak DMARC/relaxed alignment corroborates
- **SPF `~all` soft-fail**: `~all` findings downgraded to `info` when the domain has an enforcing DMARC policy (`p=quarantine` or `p=reject`). RFC 7489 §10.1 recommends `~all` when DMARC enforces — flagging it as a risk in that context is a false positive. `pct=<100` is also parsed from the DMARC record before making this determination
- **Confidence gate**: `scoreIndicatesMissingControl()` only fires for `deterministic`/`verified` confidence. Heuristic DKIM "not found" doesn't zero category
- **Provider-informed DKIM**: Known DKIM-signing provider detected but probing finds nothing → HIGH downgraded to MEDIUM
- **Severity penalties**: Critical −40, High −25, Medium −15, Low −5, Info 0
- **`passed` flag**: `score >= 50 && !hasMissingControl`. Missing control → score zeroed. Checks using `missingControl: true`: CAA, DNSSEC, HTTP Security, MTA-STS, MX, SVCB-HTTPS, NS, Zone Hygiene, BIMI, DANE, TLS-RPT
- **Grades**: A+ (92+), A (87–91), B+ (82–86), B (76–81), C+ (70–75), C (63–69), D+ (56–62), D (50–55), F (<50)

### Scoring Profiles

Five profiles: `mail_enabled` (default), `enterprise_mail`, `non_mail`, `web_only`, `minimal`. Defined in `src/lib/context-profiles.ts`.

**Phase 1 (current):** `auto` mode uses `mail_enabled` weights. Only explicit `profile` parameter activates different weights and cache keys (`cache:<domain>:profile:<profile>`).

**Detection priority:** `non_mail`/`web_only` (no MX) → `mail_enabled` (MX DNS failure fallback) → `enterprise_mail` (MX + known provider + hardening) → `mail_enabled` (default) → `minimal` (>50% failed override).

### Adaptive Weights

EMA-based system adjusting weights per profile+provider using `ProfileAccumulator` DO telemetry. Maturity-gated blending (`MATURITY_THRESHOLD = 200` samples). Falls back to static weights if DO unavailable. `PROFILE_ACCUMULATOR` binding threaded from `index.ts` → `dispatch.ts` → `handlers/tools.ts` → `scanDomain()`. Telemetry sent via `waitUntil()` (non-blocking).

### Runtime Scoring Configuration

All scoring parameters configurable via `SCORING_CONFIG` env var (JSON). Supports `weights`, `profileWeights`, `thresholds`, `grades`, `baselineFailureRates`. Parsed via `parseScoringConfigCached()` (memoized per isolate). Invalid values fall back to defaults silently. Types in `src/lib/scoring-config.ts`.

## Security

### Key rules

- **SSRF**: `config.ts` defines blocked IPs/TLDs; `sanitize.ts` enforces. `global_fetch_strictly_public` compat flag. All outbound fetches use `redirect: 'manual'`
- **Auth**: Optional `BV_API_KEY`, constant-time XOR. Token extracted from `Authorization: Bearer <token>` header first, then `?api_key=` query param as fallback (enables Smithery and URL-only clients). Tier-auth cascades: KV cache → bv-web service binding → static fallback. Six tiers: `free`, `agent`, `developer`, `enterprise`, `partner`, `owner`. Owner tier has unlimited rate limits but requires client IP in `OWNER_ALLOW_IPS` — mismatched IPs downgrade to `partner`
- **Rate limiting**: 50 req/min, 300 req/hr per IP (unauthenticated). Authenticated users bypass per-IP; per-tier daily quotas apply. Only `tools/call` counts. `check_lookalikes`/`check_shadow_domains`: 20/day per IP with 60-min caching
- **Per-tool quotas**: `FREE_TOOL_DAILY_LIMITS` in `config.ts`. Global cap 500k/day (`GLOBAL_DAILY_TOOL_LIMIT`). Distributed via `QuotaCoordinator` DO
- **Content-Type**: POST requires `application/json`; missing allowed for compat; non-JSON → 415
- **Body limit**: 10 KB on `/mcp`
- **IP sourcing**: Only `cf-connecting-ip` — never `x-forwarded-for`
- **Error sanitization**: Only known prefixes surface; unexpected → generic. Unknown JSON-RPC methods get static `'Method not found'`
- **Origin validation**: MCP spec-compliant; rejects unauthorized browser `Origin`; configurable via `ALLOWED_ORIGINS`

### Sessions

Idle TTL 2 hours, sliding refresh, KV + in-memory dual-write. Missing → 400; expired → 404 (triggers re-init). Creation rate-limited 30/min per IP. Session IDs: exactly 64 lowercase hex chars. `DELETE /mcp` accepts ID via `Mcp-Session-Id` header only. `SESSION_CREATE_BY_IP` capped at 5000 IPs (LRU). `LEGACY_STREAMS` capped at 500 (two-phase eviction).

### Input validation

All tool arguments validated via Zod schemas (`src/schemas/tool-args.ts`) before dispatch. `validateToolArgs()` runs the schema `.parse()` and translates `ZodError` to prefixed error messages. Array params (`include_providers`, `mx_hosts`) validated per-element for type, length (≤253), content. `record_type` validated against allowlist. Use `'Invalid'` prefix for validation errors. Enum schemas use `.transform().pipe()` for case-insensitive normalization (e.g., `"COMPACT"` → `"compact"`).

### Output sanitization

- SVG badges: XML-escape + hex regex for color
- DoH responses: schema-validated before casting
- Finding details: `sanitizeDnsData()` in `createFinding()` strips HTML/markdown injection
- `unescapeDnsTxt()` capped at 2 iterations
- Response body limits: 64 KB for tool checks, 1 MB for provider signatures
- Log sanitization: IPs redacted via `SENSITIVE_KEY_PATTERN`; control chars stripped via `sanitizeString()`

### Internal routes

`/internal/*` guarded by `cf-connecting-ip` detection. Cloudflare sets this on public requests; service binding calls don't carry it. Public requests → 404. Batch endpoint validates tool names (`/^[a-z_]+$/`, max 30 chars) and allowlists arg keys.

## Adding a New Tool

1. Create `src/tools/check-<name>.ts` → export async fn returning `CheckResult`
2. Add `CheckCategory` to union in `src/lib/scoring-model.ts` + `CATEGORY_DISPLAY_WEIGHTS`
3. Add to `IMPORTANCE_WEIGHTS` in `src/lib/scoring-engine.ts`
4. Add to `DEFAULT_SCORING_CONFIG` weights, profileWeights (all 5), baselineFailureRates in `scoring-config.ts`
5. Add to all 5 `PROFILE_WEIGHTS` maps in `context-profiles.ts`
6. Add Zod schema to `src/schemas/tool-args.ts` (or use `BaseDomainArgs` if domain-only) + add to `TOOL_SCHEMA_MAP`
7. Add tool entry to `TOOL_DEFS` in `src/schemas/tool-definitions.ts` (name, description, schema, group, tier, scanIncluded)
8. Add to `TOOL_REGISTRY` in `handlers/tools.ts` (import + cacheKey + execute)
9. Add to `FREE_TOOL_DAILY_LIMITS` in `config.ts`
10. Add explanation templates in `explain-finding-data.ts`
11. If part of `scan_domain`, add to parallel orchestration in `scan-domain.ts` (static import)
12. Add `test/check-<name>.spec.ts` using `dns-mock` helper pattern
13. Update README tools table

## Testing

- DNS mocked via `test/helpers/dns-mock.ts` — `setupFetchMock()`, `mockTxtRecords()`, `createDohResponse()`, `mockFetchResponse()`, `mockFetchError()`
- Each spec must call `restore()` in `afterEach`
- **Dynamic imports required** in test functions for mock isolation — `const { checkSpf } = await import('../src/tools/check-spf')`
- Clear scan cache between cases: both `cache:<domain>:check:<name>` and `cache:<domain>`
- `tsconfig.json` `types` must be under `compilerOptions` — Vitest pool requires this
- Config: `vitest.config.mts` (not `.ts`) — 15s timeout, `isolatedStorage: false`
- TXT mocking: `mockTxtRecords()` adds quotes; pass unquoted. For backslash escaping, use `createDohResponse()` directly

### Pre-commit hook

`.githooks/pre-commit` has three gates:
1. **Blocked paths**: internal docs (`docs/plans/`, `docs/code-review/`, `docs/superpowers/`), `.dev/`, `*.env*`
2. **Generated files**: blocks staging of `*.pyc`, `__pycache__/`, `worker-configuration.d.ts`, `*.wasm`, `*.sqlite`, `*.db` — even with `git add -f`
3. **IP leakage**: regex patterns from `.githooks/blocked-patterns` catch internal infrastructure references

Public docs (`docs/client-setup.md`, `docs/scoring.md`, etc.) are committable. Override with `--no-verify`.

## MCP Registry

Listed as `com.blackveilsecurity/dns` on the [MCP Registry](https://registry.modelcontextprotocol.io). `server.json` at the repo root is the registry manifest (pushed by `publish.yml` on version tags). `package.json` includes `mcpName: "com.blackveilsecurity/dns"` for registry resolution.

## Smithery

The server is listed on Smithery at `MadaBurns/bv-mcp` (proxy URL: `https://bv-mcp--madaburns.run.tools`).

`smithery.yaml` configures the external HTTP server entry: `url` template points to `dns-mcp.blackveilsecurity.com/mcp` with an optional `{{#if apiKey}}?api_key={{apiKey}}{{/if}}` suffix. The `configSchema` `apiKey` property uses `x-to: {query: api_key}` so Smithery Connect injects it as a query parameter.

Smithery registry metadata (configSchema, scanCredentials) is updated via `PUT /servers/{ns}/{server}/releases` API using the `SMITHERY_API_KEY` in `.dev/.env.testing`. The `smithery.yaml` `configSchema` is the source of truth for the open-source repo; the registry entry is pushed separately on release.

## CI/CD

- `ci.yml`: typecheck + lint + test on PRs and `main` pushes
- `security.yml`: Gitleaks + `npm audit` (**required checks**)
- `repo-hygiene.yml`: blocks tracked generated files, verifies `.gitignore`, flags large blobs. Reusable — called by `blackveil-dns-action`, `bv-claude-dns`, and `bv-vibesdk` via `workflow_call`
- `dns-security.yml`: weekly DNS scan of blackveilsecurity.com
- `auto-deploy-main.yml`: deploys `main` to Cloudflare after `CI`, `CI Contract`, `Security`, and `Repo Hygiene` all pass for the same commit
- `.gitleaks.toml`: custom rules; allowlists for test fixtures

**Branch protection**: require PR reviews, require `build-and-test` + `Secret & PII scan` + `Dependency audit`, disable direct pushes to `main`.

Main branch deploys are automated separately from tagged releases. `auto-deploy-main.yml` is triggered by completed workflow runs, re-checks the required gates for the same SHA, deploys with `CLOUDFLARE_API_TOKEN` from the `production` environment, and verifies `/health`. Tagged releases still use `publish.yml` for npm, MCP Registry, GitHub Release creation, and version synchronization.

### Release workflow (`publish.yml`)

**Important**: `main` has branch protection requiring 3 status checks for direct pushes. The workflow's "Sync version to tag" step tries to push an auto-bump commit and **will be rejected by branch protection**. To avoid this, **always pre-bump the version locally before tagging**:

```bash
# 1. Update CHANGELOG.md with the new version entry under [Unreleased]
# 2. Bump package.json + package-lock.json + SERVER_VERSION in one commit
npm version 2.6.8 --no-git-tag-version --allow-same-version
sed -i '' "s/export const SERVER_VERSION = '.*'/export const SERVER_VERSION = '2.6.8'/" src/lib/server-version.ts
git add package.json package-lock.json src/lib/server-version.ts CHANGELOG.md
git commit -m "chore: bump version to 2.6.8"
git push origin main

# 3. Tag and push — workflow will find version already matches and skip the auto-bump push
git tag v2.6.8 && git push origin v2.6.8
```

Pipeline: validate (test/typecheck/lint/audit) → sync version to tag (no-op when pre-bumped) → npm publish (provenance) → Cloudflare Workers deploy → MCP Registry publish (`server.json`) → GitHub Release with changelog.

npm and Cloudflare deploy run in parallel after the sync step. Requires `NPM_TOKEN` and `CLOUDFLARE_API_TOKEN` secrets in the `production` environment — without them, those steps log warnings and skip. A manual `npm run deploy:private` replaces the Cloudflare deploy step when the secret is absent.

**Alternative fix (not yet implemented)**: configure a `RELEASE_TOKEN` repo secret with a personal access token that has "bypass branch protection" permission. The workflow's checkout step already prefers `RELEASE_TOKEN` over `GITHUB_TOKEN`. With that secret in place, the auto-bump push would succeed and the pre-bump step becomes optional.

**Service binding consumers** (e.g., bv-web): no action required on bv-mcp release. Cloudflare service bindings are live-linked — deploying bv-mcp automatically makes the new version available to all consumers on the next request. No npm install, no version pinning, no downstream CI trigger needed.

**Workflow security**: all `${{ }}` expressions are passed via `env:` variables, never interpolated directly in `run:` blocks. Only controlled inputs used (tag name, secrets, job outputs) — no user-supplied text (issue titles, PR bodies, commit messages).

## Service Binding Integration

`/internal/tools/call` accepts plain JSON `{ name, arguments }`, returns `{ content, isError? }`. `/internal/tools/batch` runs same tool across multiple domains (max 500, concurrency 1-50, 256 KB body limit). `?format=structured` returns raw `CheckResult` per domain.

| Layer | Public `/mcp` | Internal `/internal/*` |
|-------|:---:|:---:|
| CORS, Origin, Auth, Rate limiting, Sessions, JSON-RPC, Body limit | Yes | No |
| Tool execution, Caching, Analytics, SSRF protection | Yes | Yes |

**Consumers**: companion web app (batch scanner → batch endpoint, individual pages → call endpoint).

## Deployment

```bash
npm run deploy:private     # uses .dev/wrangler.deploy.jsonc
```

**First-time**: Create KV namespaces (`RATE_LIMIT`, `SCAN_CACHE`, `SESSION_STORE`), copy `wrangler.jsonc` to `.dev/wrangler.deploy.jsonc` with real IDs. KV required for production — without it, sessions are per-isolate (intermittent 404s).

## Bindings

| Binding | Type | Purpose |
|---------|------|---------|
| `BV_API_KEY` | Secret | Static bearer auth — resolves as `owner` tier |
| `ENABLE_OAUTH` | var | Set to `true` to expose OAuth discovery/register/authorize/token routes. Defaults disabled so clients do not auto-open owner-key browser consent. |
| `ENABLE_OWNER_OAUTH` | var | Set to `true` only for operator/admin deployments that should render the legacy owner `BV_API_KEY` consent page. Defaults disabled; paid customer OAuth uses bv-web/Stripe entitlements instead. |
| `OWNER_ALLOW_IPS` | var | Comma-separated IPs allowed for `owner` tier (key + wrong IP → `partner`). Also enforced at `/oauth/authorize` consent step. |
| `OAUTH_SIGNING_SECRET` | Secret | HS256 signing key (≥32 bytes). Upload via `wrangler secret put`. `/oauth/token` returns `server_error` 500 until set. |
| `OAUTH_ISSUER` | var | Optional issuer override (e.g. `https://dns-mcp.blackveilsecurity.com`). Falls back to request Host — set in prod to harden against Host-header spoofing of discovery metadata. |
| `ALLOWED_ORIGINS` | var | Comma-separated allowed Origins |
| `RATE_LIMIT` | KV | Per-IP rate counters (**required prod**) |
| `SCAN_CACHE` | KV | 5-min TTL result cache (**required prod**) |
| `SESSION_STORE` | KV | Cross-isolate sessions (**required prod**) |
| `QUOTA_COORDINATOR` | DO | Distributed rate limiting |
| `PROFILE_ACCUMULATOR` | DO | Adaptive weight telemetry (optional) |
| `MCP_ANALYTICS` | Analytics Engine | Telemetry (fail-open, optional) |
| `PROVIDER_SIGNATURES_URL` | var | Runtime provider signatures URL |
| `BV_DOH_ENDPOINT` | var | Custom secondary DoH URL (fallback: Google) |
| `BV_DOH_TOKEN` | Secret | Auth for bv-dns (`X-BV-Token` header) |
| `BV_CERTSTREAM` | Service | CT log subdomain cache (optional, falls back to crt.sh) |
| `SCORING_CONFIG` | var | JSON scoring overrides (optional) |
| `CF_ACCOUNT_ID` | var | Cloudflare account ID (alerting) |
| `CF_ANALYTICS_TOKEN` | Secret | Analytics Engine read token (alerting) |
| `ALERT_WEBHOOK_URL` | var | Slack/Discord webhook (optional) |
| `ALERT_*_THRESHOLD` | var | Error/P95/rate-limit triggers |
| `ALERT_LOOKBACK_MINUTES` | var | Alerting query window (default: 15) |

## Analytics & Observability

Four event types: `mcp_request`, `tool_call`, `rate_limit`, `session`. Pre-built queries in `analytics-queries.ts`. Scheduled handler (`scheduled.ts`) runs every 15 min via Cron Trigger for anomaly alerts. All alerting optional — requires `CF_ACCOUNT_ID` + `CF_ANALYTICS_TOKEN` + `ALERT_WEBHOOK_URL`.

Client detection (`client-detection.ts`): `claude_mobile`, `claude_code`, `cursor`, `vscode`, `claude_desktop`, `windsurf`, `mcp_remote`, `blackveil_dns_action`, `bv_claude_dns_proxy`, `bv_load_test`, `unknown`. Used for analytics + format auto-detection, never security. `bv_load_test` matches `bv-{load,chaos,tranco}-{test,scan}` UAs emitted by internal scripts (`scripts/tranco-scan.mjs`, `scripts/tranco-deep-scan.mjs`) and is classified as non-interactive (`full` format) — it exists to keep internal load traffic out of the real-client `unknown` bucket.

## False Positive Reduction

- **MX Reputation**: Shared provider IPs (Google, M365, etc.) → DNSBL findings downgraded to `info`
- **Lookalikes**: Shared NS with primary domain → downgraded to `info` (defensive registration)
- **Shadow Domains**: Shared NS (≥2 overlap) → severity downgraded with ownership signal
- **TXT Hygiene**: Record accumulation tiered (25+→medium, 15-24→low); duplicate verifications consolidated
- **Non-mail SPF** (`check_mx`): No MX → verifies `v=spf1 -all`; missing SPF→medium, non-reject→low
