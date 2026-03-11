# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is this?

Blackveil DNS — open-source DNS & email security scanner, built as a Cloudflare Worker.
Exposes 15 tools via MCP Streamable HTTP (JSON-RPC 2.0) at `https://dns-mcp.blackveilsecurity.com/mcp`.
A 16th check (`check_subdomain_takeover`) runs only inside `scan_domain` and is not directly callable by clients.

**Version**: 1.0.0 — keep `SERVER_VERSION` in `src/index.ts` and `version` in `package.json` in sync.

## Repository Layout


## Commands

```bash
npm install                            # Install deps
npm test                               # Vitest + Istanbul coverage (Workers runtime)
npx vitest run test/check-spf.spec.ts  # Run a single test file
npm run dev                            # Local dev at localhost:8787
npm run typecheck                      # tsc --noEmit
npm run lint                           # ESLint
npm run lint:fix                       # ESLint with auto-fix
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

```
src/index.ts              — Hono app, middleware wiring, JSON-RPC dispatch, SSE transport

src/mcp/dispatch.ts       — JSON-RPC method → handler routing (initialize, tools/*, resources/*, ping)
src/mcp/request.ts        — Request body reading, JSON-RPC parsing/validation, header normalization
src/mcp/route-gates.ts    — Pre-dispatch guards (rate limits, session validation)

src/handlers/tools.ts     — tools/list + tools/call dispatch
src/handlers/tool-schemas.ts — TOOLS array (MCP tool definitions)
src/handlers/tool-args.ts — Domain/argument extraction and validation
src/handlers/tool-formatters.ts — mcpError/mcpText/formatCheckResult helpers
src/handlers/tool-execution.ts — Tool logging helpers
src/handlers/resources.ts — resources/list + resources/read (static docs)

src/tools/check-*.ts      — Individual DNS checks (SPF, DMARC, DKIM, MX, SSL, BIMI, TLS-RPT, lookalikes, etc.)
src/tools/*-analysis.ts   — Analysis helpers extracted from check modules
src/tools/spf-trust-surface.ts — SPF trust surface analysis (multi-tenant SaaS platform detection)
src/tools/lookalike-analysis.ts — Lookalike/typosquat domain permutation generator
src/tools/scan-domain.ts  — Parallel orchestrator for all checks → ScanScore + MaturityStage
src/tools/scan/           — Scan sub-helpers (format-report.ts, post-processing.ts, maturity-staging.ts)
src/tools/explain-finding.ts — Static explanation generator

src/lib/scoring.ts        — Re-export facade for scoring subsystem
src/lib/scoring-model.ts  — Types (Finding, CheckResult, ScanScore, CheckCategory, Severity) + buildCheckResult/createFinding
src/lib/scoring-engine.ts — IMPORTANCE_WEIGHTS, computeScanScore, scoreToGrade
src/lib/json-rpc.ts       — JSON-RPC 2.0 types, error codes, response builders
src/lib/session.ts        — KV-backed (optional) + in-memory fallback session management
src/lib/auth.ts           — Bearer token validation (constant-time XOR comparison)
src/lib/sse.ts            — SSE event formatting and Accept header checking
src/lib/dns.ts            — DNS-over-HTTPS facade (re-exports from dns-transport, dns-records, dns-types)
src/lib/sanitize.ts       — Domain validation, SSRF protection
src/lib/config.ts         — Centralized SSRF constants, DNS tuning, rate limit quotas (FREE_TOOL_DAILY_LIMITS, GLOBAL_DAILY_TOOL_LIMIT)
src/lib/cache.ts          — KV-backed + in-memory TTL cache, INFLIGHT dedup map, cacheSetDeferred()
src/lib/rate-limiter.ts   — KV-backed + in-memory per-IP rate limiting (delegates to rate-limiter-memory.ts)
src/lib/quota-coordinator.ts — Durable Objects-based distributed rate limiting across isolates
src/lib/analytics.ts      — Cloudflare Analytics Engine integration (fail-open telemetry)
src/lib/badge.ts          — SVG badge generator for /badge/:domain endpoint
src/lib/audit.ts          — Audit logging
src/lib/output-sanitize.ts — Markdown syntax sanitization for text output
src/lib/provider-signatures.ts — Email provider database and MX pattern matching
src/lib/provider-signature-source.ts — Runtime provider signature fetching/validation
src/lib/log.ts            — Structured JSON logging (logEvent, logError)

test/                     — One spec per source file
test/helpers/dns-mock.ts  — Shared fetch mock for DNS-over-HTTPS queries
```

### Request flow

```
MCP Client → POST /mcp → Origin check → Auth middleware → Body parse → JSON-RPC validate
  → mcp/route-gates (rate limit + session) → mcp/dispatch.ts → handlers/tools.ts
  → src/tools/check-*.ts → lib/dns.ts → Cloudflare DoH
```

### scan_domain orchestration

`scan_domain` runs **12 checks** in parallel via `Promise.allSettled`: SPF, DMARC, DKIM, DNSSEC, SSL, MTA-STS, NS, CAA, BIMI, TLS-RPT, subdomain takeover, and MX. Each has its own cache key (`cache:<domain>:check:<name>`), plus a top-level `cache:<domain>` key for the full scan result. Results are cached for 5 minutes. After scoring, `computeMaturityStage()` classifies the domain into a maturity stage (0-4: Unprotected → Hardened) based on SPF/DMARC/DKIM/MTA-STS/DNSSEC/BIMI presence and enforcement.

**Partial results on timeout**: When the 25s scan timeout fires, completed checks are preserved and missing checks receive a timeout finding. This avoids discarding work from checks that finished in 1-2s.

**Non-mail domain adjustment**: After all checks complete, if `check_mx` finds no MX records, `scan_domain` queries the parent domain's DMARC `sp=`/`p=` tag and then calls `adjustForNonMailDomain()` to downgrade critical/high email-auth findings (SPF, DMARC, DKIM, MTA-STS) to `info` severity. This significantly affects scores for non-mail domains.

## Conventions

- `createFinding()` + `buildCheckResult()` from `lib/scoring-model.ts` (re-exported via `lib/scoring.ts`) — never construct findings manually
- `validateDomain()` + `sanitizeDomain()` from `lib/sanitize.ts` for all domain inputs
- `mcpError()` / `mcpText()` from `handlers/tool-formatters.ts` for MCP response formatting
- `cacheGet()` / `cacheSet()` / `cacheSetDeferred()` from `lib/cache.ts` — supports KV and in-memory; `cacheSetDeferred()` wraps writes in `ctx.waitUntil()` to avoid blocking responses
- JSDoc (`/** */`) on exported functions
- `import type { ... }` for type-only imports
- All tool functions return `Promise<CheckResult>` (follow pattern in `check-spf.ts`)
- `check_mx` is dynamically imported in `handlers/tools.ts` (for test mock isolation — unlike other checks which are statically imported)
- MCP server key name is `"blackveil-dns"` across all client configs (README, docs, `.mcp.json`) — keep consistent
- SSRF config constants live in `src/lib/config.ts`, not `sanitize.ts` — edit there when modifying blocked TLDs, IP patterns, DNS tuning (`DOH_EDGE_CACHE_TTL`, `DNS_RETRY_BASE_DELAY_MS`, `INFLIGHT_CLEANUP_MS`), etc.
- `sanitize.ts` imports `punycode/` (trailing slash = npm package, not Node.js built-in) for IDN/Unicode domain support

### Error surfacing convention

Both `index.ts` and `handlers/tools.ts` sanitize errors. Only messages starting with specific prefixes pass through to clients:
- `'Missing required'`, `'Invalid'` (both files)
- `'Resource not found'` (index.ts only)
- `'Domain validation failed'` (tools.ts only)

All other errors become generic messages. New validation errors that need to reach clients **must start with one of these exact prefixes**.

## Scoring

Only `IMPORTANCE_WEIGHTS` drives `computeScanScore()` (the `CATEGORY_DISPLAY_WEIGHTS` map exists for display/registry purposes and is unused in scoring):

| Category | Importance | Critical? |
|----------|------------|-----------|
| DMARC | 22 | Yes |
| DKIM | 16 | Yes |
| SPF | 10 | Yes |
| SSL | 5 | Yes |
| Subdomain Takeover | 3 | Yes |
| DNSSEC | 2 | Yes |
| MTA-STS | 2 | No |
| MX | 2 | No |
| TLS-RPT | 1 | No |
| NS | 0 (informational) | No |
| CAA | 0 (informational) | No |
| BIMI | 0 (informational) | No |
| Lookalikes | 0 (informational) | No |

**Email bonus** (up to +8 points): Awarded when SPF score >= 57, DKIM present, and DMARC present. DMARC score >= 90 → 8pts, >= 70 → 5pts, otherwise 4pts.

**SPF trust-surface scoring**: Shared-platform SPF findings (e.g., Google Workspace, SendGrid) are informational by default. They are elevated to `medium`/`high` only when weak DMARC enforcement or relaxed alignment corroborates the exposure.

**Per-finding severity penalties**: Critical −40, High −25, Medium −15, Low −5, Info 0.

**`passed` flag**: `score >= 50` in `buildCheckResult`.

**Grades**: A+ (90+), A (85–89), B+ (80–84), B (75–79), C+ (70–74), C (65–69), D+ (60–64), D (55–59), E (50–54), F (<50).

## Security

- **SSRF protection**: `config.ts` defines blocked IPs/TLDs/rebinding services; `sanitize.ts` enforces them. Wrangler uses `global_fetch_strictly_public` compatibility flag.
- **Auth**: optional bearer token (`BV_API_KEY`), constant-time XOR comparison in `lib/auth.ts`
- **Rate limiting**: 50 req/min, 300 req/hr per IP via KV (in-memory fallback). Only `tools/call` counts against rate limits — protocol methods (`initialize`, `tools/list`, `resources/*`, `ping`, `notifications/*`) are exempt. Authenticated requests (valid `BV_API_KEY` bearer token) bypass rate limiting entirely. `check_lookalikes` has a separate daily quota of 10/day per IP (unauthenticated) with 60-minute result caching, due to high outbound query volume (~100 DoH queries per invocation).
- **Per-tool daily quotas**: `FREE_TOOL_DAILY_LIMITS` in `config.ts` caps unauthenticated usage per tool (e.g., `scan_domain`: 25/day, individual checks: 200/day). Global daily cap of 500k requests/day across all unauthenticated IPs (`GLOBAL_DAILY_TOOL_LIMIT`). Distributed via Durable Objects (`QuotaCoordinator`).
- **Request body max**: 10 KB on `/mcp`
- **IP sourcing**: only `cf-connecting-ip` — never `x-forwarded-for`
- **Error sanitization**: only known validation errors surface; unexpected → generic message
- **Origin validation**: MCP spec-compliant; rejects browser requests with unauthorized `Origin` header; configurable via `ALLOWED_ORIGINS` env var
- **Sessions**: idle TTL (30 min), sliding refresh on validate, optional KV-backed storage via `SESSION_STORE` with in-memory fallback. Missing session → 400; expired/terminated session → 404 (per MCP spec, triggers client re-initialization)

## Adding a New Tool

1. Create `src/tools/check-<name>.ts` → export async fn returning `CheckResult`
2. Add the `CheckCategory` value to the union type in `src/lib/scoring-model.ts`
3. Register in `src/handlers/tools.ts`: add to `TOOLS` array (schema) + `TOOL_REGISTRY` map (dispatch)
4. If the new check is part of `scan_domain`, add it to the parallel orchestration in `src/tools/scan-domain.ts` (use static import there, not dynamic)
5. Add `test/check-<name>.spec.ts` using the `dns-mock` helper pattern
6. Update README tools table

## Testing

- DNS mocked via `test/helpers/dns-mock.ts` — key helpers: `setupFetchMock()`, `mockTxtRecords()`, `createDohResponse()`, `mockFetchResponse()`, `mockFetchError()`
- Each spec must call `restore()` in `afterEach` to reset the fetch mock
- **Dynamic imports are required** in test functions for mock isolation — e.g. `const { checkSpf } = await import('../src/tools/check-spf')` inside each test helper
- Clear scan cache between cases when testing tool dispatch — both `cache:<domain>:check:<name>` (per-check) and `cache:<domain>` (full scan)
- `tsconfig.json` `types` must be under `compilerOptions` (not top-level) — Vitest pool requires this
- Config file is `vitest.config.mts` (not `.ts`)
- TXT record mocking: `mockTxtRecords()` wraps values in quotes (as Cloudflare DoH does); pass unquoted strings

## CI/CD

- `.github/workflows/ci.yml`: typecheck + lint + test on PRs and pushes to `main`
- `.github/workflows/security.yml`: Gitleaks secret/PII scan + `npm audit` dependency check on PRs and pushes to `main` (**required checks**)
- `.github/workflows/dns-security.yml`: weekly DNS security scan of blackveilsecurity.com via blackveil-dns-action
- `.gitleaks.toml`: custom rules for email addresses, real IP addresses, phone numbers, Cloudflare credentials; allowlists for test fixtures (`@example.com`, RFC 5737 IPs, private ranges)

**Branch protection** (configure in GitHub Settings → Branches → `main`): require PR reviews, require `build-and-test`, `Secret & PII scan`, and `Dependency audit` status checks to pass before merge, disable direct pushes to `main`.

## Deployment

The public `wrangler.jsonc` has placeholder KV bindings (commented out). Real deployments use a gitignored private config:

```bash
npm run deploy:private     # uses .dev/wrangler.deploy.jsonc
```

**First-time setup:**
1. Create KV namespaces: `npx wrangler kv namespace create "RATE_LIMIT"` (repeat for `SCAN_CACHE`, `SESSION_STORE`)
2. Copy `wrangler.jsonc` to `.dev/wrangler.deploy.jsonc`, uncomment the `kv_namespaces` block, and replace placeholder IDs with the real ones from step 1
3. Deploy: `npm run deploy:private`

**Important:** KV bindings are required for production. Without them, sessions are per-Worker-isolate and MCP clients will get intermittent 404 "session expired" errors when requests hit different isolates.

## Bindings

| Binding | Type | Purpose |
|---------|------|---------|
| `BV_API_KEY` | Secret/var | Optional bearer auth (open when empty) |
| `ALLOWED_ORIGINS` | var | Comma-separated allowed Origin headers (optional; same-origin allowed by default) |
| `RATE_LIMIT` | KV Namespace | Per-IP rate counters (**required in production**; in-memory fallback for dev) |
| `SCAN_CACHE` | KV Namespace | 5-min TTL result cache (**required in production**; in-memory fallback for dev) |
| `SESSION_STORE` | KV Namespace | Session state for cross-isolate continuity (**required in production**; in-memory fallback for dev) |
| `QUOTA_COORDINATOR` | Durable Object | Distributed rate limiting across isolates |
| `MCP_ANALYTICS` | Analytics Engine | Telemetry dataset (fail-open; optional) |
| `PROVIDER_SIGNATURES_URL` | var | Optional URL for runtime email provider signatures |

