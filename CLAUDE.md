# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is this?

Blackveil DNS — open-source DNS & email security scanner, deployed as a Cloudflare Worker.
Exposes 11 tools via MCP Streamable HTTP (JSON-RPC 2.0) at `https://dns-mcp.blackveilsecurity.com/mcp`.
A 12th check (`check_subdomain_takeover`) runs only inside `scan_domain` and is not directly callable by clients.

**Version**: 1.0.3 — keep `SERVER_VERSION` in `src/index.ts` and `version` in `package.json` in sync.

## Repository Layout

- `/.dev/` — **Gitignored**: local dev config (KV namespace IDs, custom domains, deploy overrides). Contains `wrangler.local.jsonc` used by `npm run deploy`.
- `/scripts/` — Utility scripts (benchmark, etc.)

## Commands

```bash
npm install                            # Install deps
npm test                               # Vitest + Istanbul coverage (Workers runtime)
npx vitest run test/check-spf.spec.ts  # Run a single test file
npm run dev                            # Local dev at localhost:8787
npm run deploy                         # Deploy via Wrangler
npm run typecheck                      # tsc --noEmit
npm run setup:kv                       # Create KV namespaces (first time only)
```

## Tech

- **Runtime**: Cloudflare Workers — no Node.js APIs (only `fetch`, `crypto`, Web APIs)
- **Framework**: Hono v4
- **TypeScript**: strict, ES2024 target, Bundler resolution, `isolatedModules: true`
- **Testing**: Vitest + `@cloudflare/vitest-pool-workers` (tests execute inside Workers runtime)
- **Formatter**: Prettier (tabs, single quotes, semi, 140 width)
- **Package manager**: npm

## Architecture

```
src/index.ts              — Hono app, middleware wiring, JSON-RPC dispatch, SSE transport
src/handlers/tools.ts     — tools/list + tools/call dispatch (TOOLS array + TOOL_REGISTRY)
src/handlers/resources.ts — resources/list + resources/read (static docs)
src/tools/check-*.ts      — Individual DNS checks (SPF, DMARC, DKIM, MX, SSL, etc.)
src/tools/scan-domain.ts  — Parallel orchestrator for all checks → ScanScore
src/tools/explain-finding.ts — Static explanation generator
src/lib/json-rpc.ts       — JSON-RPC 2.0 types, error codes, response builders
src/lib/session.ts        — KV-backed (optional) + in-memory fallback session management
src/lib/auth.ts           — Bearer token validation (constant-time XOR comparison)
src/lib/sse.ts            — SSE event formatting and Accept header checking
src/lib/dns.ts            — DNS-over-HTTPS via Cloudflare DoH (cloudflare-dns.com/dns-query)
src/lib/scoring.ts        — Weighted scoring engine (Finding, CheckResult, ScanScore types)
src/lib/sanitize.ts       — Domain validation, SSRF protection, MCP response helpers
src/lib/config.ts         — Centralized SSRF constants (blocked TLDs, IPs, rebinding services, domain limits)
src/lib/cache.ts          — KV-backed + in-memory TTL cache
src/lib/rate-limiter.ts   — KV-backed + in-memory per-IP rate limiting
src/lib/log.ts            — Structured JSON logging (logEvent, logError)
test/                     — One spec per source file
test/helpers/dns-mock.ts  — Shared fetch mock for DNS-over-HTTPS queries
```

### Request flow

```
MCP Client → POST /mcp → Auth middleware → Rate limiter → JSON-RPC dispatch
  → tools/call → handlers/tools.ts → src/tools/check-*.ts → lib/dns.ts → Cloudflare DoH
```

### scan_domain orchestration

`scan_domain` runs **10 checks** in parallel via `Promise.all`: SPF, DMARC, DKIM, DNSSEC, SSL, MTA-STS, NS, CAA, subdomain takeover, and MX. Each has its own cache key (`cache:<domain>:check:<name>`), plus a top-level `cache:<domain>` key for the full scan result. Results are cached for 5 minutes.

**Non-mail domain adjustment**: After all checks complete, if `check_mx` finds no MX records, `scan_domain` queries the parent domain's DMARC `sp=`/`p=` tag and then calls `adjustForNonMailDomain()` to downgrade critical/high email-auth findings (SPF, DMARC, DKIM, MTA-STS) to `info` severity. This significantly affects scores for non-mail domains.

## Conventions

- `createFinding()` + `buildCheckResult()` from `lib/scoring.ts` — never construct findings manually
- `validateDomain()` + `sanitizeDomain()` from `lib/sanitize.ts` for all domain inputs
- `mcpError()` / `mcpText()` from `lib/sanitize.ts` for MCP response formatting
- `cacheGet()` / `cacheSet()` from `lib/cache.ts` — supports KV and in-memory
- JSDoc (`/** */`) on exported functions
- `import type { ... }` for type-only imports
- All tool functions return `Promise<CheckResult>` (follow pattern in `check-spf.ts`)
- `check_mx` is dynamically imported in `handlers/tools.ts` (for test mock isolation — unlike other checks which are statically imported)
- SSRF config constants live in `src/lib/config.ts`, not `sanitize.ts` — edit there when modifying blocked TLDs, IP patterns, etc.
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
| SPF | 19 | Yes |
| DKIM | 10 | Yes |
| SSL | 8 | Yes |
| DNSSEC | 3 | Yes |
| MTA-STS | 3 | No |
| NS | 0 (informational) | No |
| CAA | 0 (informational) | No |
| Subdomain Takeover | 0 (informational) | No |
| MX | 0 (informational) | No |

**Email bonus** (up to +5 points): Awarded when SPF score >= 57, DKIM present, and DMARC present. DMARC score >= 90 → 5pts, >= 70 → 3pts, otherwise 2pts.

**Per-finding severity penalties**: Critical −40, High −25, Medium −15, Low −5, Info 0.

**`passed` flag**: `score >= 50` in `buildCheckResult`.

**Grades**: A+ (90+), A (85–89), B+ (80–84), B (75–79), C+ (70–74), C (65–69), D+ (60–64), D (55–59), E (50–54), F (<50).

## Security

- **SSRF protection**: `config.ts` defines blocked IPs/TLDs/rebinding services; `sanitize.ts` enforces them. Wrangler uses `global_fetch_strictly_public` compatibility flag.
- **Auth**: optional bearer token (`BV_API_KEY`), constant-time XOR comparison in `lib/auth.ts`
- **Rate limiting**: 10 req/min, 100 req/hr per IP via KV (in-memory fallback). Only `tools/call` counts against rate limits — protocol methods (`initialize`, `tools/list`, `resources/*`, `ping`, `notifications/*`) are exempt. Authenticated requests (valid `BV_API_KEY` bearer token) bypass rate limiting entirely.
- **Request body max**: 10 KB on `/mcp`
- **IP sourcing**: only `cf-connecting-ip` — never `x-forwarded-for`
- **Error sanitization**: only known validation errors surface; unexpected → generic message
- **Sessions**: idle TTL (30 min), sliding refresh on validate, optional KV-backed storage via `SESSION_STORE` with in-memory fallback

## Adding a New Tool

1. Create `src/tools/check-<name>.ts` → export async fn returning `CheckResult`
2. Add the `CheckCategory` value to the union type in `src/lib/scoring.ts`
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

- `.github/workflows/ci.yml`: typecheck + test on PRs and pushes to `main` (no deployment)
- `.github/workflows/release.yml`: typecheck + test + `wrangler deploy` + GitHub release on tag push (`v*`). Uses `production` GitHub environment. Requires `CLOUDFLARE_API_TOKEN` secret.

## Bindings

| Binding | Type | Purpose |
|---------|------|---------|
| `BV_API_KEY` | Secret/var | Optional bearer auth (open when empty) |
| `RATE_LIMIT` | KV Namespace | Per-IP rate counters (optional, in-memory fallback) |
| `SCAN_CACHE` | KV Namespace | 5-min TTL result cache (optional, in-memory fallback) |
| `SESSION_STORE` | KV Namespace | Session state for cross-isolate continuity (optional, in-memory fallback) |

After `npm run setup:kv`, copy `wrangler.jsonc` to `.dev/wrangler.local.jsonc` and paste the printed namespace IDs there. The `.dev/` directory is gitignored.
