# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is this?

BLACKVEIL Scanner — open-source DNS/email security analysis and remediation platform, deployed as a Cloudflare Worker.
Exposes 12 tools via MCP Streamable HTTP (JSON-RPC 2.0) at `https://dns-mcp.blackveilsecurity.com/mcp`.

**Version**: 1.0.0 — keep `SERVER_VERSION` in `src/index.ts` and `version` in `package.json` in sync.

## Monorepo Layout

- `/` (root) — **Primary**: actively developed and deployed
- `/bv-dns-security-mcp/` — **Frozen snapshot**: separate distribution, own CI. Do not modify during development; only updated intentionally for releases.

## Commands

```bash
npm install                          # Install deps
npm test                             # Vitest + Istanbul coverage (Workers runtime)
npx vitest run test/check-spf.spec.ts  # Run a single test file
npm run dev                          # Local dev at localhost:8787
npm run deploy                       # Deploy via Wrangler
npm run typecheck                    # tsc --noEmit
npm run setup:kv                     # Create KV namespaces (first time only)
```

## Tech

- **Runtime**: Cloudflare Workers — no Node.js APIs (only `fetch`, `crypto`, Web APIs)
- **Framework**: Hono v4
- **TypeScript**: strict, ES2024 target, Bundler resolution
- **Testing**: Vitest + `@cloudflare/vitest-pool-workers` (tests execute inside Workers runtime)
- **Formatter**: Prettier (tabs, single quotes, semi, 140 width)
- **Package manager**: npm

## Architecture

```
src/index.ts              — Hono app, auth middleware, JSON-RPC dispatch, SSE transport
src/handlers/tools.ts     — tools/list + tools/call dispatch (TOOLS array + switch)
src/handlers/resources.ts — resources/list + resources/read (static docs)
src/tools/check-*.ts      — Individual DNS checks (SPF, DMARC, DKIM, MX, SSL, etc.)
src/tools/scan-domain.ts  — Parallel orchestrator for all checks → ScanScore
src/tools/explain-finding.ts — Static explanation generator
src/lib/dns.ts            — DNS-over-HTTPS via Cloudflare DoH (cloudflare-dns.com/dns-query)
src/lib/scoring.ts        — Weighted scoring engine (Finding, CheckResult, ScanScore types)
src/lib/sanitize.ts       — Domain validation, SSRF protection, MCP response helpers
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

`scan_domain` runs all individual checks in parallel via `Promise.all`, each with its own cache key (`cache:<domain>:check:<name>`). Results are cached for 5 minutes.

## Conventions

- `createFinding()` + `buildCheckResult()` from `lib/scoring.ts` — never construct findings manually
- `validateDomain()` + `sanitizeDomain()` from `lib/sanitize.ts` for all domain inputs
- `mcpError()` / `mcpText()` from `lib/sanitize.ts` for MCP response formatting
- `cacheGet()` / `cacheSet()` from `lib/cache.ts` — supports KV and in-memory
- JSDoc (`/** */`) on exported functions
- `import type { ... }` for type-only imports
- All tool functions return `Promise<CheckResult>` (follow pattern in `check-spf.ts`)
- `check_mx` is dynamically imported in `handlers/tools.ts` (unlike other checks which are statically imported)

## Security

- **SSRF protection**: `sanitize.ts` blocks private IPs, reserved TLDs, DNS rebinding services. Wrangler uses `global_fetch_strictly_public` compatibility flag.
- **Auth**: optional bearer token (`BV_API_KEY`), constant-time XOR comparison in `index.ts`
- **Rate limiting**: 10 req/min, 50 req/hr per IP via KV (in-memory fallback)
- **Request body max**: 10 KB on `/mcp`
- **IP sourcing**: only `cf-connecting-ip` — never `x-forwarded-for`
- **Error sanitization**: only known validation errors surface; unexpected → generic message

## Adding a New Tool

1. Create `src/tools/check-<name>.ts` → export async fn returning `CheckResult`
2. Add the `CheckCategory` value to the union type in `src/lib/scoring.ts`
3. Register in `src/handlers/tools.ts`: add to `TOOLS` array (schema) + `handleToolsCall` switch (dispatch)
4. If the new check is part of `scan_domain`, add it to the parallel orchestration in `src/tools/scan-domain.ts`
5. Add `test/check-<name>.spec.ts` using the `dns-mock` helper pattern
6. Update README tools table

## Testing

- DNS mocked via `test/helpers/dns-mock.ts` — key helpers: `setupFetchMock()`, `mockTxtRecords()`, `createDohResponse()`, `mockMultiQuery()`
- Each spec must call `restore()` in `afterEach` to reset the fetch mock
- **Dynamic imports are required** in test functions for mock isolation — e.g. `const { checkSpf } = await import('../src/tools/check-spf')` inside each test helper
- Clear scan cache between cases when testing tool dispatch (`cache:<domain>:check:<name>`)
- `tsconfig.json` `types` must be under `compilerOptions` (not top-level) — Vitest pool requires this
- Run a single test: `npx vitest run test/<filename>.spec.ts`

## CI/CD

- `.github/workflows/ci.yml`: typecheck + test on PRs to `main`; auto-deploy on push to `main` via `wrangler deploy`
- `.github/workflows/release.yml`: deploy on tag push (`v*`)
- Deploy requires `CLOUDFLARE_API_TOKEN` secret in GitHub

## Bindings

| Binding | Type | Purpose |
|---------|------|---------|
| `BV_API_KEY` | Secret/var | Optional bearer auth (open when empty) |
| `RATE_LIMIT` | KV Namespace | Per-IP rate counters (optional, in-memory fallback) |
| `SCAN_CACHE` | KV Namespace | 5-min TTL result cache (optional, in-memory fallback) |

After `npm run setup:kv`, paste the printed namespace IDs into `wrangler.jsonc`.
