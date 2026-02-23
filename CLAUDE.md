# CLAUDE.md — bv-mcp

## What is this?

Open-source MCP server for DNS security analysis, deployed as a Cloudflare Worker.
Exposes 10 tools via MCP Streamable HTTP (JSON-RPC 2.0) at `https://dns-mcp.blackveilsecurity.com/mcp`.

## Monorepo Layout

- `/` (root) — **Primary**: actively developed and deployed
- `/bv-dns-security-mcp/` — **Frozen snapshot**: separate distribution, own CI. Only updated for releases.

## Commands

```bash
npm install        # Install deps
npm test           # Vitest + Istanbul coverage (inside Workers runtime)
npm run dev        # Local dev at localhost:8787
npm run deploy     # Deploy via Wrangler
npm run typecheck  # tsc --noEmit
```

## Tech

- **Runtime**: Cloudflare Workers — no Node.js APIs (only `fetch`, `crypto`, Web APIs)
- **Framework**: Hono v4
- **TypeScript**: strict, ES2024 target, Bundler resolution
- **Testing**: Vitest + `@cloudflare/vitest-pool-workers`
- **Formatter**: Prettier (tabs, single quotes, semi, 140 width)

## Architecture

```
src/index.ts              — Hono app, auth middleware, JSON-RPC dispatch, SSE
src/handlers/tools.ts     — tools/list + tools/call dispatch
src/handlers/resources.ts — resources/list + resources/read (static docs)
src/tools/check-*.ts      — Individual DNS checks (SPF, DMARC, DKIM, etc.)
src/tools/scan-domain.ts  — Parallel orchestrator for all checks
src/tools/explain-finding.ts — Static explanation generator
src/lib/dns.ts            — DNS-over-HTTPS via Cloudflare DoH
src/lib/scoring.ts        — Weighted scoring engine
src/lib/sanitize.ts       — Domain validation, SSRF protection, MCP helpers
src/lib/cache.ts          — KV-backed + in-memory TTL cache
src/lib/rate-limiter.ts   — KV-backed + in-memory per-IP rate limiting
test/                     — One spec per source file + helpers/dns-mock.ts
```

## Conventions

- `createFinding()` + `buildCheckResult()` from `lib/scoring.ts` — never construct findings manually
- `validateDomain()` + `sanitizeDomain()` from `lib/sanitize.ts` for all domain inputs
- `mcpError()` / `mcpText()` from `lib/sanitize.ts` for MCP response formatting
- `cacheGet()` / `cacheSet()` from `lib/cache.ts` — supports KV and in-memory
- JSDoc (`/** */`) on exported functions
- `import type { ... }` for type-only imports
- All tool functions return `Promise<CheckResult>` (follow pattern in `check-spf.ts`)

## Security

- SSRF protection: `sanitize.ts` blocks private IPs, reserved TLDs, DNS rebinding services
- Auth: optional bearer token (`BV_API_KEY`), constant-time comparison
- Rate limiting: 10 req/min, 50 req/hr per IP via KV (in-memory fallback)
- Request body max: 10 KB on `/mcp`
- IP sourcing: only `cf-connecting-ip` — never `x-forwarded-for`
- Error sanitization: only known validation errors surface; unexpected → generic message

## Adding a New Tool

1. Create `src/tools/check-<name>.ts` → export async fn returning `CheckResult`
2. Register in `src/handlers/tools.ts` (`TOOLS` array + `handleToolsCall` switch)
3. Add `test/check-<name>.spec.ts` using `dns-mock` helper
4. Update README tools table

## Testing Notes

- DNS mocked via `test/helpers/dns-mock.ts` (`setupFetchMock()`, `mockTxtRecords()`, etc.)
- Each spec calls `restore()` in `afterEach`
- Clear scan cache between cases (`cache:<domain>:check:<name>`)
- Dynamic imports for mock isolation
- `tsconfig.json` `types` must be under `compilerOptions` (not top-level)

## Bindings

| Binding | Type | Purpose |
|---------|------|---------|
| `BV_API_KEY` | Secret/var | Optional bearer auth (open when empty) |
| `RATE_LIMIT` | KV Namespace | Per-IP rate counters (optional) |
| `SCAN_CACHE` | KV Namespace | 5-min TTL result cache (optional) |
