# bv-dns-security-mcp — Copilot Instructions

## Project Overview

MCP (Model Context Protocol) server for DNS security analysis, deployed as a **Cloudflare Worker** using **Hono** for routing. Exposes 10 tools over MCP Streamable HTTP transport (JSON-RPC 2.0) that analyze domain DNS security posture.

## Tech Stack

- **Runtime**: Cloudflare Workers (no Node.js APIs — only `fetch`, `crypto`, Web APIs)
- **Framework**: Hono v4
- **Language**: TypeScript (strict mode, ES2024 target, Bundler module resolution)
- **Testing**: Vitest with `@cloudflare/vitest-pool-workers` (tests run inside the Workers runtime)
- **Package manager**: npm
- **Deploy**: Wrangler CLI (`wrangler deploy`)

## Architecture

```
src/
  index.ts          — Hono app, auth middleware, JSON-RPC dispatch, SSE transport
  handlers/
    tools.ts        — MCP tools/list + tools/call dispatch
    resources.ts    — MCP resources/list + resources/read (static docs)
  tools/
    check-*.ts      — Individual DNS check tools (one per file)
    scan-domain.ts  — Orchestrates all checks in parallel
    explain-finding.ts — Plain-language explanation generator
  lib/
    dns.ts          — DNS-over-HTTPS queries via Cloudflare DoH
    scoring.ts      — Weighted scoring engine (Finding, CheckResult, ScanScore)
    sanitize.ts     — Domain validation, input cleaning, MCP response helpers
    cache.ts        — KV-backed scan result caching
    rate-limiter.ts — KV-backed per-IP rate limiting
```

## Conventions

### Code Style

- Use **JSDoc block comments** (`/** ... */`) for exported functions and modules
- Prefer `type` imports when importing only types: `import type { ... }`
- All tool check functions return `Promise<CheckResult>` and follow the pattern in `check-spf.ts`
- Use `createFinding()` and `buildCheckResult()` from `lib/scoring.ts` — never construct findings manually
- Use `validateDomain()` and `sanitizeDomain()` from `lib/sanitize.ts` for all domain inputs
- Use `mcpError()` and `mcpText()` from `lib/sanitize.ts` for MCP response formatting

### Security

- **No Node.js APIs** — Workers runtime only (`fetch`, `crypto.getRandomValues`, `TextEncoder`, etc.)
- **SSRF protection**: All domain inputs must pass through `sanitize.ts` validation (blocks private IPs, reserved TLDs, DNS rebinding services)
- **Auth**: Bearer token with constant-time comparison (`timingSafeEqual` in `index.ts`)
- **Rate limiting**: Per-IP via KV (10 req/min, 50 req/hr)
- **Request size**: Max 10KB body on `/mcp`
- **IP sourcing**: Only `cf-connecting-ip` header — never fall back to `x-forwarded-for`

### Adding a New Tool

1. Create `src/tools/check-<name>.ts` exporting an async function returning `CheckResult`
2. Register the tool schema in `src/handlers/tools.ts` (add to `TOOLS` array and `handleToolsCall` switch)
3. Add tests in `test/check-<name>.spec.ts` using the `dns-mock` helper
4. Update the README tools table

### Testing

- Tests live in `test/` and use `vitest` with Cloudflare Workers pool
- DNS calls are mocked via `test/helpers/dns-mock.ts` — use `setupFetchMock()` and `mockTxtRecords()` / similar helpers
- Each test file calls `restore()` in `afterEach` to reset mocks
- Run tests: `npm test` (includes coverage via Istanbul)
- Tests import source directly (e.g., `import('../src/tools/check-spf')`) — dynamic imports for mock isolation

### Types

- Scoring types: `Severity`, `CheckCategory`, `Finding`, `CheckResult`, `ScanScore` (from `lib/scoring.ts`)
- DNS types: `DnsAnswer`, `DohResponse`, `RecordType` (from `lib/dns.ts`)
- Environment bindings: `Env` type in `worker-configuration.d.ts` (bindings: `SECRET`, `RATE_LIMIT`, `SCAN_CACHE`)

## Build & Deploy

```bash
npm install        # Install dependencies
npm run dev        # Local dev server at localhost:8787
npm test           # Run tests with coverage
npm run deploy     # Deploy to Cloudflare Workers
```

## CI/CD

GitHub Actions (`.github/workflows/ci.yml`): runs tests on PR/push to `main`, auto-deploys on push to `main` via `cloudflare/wrangler-action`.
