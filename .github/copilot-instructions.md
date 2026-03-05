# Copilot Workspace Instructions

These instructions are for contributors and coding agents working in `bv-mcp`.

## Project Snapshot

- Runtime: Cloudflare Workers (Web APIs only, no Node.js runtime APIs).
- Framework: Hono v4.
- Protocol: MCP Streamable HTTP (JSON-RPC 2.0) on `/mcp`.
- Language: TypeScript strict mode.
- Testing: Vitest running in Workers runtime.

## Build, Test, and Dev Commands

- Install dependencies: `npm install`
- Local dev server: `npm run dev`
- Run tests with coverage: `npm test`
- Typecheck: `npm run typecheck`
- Lint: `npm run lint`
- Deploy (uses local config): `npm run deploy`
- First-time KV setup: `npm run setup:kv`

## Architecture and Boundaries

- `src/index.ts`: Hono app setup, middleware, JSON-RPC routing, SSE transport.
- `src/handlers/tools.ts`: `tools/list` and `tools/call` dispatch.
- `src/handlers/tool-schemas.ts`: tool schemas exposed to clients.
- `src/tools/check-*.ts`: individual DNS/email checks.
- `src/tools/scan-domain.ts`: runs checks in parallel and computes overall score.
- `src/lib/dns.ts`: DNS-over-HTTPS calls to Cloudflare DoH.
- `src/lib/sanitize.ts`: domain validation and MCP-safe response helpers.
- `src/lib/scoring.ts`: finding and scoring model.
- `src/lib/cache.ts`, `src/lib/rate-limiter.ts`, `src/lib/session.ts`: KV-backed with in-memory fallback.

## Non-Negotiable Conventions

- Always validate user-provided domains with `validateDomain()` and `sanitizeDomain()` from `src/lib/sanitize.ts`.
- Always build findings/check results with `createFinding()` and `buildCheckResult()` from `src/lib/scoring.ts`.
- Tool check functions should return `Promise<CheckResult>`.
- Use `mcpError()` / `mcpText()` for MCP response formatting.
- Keep `SERVER_VERSION` in `src/index.ts` and `version` in `package.json` synchronized.

## Error Message Surfacing Rules

Only specific error message prefixes are allowed through to clients; all others are sanitized.

- Allowed prefixes include: `Missing required`, `Invalid`, `Domain validation failed`.
- When adding new validation errors intended for clients, use one of the allowed prefixes.

## Testing Conventions

- Use `test/helpers/dns-mock.ts` helpers for DoH mocking.
- Restore fetch mocks in `afterEach`.
- Use dynamic imports in tests when needed for isolation, following existing check specs.
- Clear both scan cache layers in tests when validating cache behavior (`cache:<domain>:check:<name>` and `cache:<domain>`).

## Security and Runtime Constraints

- SSRF controls are configured in `src/lib/config.ts` and enforced by `src/lib/sanitize.ts`.
- Do not add direct resolver/network behavior that bypasses `src/lib/dns.ts` for scan logic.
- Use `cf-connecting-ip` for client IP behavior; do not trust `x-forwarded-for`.
- Keep request-body limits and auth/rate-limiter semantics consistent with `src/index.ts` and `src/lib/rate-limiter.ts`.

## Scan-Domain Specific Behavior

- `scan_domain` runs checks in parallel (`Promise.all`) and applies score aggregation.
- If `check_mx` finds no mail setup, non-mail-domain severity adjustments can downgrade email-auth findings.
- Avoid serializing subdomain takeover probe logic; preserve parallel probing to prevent latency regressions.

## Common Pitfalls

- Breaking test isolation by switching dynamic imports to static imports in check tests.
- Forgetting that `check_mx` dispatch in `handlers/tools.ts` is dynamic for test mock isolation.
- Updating scoring/weights without matching docs and tests.
- Editing SSRF rules outside `src/lib/config.ts`.

## Key Files to Open First

- `CLAUDE.md`
- `README.md`
- `src/index.ts`
- `src/handlers/tools.ts`
- `src/tools/check-spf.ts`
- `src/tools/scan-domain.ts`
- `src/lib/scoring.ts`
- `test/check-spf.spec.ts`

## Change Checklist

Before finishing a change:

- Run `npm run typecheck`
- Run `npm test` (or targeted vitest spec during iteration)
- Confirm tool names/schemas and dispatch registry stay aligned
- Confirm docs are updated if behavior or limits changed