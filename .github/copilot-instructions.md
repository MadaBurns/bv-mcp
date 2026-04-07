# Project Guidelines

## Build and Test
- Install dependencies: `npm install`
- Build package and CLI bundle: `npm run build`
- Build subpackage: `npm -w packages/dns-checks run build`
- Run local dev server: `npm run dev`
- Run tests (Workers runtime): `npm test`
- Run subpackage tests: `npm -w packages/dns-checks run test`
- Run single test file: `npx vitest run test/check-spf.spec.ts`
- Run chaos test (all 9 MCP client types): `python3 scripts/chaos/chaos-test-clients.py`
- Typecheck: `npm run typecheck`
- Typecheck subpackage: `npm -w packages/dns-checks run typecheck`
- Lint: `npm run lint`
- Auto-fix lint issues: `npm run lint:fix`
- Enable pre-commit hooks: `git config core.hooksPath .githooks`
- Deploy private worker config: `npm run deploy:private`

## Runtime and Code Style
- Target Cloudflare Workers APIs only. Do not use Node-only APIs in runtime code.
- Keep TypeScript strict and preserve existing `module`/`isolatedModules` patterns.
- WASM Policy Engine: Integrated `bv-wasm-core` (Rust → WASM) for tamper-resistant permission checks (`checkPermission`) and token estimation (`estimateTokens`). Source: `crates/bv-wasm-core/`.
- For findings/results, use `createFinding()` and `buildCheckResult()` from `src/lib/scoring.ts` rather than manual object construction.
- Validate and normalize all domain input with `validateDomain()` and `sanitizeDomain()` from `src/lib/sanitize.ts`.
- Keep changes minimal and avoid unrelated refactors.

## Architecture
- HTTP entrypoint and middleware: `src/index.ts`
- Internal service binding routes: `src/internal.ts`
- Shared MCP execution flow: `src/mcp/execute.ts` and `src/mcp/dispatch.ts`
- Tool dispatch and `TOOL_REGISTRY` map: `src/handlers/tools.ts`
- Tool definitions (44 tools): `src/schemas/tool-definitions.ts` (`TOOLS` array, `TOOL_DEFS`)
- Tool argument Zod schemas: `src/schemas/tool-args.ts` (`TOOL_SCHEMA_MAP`)
- Legacy re-export shim (deprecated): `src/handlers/tool-schemas.ts` — import from `src/schemas/` in new code
- Individual DNS checks: `src/tools/check-*.ts` (with extracted `*-analysis.ts` helpers)
- Parallel orchestration and scoring output: `src/tools/scan-domain.ts`
- Response formatting and structured JSON: `src/handlers/tool-formatters.ts` (`buildToolContent`, `mcpText`, `mcpError`)
- Client type detection (format auto-selection): `src/lib/client-detection.ts`
- DNS multi-resolver and transport: `src/lib/dns-multi-resolver.ts`, `src/lib/dns-transport.ts`, `src/lib/dns-types.ts`
- Core cache/session/rate-limit utilities: `src/lib/`
- Cron Trigger alerting: `src/scheduled.ts`
- Native stdio MCP transport (CLI): `src/stdio.ts`
- Monorepo structure: Root Cloudflare Worker + `packages/dns-checks` runtime-agnostic subpackage

## Project Conventions
- Keep versions synchronized between `package.json` version and `src/lib/server-version.ts` `SERVER_VERSION`.
- Error messages intended for clients must start with safe prefixes (for example: `Missing required`, `Invalid`, `Domain validation failed`, `Resource not found`).
- Rate limiting for MCP should return HTTP 200 with JSON-RPC error code `-32029` (not HTTP 429).
- Output format behavior:
  - `format=compact` for interactive clients (claude_code, cursor, vscode, claude_desktop, windsurf) — plain text only.
  - `format=full` for non-interactive clients — includes `<!-- STRUCTURED_RESULT -->` JSON block via `buildToolContent()`.
  - All tools return structured JSON in full mode. Use `buildToolContent(text, structuredData, format)` from `src/handlers/tool-formatters.ts`.
- `scan` is a supported alias for `scan_domain`.
- `TOOL_REGISTRY` in `src/handlers/tools.ts` maps check tool names to `{ cacheKey, execute, cacheTtlSeconds? }`. Add new check tools here, not via switch cases.

## Caching and Performance
- Per-check cache key pattern: `cache:<domain>:check:<name>`
- Scan-level cache key pattern: `cache:<domain>`
- Profile cache key pattern: `cache:<domain>:profile:<profile>`
- Cross-isolate dedup sentinel key pattern: `cache:<domain>:check:<name>:computing` (30s TTL)
- For `force_refresh` flows, propagate `skipCache` through `runWithCache()`.
- Circuit breaker wraps all QuotaCoordinator DO calls (3 failures → 60s cooldown).
- DNS secondary confirmation races bv-dns and Google in parallel via `Promise.allSettled`.
- Per-tier concurrency limits (`TIER_CONCURRENT_LIMITS`) enforced per-isolate in `execute.ts`.

## Testing Patterns
- Use `test/helpers/dns-mock.ts` utilities for DNS mocking.
- Restore fetch mocks in `afterEach`.
- In tests that need mock isolation for `check_mx`, use dynamic imports inside test bodies.
- Clear both scan-level and per-check cache entries between relevant test cases.
- Tools in `format=full` (default for non-interactive) return 2 content items (text + structured JSON). Assert `toHaveLength(2)` for success paths, `toHaveLength(1)` for compact mode.
- Chaos testing: Run `python3 scripts/chaos/chaos-test-clients.py` to validate behavior across all 9 MCP client types.

## Security and Internal Routes
- Keep SSRF protections and domain sanitization paths intact.
- Public traffic must not access `/internal/*` routes.
- Do not expose secrets in code, logs, or committed files.
- Do not hardcode API keys in scripts or client config examples; load from environment variables (for example `BV_API_KEY`).
- See `.github/instructions/security.instructions.md` for the full threat model and defense layers.

## Documentation Map (Link, Do Not Duplicate)
- Canonical architecture and repository conventions: `CLAUDE.md`
- **Architecture diagrams (Mermaid): `docs/architecture.md`** — system overview, request flows, scoring model, security layers
- User-facing overview and quick start: `README.md`
- Contributor workflow and expectations: `CONTRIBUTING.md`
- Client setup and transport details: `docs/client-setup.md`
- Scoring model details: `docs/scoring.md`
- Documentation writing conventions: `docs/style-guide.md`
- Troubleshooting guide: `docs/troubleshooting.md`
- Security policy and disclosure process: `SECURITY.md`
