# Contributing to Blackveil DNS

Thanks for your interest in contributing! Blackveil DNS is an open-source DNS & email security scanner exposed as an MCP server.

## Getting Started

```bash
git clone https://github.com/MadaBurns/bv-mcp.git
cd bv-mcp
npm install
npm test           # Run tests (1090+ tests, ~90% coverage)
npm run dev        # Local dev server at localhost:8787
npm run typecheck  # Type-check without emitting
```


## Development

- **Runtime**: Cloudflare Workers — no Node.js APIs (`fetch`, `crypto`, Web APIs only)
- **Framework**: Hono v4
- **Tests**: Vitest with `@cloudflare/vitest-pool-workers` (runs inside Workers runtime)
- **Formatter**: Prettier (tabs, single quotes, semicolons, 140 print width)

Run `npx prettier --write 'src/**/*.ts' 'test/**/*.ts'` before committing.

## Adding a New Tool

1. Create `src/tools/check-<name>.ts` → export async fn returning `CheckResult`
2. Add the `CheckCategory` value to the union type in `src/lib/scoring-model.ts` + `CATEGORY_DISPLAY_WEIGHTS`
3. Add to `IMPORTANCE_WEIGHTS` in `src/lib/scoring-engine.ts`
4. Add to `DEFAULT_SCORING_CONFIG` weights, profileWeights (all 5 profiles), and baselineFailureRates in `src/lib/scoring-config.ts`
5. Add to all 5 `PROFILE_WEIGHTS` maps in `src/lib/context-profiles.ts`
6. Register in `src/handlers/tool-schemas.ts` (TOOLS array) + `src/handlers/tools.ts` (import + TOOL_REGISTRY)
7. Add to `FREE_TOOL_DAILY_LIMITS` in `src/lib/config.ts`
8. Add explanation templates in `src/tools/explain-finding-data.ts`
9. If the new check is part of `scan_domain`, add it to the parallel orchestration in `src/tools/scan-domain.ts`
10. Add `test/check-<name>.spec.ts` using the `dns-mock` helper pattern
11. Update the README tools table

Follow the pattern in `src/tools/check-spf.ts` — use `createFinding()` and `buildCheckResult()` from `lib/scoring.ts`, never construct findings manually.

## Testing

- DNS calls are mocked via `test/helpers/dns-mock.ts`
- Each test file calls `restore()` in `afterEach` to reset mocks
- Tests that call tool handlers should clear scan cache between cases
- Dynamic imports are used for mock isolation

## Pull Requests

- Keep PRs focused — one feature or fix per PR
- All tests must pass (`npm test`)
- Type check must pass (`npm run typecheck`)
- Format with Prettier before submitting

## Security

If you discover a security vulnerability, please email security@blackveilsecurity.com instead of opening a public issue.

## License

By contributing, you agree that your contributions will be licensed under the [Business Source License 1.1](LICENSE).
