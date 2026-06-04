# Contributing to Blackveil DNS

Thanks for your interest in contributing! Blackveil DNS is a source-available DNS & email security scanner exposed as an MCP server.

## Getting Started

```bash
git clone https://github.com/MadaBurns/bv-mcp.git
cd bv-mcp
npm ci
npm test           # Run the Vitest suite
npx wrangler dev   # Local Worker dev server at localhost:8787
npm run typecheck  # Type-check without emitting
```


## Development

- **Runtime**: Cloudflare Workers — no Node.js APIs (`fetch`, `crypto`, Web APIs only)
- **Framework**: Hono v4
- **Tests**: Vitest with `@cloudflare/vitest-pool-workers` (runs inside Workers runtime)
- **Formatter**: Prettier (tabs, single quotes, semicolons, 140 print width)

Run `npx prettier --write 'src/**/*.ts' 'test/**/*.ts'` before committing large formatting changes.

## Adding a New Tool

1. Create `src/tools/check-<name>.ts` → export async fn returning `CheckResult`
2. Add the `CheckCategory` value to the union type in `packages/dns-checks/src/types.ts` + `CATEGORY_TIERS` (tier classification) + `CATEGORY_DISPLAY_WEIGHTS` (`scoring/model.ts` only re-exports these — edit `types.ts`)
3. Add to `IMPORTANCE_WEIGHTS` in `packages/dns-checks/src/scoring/engine.ts`
4. Add to `DEFAULT_SCORING_CONFIG` weights, profileWeights (all 6 profiles), and baselineFailureRates in `packages/dns-checks/src/scoring/config.ts`
5. Add to all 6 `PROFILE_WEIGHTS` maps in `packages/dns-checks/src/scoring/profiles.ts`
6. Rebuild the package: `npm -w packages/dns-checks run build` (the Worker and tests import the built `dist/`, not `src/`)
7. Register in `src/schemas/tool-definitions.ts` (TOOL_DEFS) + `src/handlers/tools.ts` (import + TOOL_REGISTRY)
8. Add to `FREE_TOOL_DAILY_LIMITS` in `src/lib/config.ts`
9. Add explanation templates in `src/tools/explain-finding-data.ts`
10. If the new check is part of `scan_domain`, add it to the `CHECK_DISPATCH` registry in `src/tools/scan-domain.ts` (the single dispatch source — `SCAN_CATEGORIES` and the retry switch both derive from it)
11. Add `test/check-<name>.spec.ts` using the `dns-mock` helper pattern
12. Bump the single tool-count tripwire `EXPECTED_TOOL_COUNT` in `test/audits/tool-count-ssot.audit.test.ts` (all other counts derive from the registry) and update the README tools table

Follow the pattern in `src/tools/check-spf.ts` — use `createFinding()` and `buildCheckResult()` from `@blackveil/dns-checks/scoring`, never construct findings manually.

> The full SSOT checklist (the additional audits a new tool trips, scoring-snapshot bumps, generated WASM permissions, etc.) lives in the repo's `CLAUDE.md` "Adding a New Tool" section.

## Testing

- DNS calls are mocked via `test/helpers/dns-mock.ts`
- Each test file calls `restore()` in `afterEach` to reset mocks
- Tests that call tool handlers should clear scan cache between cases
- Dynamic imports are used for mock isolation
- **Scoring specs** (`model`/`profiles`/`config`/`engine`) keep their assertions and expected values once in `packages/dns-checks/src/__tests__/scoring/scoring-<name>.suite.ts`. The eight `scoring-<name>.spec.ts` files (one per name in that dir, one per name in `test/`) are thin wrappers that inject the SOURCE vs the BUILT `@blackveil/dns-checks/scoring` module so source↔build drift is caught — **edit the `.suite.ts`, not the wrappers**.

## Public Fixtures

Use synthetic fixtures only. There must be no real customer data, real tenant lists, customer emails, public IP literals, internal hostnames, generated reports, PDFs, CSC artifacts, or private Wrangler config in commits.

Safe examples:

- Domains: `tenant-001.example.test`, `mail.example.com`, `service.example.invalid`
- Emails: `admin@example.test`, `security@example.com`
- IPs: RFC 5737 ranges such as `192.0.2.10`, `198.51.100.20`, and `203.0.113.30`

Run `npm run audit:repo-safety` and `npm run audit:oss-safety` before opening a PR that changes fixtures, docs, scripts, workflow files, or package publishing metadata.

## Pull Requests

- Keep PRs focused — one feature or fix per PR
- All tests must pass (`npm test`)
- Chaos tests must pass for client-impacting changes (`python3 scripts/chaos/chaos-test-clients.py`)
- Type check must pass (`npm run typecheck`)
- Format with Prettier before submitting

## Security

If you discover a security vulnerability, please email security@blackveilsecurity.com instead of opening a public issue.

## License

By contributing, you agree that your contributions will be licensed under the [Business Source License 1.1](LICENSE).
