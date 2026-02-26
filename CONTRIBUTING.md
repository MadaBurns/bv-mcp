# Contributing to BLACKVEIL Scanner

Thanks for your interest in contributing! BLACKVEIL Scanner is an open-source DNS/email security analysis and remediation platform.

## Getting Started

```bash
git clone https://github.com/MadaBurns/bv-mcp.git
cd bv-mcp
npm install
npm test           # Run tests (245+ tests, ~95% coverage)
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

1. Create `src/tools/check-<name>.ts` exporting an async function that returns `CheckResult`
2. Register the tool schema in `src/handlers/tools.ts` (add to `TOOLS` array and `handleToolsCall` switch)
3. Add tests in `test/check-<name>.spec.ts` using the `dns-mock` helper
4. Update the README tools table

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

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
