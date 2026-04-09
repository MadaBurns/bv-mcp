---
description: Use when editing or creating test files, fixing flaky tests, writing DNS mocks, or validating cache and session behavior in this repository.
name: Test Patterns
applyTo: test/**/*.spec.ts
---
# Test Patterns

- Run tests in Workers runtime: `npm test`.
- Prefer single-file runs during iteration: `npx vitest run test/check-spf.spec.ts`.
- Use `test/helpers/dns-mock.ts` helpers for DNS mocking.
- Always restore fetch mocks in `afterEach`.
- For tests that need `check_mx` mock isolation, use dynamic import inside test bodies.
- Clear both cache levels between relevant cases:
  - `cache:<domain>`
  - `cache:<domain>:check:<name>`
- Keep assertions aligned with MCP behavior:
  - Rate-limit responses are HTTP 200 with JSON-RPC error code `-32029`.
  - Client-safe error text should use approved safe prefixes.
  - Tools in `format=full` (default for non-interactive) return 2 content items (text + structured JSON). Assert `toHaveLength(2)` for success paths, `toHaveLength(1)` for compact mode.

## When changing scan behavior

- Re-run affected scan and check-specific specs.
- Validate timeout and partial-result behavior does not regress.
- Confirm `force_refresh` paths propagate cache bypass.

## Reference docs

- Canonical conventions: [CLAUDE.md](../../CLAUDE.md)
- Troubleshooting patterns: [docs/troubleshooting.md](../../docs/troubleshooting.md)
- Scoring behavior and thresholds: [docs/scoring.md](../../docs/scoring.md)
