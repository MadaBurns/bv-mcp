---
name: bv-mcp-testing
description: "Use when writing or debugging tests in the bv-mcp / blackveil-dns repo — Vitest in the Cloudflare Workers pool, DNS mocking via dns-mock, dynamic-import mock isolation, cache clearing between cases, and the pyramid-layer filename suffixes. Symptoms: a mock leaking between tests, a tool not picking up mocked DNS, cache hits across cases, or a full-suite run ending in 'WebSocket peer disconnected' failures."
---

# bv-mcp Testing

Tests run **inside the Workers runtime** (`@cloudflare/vitest-pool-workers`), not Node. Config: `vitest.config.mts` (15s timeout, `isolatedStorage: false`). For *which* pyramid layer to write at and the philosophy, read `~/.claude/docs/testing-methodology.md` and the global **test-patterns** skill — this skill is the bv-mcp-specific mechanics only.

## The two rules that cause most flakes

1. **Dynamic-import inside the test fn for mock isolation.** Import the unit under test *after* setting up mocks, inside the test body — not at the top of the file:
   ```ts
   const { checkSpf } = await import('../src/tools/check-spf');
   ```
   A static top-of-file import binds before your mock is installed and the tool won't see mocked DNS. (`check_mx` is even dynamically imported in `handlers/tools.ts` itself for this reason.)

2. **Clear BOTH cache keys between cases** when exercising `scan_domain` or any cached check — the per-check key *and* the top-level key:
   - `cache:<domain>:check:<name>`
   - `cache:<domain>`
   A stale entry from a prior case produces a cache hit and a confusing pass/fail.

## DNS mocking (`test/helpers/dns-mock.ts`)

- `setupFetchMock`, `mockTxtRecords`, `createDohResponse`, `mockFetchResponse`, `mockFetchError`.
- Call `restore()` in `afterEach` — every spec.
- `mockTxtRecords()` **adds the quotes for you** — pass the record unquoted. For backslash-escaped records, build the response with `createDohResponse()` directly.

## Pyramid-layer filename suffixes (routing, enforced by a hook)

| Suffix | Layer |
|---|---|
| `.spec.ts` | Vitest unit/integration — **NOT Playwright E2E** in this repo |
| `.integration.test.ts` | narrow integration (prefer this for new mock-D1 files) |
| `.contract.test.ts` | Zod / API contracts |
| `.audit.test.ts` | invariant audits (the backstops the other skills rely on) |
| `.chaos.test.ts` | failure-injection |

`test/` is flat by source file; subdirs are `helpers/ schemas/ oauth/ audits/ contracts/ chaos/`.

## Running

```bash
npm test                                 # full suite (~3300 tests, Workers pool)
npx vitest run test/check-spf.spec.ts    # single spec — fast feedback loop
```

## Known full-suite flake — don't chase it

A full run ending with `workerd ... WebSocket peer disconnected` plus ~10 "failures" is **pool-teardown noise, not real**. To confirm a failure is genuine, **re-run the named spec(s) in isolation** — if they pass alone, it was teardown noise.

## Red flags

- "The tool ignores my mocked DNS" → you imported it statically. Move the import inside the test fn.
- "Second test case sees stale data" → you cleared one cache key, not both.
- "~10 failures at the end of `npm test`" → likely teardown noise; re-run those specs alone before debugging.
- Writing an `expect(...).toHaveLength(N)` change → that's a tool-count surface; see **bv-mcp-add-tool**, not here.

## Provenance

Moved here from the fleet-global `bv-cc` skills library (`~/.claude/skills/`) on 2026-08-03. It is bv-mcp-specific, so as a global skill its description competed for context in every session on every repo — including repos it can never apply to. Scoping it to this repo is the "scope skills to specific paths so they only activate in the relevant part" rule from Anthropic's large-codebase guidance.

Keep it here. If a fact in it turns out to be cross-repo (a seam bv-web-prod also depends on), the cross-repo half belongs in `fleet-architecture`, not back in the global library.
