---
name: bv-mcp-testing
description: "Use when writing or debugging tests in the bv-mcp / blackveil-dns repo — Vitest in the Cloudflare Workers pool, DNS mocking via dns-mock, dynamic-import mock isolation, cache clearing between cases, and the pyramid-layer filename suffixes. Symptoms: a mock leaking between tests, a tool not picking up mocked DNS, cache hits across cases, a full-suite run ending in 'WebSocket peer disconnected' failures, or a workerd 'Segmentation fault: 11' crash timing a test out at 15s. ALSO when touching Analytics Engine SQL in analytics-queries.ts — those builders are asserted as STRINGS only, so a query can be 100% rejected in prod while its spec passes; covers the AE ClickHouse-subset limits (CASE WHEN / GREATEST / COUNT(*) all 422) and how to probe the live API."
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

Same family, different signature (seen 2026-08-19): `*** Received signal #11: Segmentation fault: 11` followed by `[mf:warn] The Workers runtime crashed unexpectedly and is being restarted`. The crashed worker's in-flight test then **times out at 15s** and reports as a normal assertion failure. A test that fails by *timeout* next to a segfault line is runtime instability — re-run it alone. Adding test FILES perturbs pool sharding and can move which spec catches the crash, so a "new failure" after adding a spec is not automatically caused by it: baseline the full suite on a clean stash before attributing.

## A string-asserted query is NOT a working query

`src/lib/analytics-queries.ts` builders are covered only by assertions on the SQL **text**. Nothing in the suite executes them, so a query can be 100% rejected in production while its spec passes green. That is not hypothetical: `CASE WHEN` + `GREATEST()` had every Analytics Engine alerting query returning **HTTP 422 for 610 consecutive cron ticks** (the full 7-day retention window) from the commit that introduced the builders — and three specs asserted `toContain('GREATEST')`, actively **pinning the broken SQL in place**. See PR #708 and `test/analytics-queries-ae-dialect.spec.ts`, which records each measured 422.

**AE SQL is a ClickHouse *subset*.** Rejected: `CASE WHEN`, `GREATEST()`, `multiIf()`, `max2()`, `COUNT(*)`. Use `if(cond,a,b)`, `if(x > 0, x, 1)`, `count()`. AE's `IF()` also requires both branches to share a type — guard a Double aggregate (`avg`/`quantile*`) with `1.0`, never `1`.

**When you remove a construct from generated SQL, grep the specs for assertions on that construct** — otherwise the test fails and you "fix" it by restoring the defect.

To actually prove a query is accepted, execute it against the live API. Tests can't: they run in `workerd`, which has no fs and cannot read `~/.wrangler/config/default.toml` for a token. Drive the builders from a **`.mts`** script via `npx tsx` (a `.ts` file dies on *"Top-level await is currently not supported with the cjs output format"*). ⚠️ The AE API rate-limits hard (`10429`/`971`) — a ~58-query sweep exhausts it and a follow-up control run returns **all-429, masking the 422s and looking like a pass**. Throttle ~4s between calls, and treat an all-429 run as contaminated, not as evidence.

## Red flags

- "The tool ignores my mocked DNS" → you imported it statically. Move the import inside the test fn.
- "Second test case sees stale data" → you cleared one cache key, not both.
- "~10 failures at the end of `npm test`" → likely teardown noise; re-run those specs alone before debugging.
- Writing an `expect(...).toHaveLength(N)` change → that's a tool-count surface; see **bv-mcp-add-tool**, not here.

## Provenance

Moved here from the fleet-global `bv-cc` skills library (`~/.claude/skills/`) on 2026-08-03. It is bv-mcp-specific, so as a global skill its description competed for context in every session on every repo — including repos it can never apply to. Scoping it to this repo is the "scope skills to specific paths so they only activate in the relevant part" rule from Anthropic's large-codebase guidance.

Keep it here. If a fact in it turns out to be cross-repo (a seam bv-web-prod also depends on), the cross-repo half belongs in `fleet-architecture`, not back in the global library.

**2026-08-19** — added the AE-SQL section and the segfault flake signature, both measured while root-causing the `alerting_self_check` page (PR #708). The AE dialect limits were established by executing each construct against the live SQL API, with a control run proving the probe discriminates (known-bad → the quoted 422, known-good → 200).
