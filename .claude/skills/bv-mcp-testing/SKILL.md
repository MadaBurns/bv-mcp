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

## Wall-clock in a spec: three tools, and the one that does not work

A spec that exercises a deadline/budget path will sit through the production
constant in REAL TIME unless you do something about it. Measured 2026-09-11:
five specs were burning 81.3s between them, one test alone waiting out
`LOOKALIKE_TIMEOUT_MS` (20s). Pick by what the test actually claims:

1. **The budget is already injectable — just unused.** Check first. `scanDomain`
   has taken `scanTimeoutMs`/`perCheckTimeoutMs` via `resolveScanTimeoutBudget`
   all along; two specs waited out the 8s default anyway. ⚠️ Keep the scan
   ceiling above `RETRY_BUDGET_MS` (3s) or the per-check killer is clamped away
   and the transient-zero retry pass silently goes unreachable.
2. **No knob exists → add one on the options bag, with a resolver.** Follow
   `resolveScanTimeoutBudget` / `resolveLookalikeTimeoutBudget`: resolve the
   ceiling and its dependent sub-budgets TOGETHER. Sub-budgets here are measured
   absolutes, so the resolver must return today's exact numbers at the default —
   scale only a shorter override, or the arithmetic goes negative (below 8s the
   bare `timeout - reserve - window` deadlined every lookalike DNS phase at once).
3. **The constant under test IS the production default → fake timers.** Passing
   an override there moves the assertion onto a different arm (for
   `check_http_security` the budgeted arm is already covered by
   `http-security-fetch-budget.spec.ts`). Use `await vi.advanceTimersByTimeAsync(n)`
   — the async variant flushes microtasks between steps, so awaited rounds
   resolve instead of deadlocking the advance — and attach the rejection handler
   BEFORE advancing, or a re-throwing tool settles unhandled. Always restore in
   a `finally`.

⚠️ **Fake timers do NOT patch `AbortSignal.timeout`.** Vitest patches
`setTimeout`/`Date`; `AbortSignal.timeout` is a platform static on the real
clock. So a spec bounded by one is irreducible without shortening a shipped
constant — which tests something other than what ships. That is what makes the
`no budget → unchanged` cases in the fetch-budget specs and the lookalikes
fan-out pair (`dns-starvation`, `registration-age`) legitimately slow: leave
them. `composeAbortSignal` in `discover-subdomains.ts` uses a plain `setTimeout`
and IS fakeable — check the primitive before assuming.

## The suite is import-bound, not test-bound

Measured 2026-09-11 (M4 Pro, 14 cores): full run **~3:06 wall**, of which
**import is 1,016s cumulative across 727 files (~1.4s/file)** against 735s of
cumulative test time. Consequences before anyone "optimises the tests":

- Shaving cumulative test time barely moves the wall clock. Cutting those 81.3s
  to 10.4s changed the full run by nothing measurable (3:06.28 → 3:09.50, inside
  variance). It is an **inner-loop** win — one spec 22s → 2s — not a CI win.
- `--maxWorkers` does not help: 89 files ran 27.45s at default, 29.92s at 14.
- The import cost is the mock-isolation convention (rule 1 above) re-importing
  the worker graph per file. That is the only real lever left, and it trades
  against the isolation those dynamic imports buy.
- **Adding a spec FILE costs ~1.4s.** Splitting a slow file is a net loss once
  its slow test is fixed.

⚠️ **Never baseline a timing run without checking CPU utilisation.** The first
measurement of this suite read 6:10 at **187% CPU**; every later run read ~3:06
at ~280%. The 6:10 was a contended machine, not the suite, and reporting it
overstated the wall clock by 2×. The five "failures" in that run were the
teardown/segfault flake documented below — they vanish on a quiet run with no
code change. Re-run before concluding.

## Expected `npm test` exit 1 in a FRESH WORKTREE — not a real failure

`test/wasm-integration.test.ts` fails to **LOAD** with `No such module …bv_wasm_core_bg.wasm`, and the run reports **0 test failures**. `crates/bv-wasm-core/pkg/` is produced only by `npm run build:wasm` (wasm-pack), which **neither `scripts/worktree-setup.sh` nor `npm ci` runs** — CI builds it separately with a cached wasm-pack binary. Distinguish it from a real failure by that shape: a *suite-load* error alongside `N passed, 0 failed`. Run `npm run build:wasm` once per worktree for a fully green local run. Confirmed independently by two agents on unrelated branches (2026-08-03). **Do not "fix" it by editing the spec.**

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
