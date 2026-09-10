---
name: bv-mcp-check-conventions
description: Use when writing or modifying a bv-mcp check or its orchestration — emitting findings via createFinding/buildCheckResult, DNS-failure resilience and the abstention shape, wiring a per-check fetch budget, fixing serial-DoH cost with bounded parallelism, caching and mutating-tool request-dedup, scan_domain post-processing and maturity staging, or the false-positive downgrades (MX reputation, lookalikes, shadow domains, TXT hygiene, non-mail SPF, subdomain takeover). Symptoms — a category scoring 0 for a probe that never ran, a clean verdict from a cut probe, a check that got slower after adding queries, a downgrade that fires on the wrong domains, or "is this control even implemented".
---

# bv-mcp Check Conventions

How a check is written, bounded, cached and post-processed. `CLAUDE.md` carries
only the pointer. For the score MODEL (weights, profiles, grades) see
**bv-mcp-scoring**; for adding a whole new tool see **bv-mcp-add-tool**; for
tests see **bv-mcp-testing**.

## Emitting findings

- `createFinding()` + `buildCheckResult()` from `@blackveil/dns-checks/scoring`
  — **never construct findings manually**. `createFinding()` auto-sanitizes
  `detail`.
- Tool functions return `Promise<CheckResult>` and take an optional
  `dnsOptions?: QueryDnsOptions`. Follow `check-spf.ts`.
- ⚠️ **`CheckResult` literal**: include both `passed: boolean` **and**
  `findings: [] as Finding[]`. A bare `findings: []` infers `never[]` and breaks
  CI after a dns-checks DTS rebuild.

⚠️ **Before concluding a control is unimplemented, grep the whole package.**
Emission is not uniform: DMARC is the **sole** check that delegates to a
classifier (`packages/dns-checks/src/scoring/classifiers/dmarc.ts`); every other
check emits inline or via a sibling `*-analysis.ts`. Confirm with a
category-wide grep of `createFinding(` / `buildCheckResult(` call sites — never
from file layout.

## Abstention: the shape that keeps an unmeasured category out of the score

Directly-callable tools catch top-level DNS errors and return
`buildDnsErrorResult(category, label, err)` (`lib/dns-error-result.ts`) — the
same shape `safeCheck` produces:

```
checkStatus: 'error'   score: 0   passed: false   partial: true
+ a `high` finding with errorKind: 'dns_error'
```

⚠️ **`checkStatus` — NOT `missingControl` — is the load-bearing signal.** It is
what lets the transient-zero retry fire and lets scoring EXCLUDE the category.
`partial: true` is what keeps the non-answer out of the 5-minute cache.

⚠️ `missingControl` means "we MEASURED and the control is absent".
`inconclusive` + `errorKind` means "the probe never reached the origin". Never
both on one finding — recording a blocked or cut probe as absence zeroes a
category nobody measured (#638).

The contract is pinned repo-wide by
`test/audits/check-abstention-shape.audit.test.ts`.

## Per-check fetch budgets (#641/#674)

`createFetchBudget(budgetMs)` (`src/lib/fetch-budget.ts`) opens **one** deadline
per check; `.wrap(fetchFn)` **composes** (never substitutes) each fetch with the
remainder. Absent `budgetMs` (direct calls) → identity, i.e. unchanged
behaviour. Budgeted checks: `ssl`, `http_security`, `mta_sts`,
`subdomain_takeover`.

⚠️⚠️ **Budgeting a check is a CORRECTNESS change, not a latency one.** Read what
the check does when a fetch *throws* before wiring one: a cut probe must
WITHHOLD its clean verdict (`subdomain_takeover`) or return the retryable
`'error'` class (`mta_sts`). It must never record a confident finding for a
probe that was never issued.

⚠️ A `fetch` wrapper does **not** cover service bindings — `check_ssl`'s
bv-tls-probe call needed `budget.signal()` threaded separately.

⚠️ Where a check has its own total-budget `Promise.race`, arm it strictly
**BEHIND** the fetch budget (`BUDGET_RACE_MARGIN_MS`). Level with it, both fire
on the same tick, the race frequently wins, and the check throws away headers
the graceful path had just salvaged — converting a reportable category into an
unreportable one, the opposite of the fix.

Full incident lore is in the in-code comments at those four sites; read them
rather than re-deriving.

## Serial-DoH cost is a DIFFERENT defect — bounded parallelism, not a budget

Use `mapConcurrent` + a named per-check constant.

⚠️ `SCAN_DNS_CONCURRENCY = 12` is **shared and zero-sum across 19 categories** —
keep a new pool at or below the width the check already used.

⚠️ **`spf`, `ns`, `caa` are NOT candidates.** `spf`'s and `subdomailing`'s
mid-iteration caps make DFS **order** load-bearing on scored findings, so
parallelizing them is a scoring change (measured: 90 → 60). Pinned by
`test/check-subdomailing-parity.spec.ts`.

## Caching and dedup

- `cacheGet` / `cacheSet` / `cacheSetDeferred` / `runWithCache` from
  `lib/cache.ts`. `cacheSetDeferred` wraps in `ctx.waitUntil()`.
- Keys: per-check `cache:<domain>:check:<name>` **and** top-level
  `cache:<domain>`. 5-min TTL (`cacheTtlSeconds` override); `force_refresh` →
  `skipCache`. Both predicates are `!partial`.
- **Mutating-tool request-dedup**: `handleToolsCall` wraps mutating `*_start` /
  `register_*` tools in `withRequestDedup` (`lib/request-dedup.ts`, ~90s KV
  window keyed `sha256(principal + tool + canonicalArgs)`). `MUTATING_DEDUP_TOOLS`
  derives from annotations; the exact set is pinned by
  `test/request-dedup-wiring.spec.ts`.
  ⚠️ Invariants: **store-on-success only**, and key on `runtimeOptions.keyHash`
  **ONLY** — never fall back to `principalId`, whose `ipHash` would replay
  operation IDs cross-principal (fixed 3.15.1).

## `scan_domain` orchestration

19 categories in parallel via `Promise.allSettled` (18 registered scan-included
tools + the internal `subdomain_takeover` slot). Timeouts: scan 15s, which
preserves partial results; per-check 8s. `SCAN_TIMEOUT_MS` is env-overridable
and clamped to [5s, 30s]; both budgets resolve through
`resolveScanTimeoutBudget` (`src/tools/scan/timeouts.ts`), which also reconciles
the two so a check cannot be permitted to outlive the scan.

**Maturity staging** — `computeMaturityStage()` 0–4. ⚠️ The score cap reads the
**displayed NIST 6-band** letter (`nistScoreToGrade`), never the internal 9-band
(#640 printed grade D beside "Stage 4 — Hardened"). `indeterminate` is never
capped, and the capped label is worded by the same `ladderForProfile()` that
produced the stage.

**Post-processing** — two downgrades, both narrowly gated:

- Non-mail (no MX) downgrades email-auth findings to `info` **only under
  inherited DMARC enforcement**. ⚠️ The parent `sp=`/`p=` `quarantine|reject`
  condition is **LOAD-BEARING** (#643: ungated it hands a clean pass to
  spoofable domains, +7 to +23 points on ~28.6% of domains). Apex domains never
  qualify — that is correct, not a gap.
- No-send (SPF `noSendPolicy`) downgrades DKIM / MTA-STS / BIMI missing-record
  findings to `info`; BIMI is rewritten for non-mail domains.

**Output** — prose + `structuredContent` (always) + a legacy
`<!-- STRUCTURED_RESULT -->` comment that `stripRedundantStructuredComment()`
(`src/mcp/dispatch.ts`) drops only for clients proven to read
`structuredContent`. The `clientType` allowlist is the load-bearing safeguard;
full gating rules in **bv-mcp-operations**.

**Format** — `format` param (`full` | `compact`), auto-detected from client type
(interactive LLM → `compact`, else `full`). Resolved in `extractFormat(args)`
(`tool-args.ts`): explicit wins, else `resolveFormat()` from `clientType`.

**`batch_scan`** — `budgetMs` default 25s, `concurrency` default 3, per-domain
`Promise.race`. Exceeded → `error: 'batch_budget_exceeded'`.

⚠️ A cold scan fans out ~20 subrequests/domain and the scanner queue has
measurably overrun the paid 10,000/invocation ceiling — see **bv-mcp-operations**
before changing batch sizes.

## False-positive reduction (the deliberate downgrades)

- **MX Reputation** — shared provider IPs (Google, M365, Cloudflare Email
  Security, …) downgrade DNSBL findings **and rDNS findings** to `info`.
  ⚠️ `detectSharedMxProvider()` must be threaded into `analyzePtrRecords()` as
  well as the DNSBL branch. Until 2026-09-07 it was computed but passed only to
  DNSBL, so missing-PTR/FCrDNS scored `medium` against provider infrastructure
  the customer cannot configure (Cloudflare Email Security publishes no PTR at
  all → 3 × medium = −45 on every customer domain). Dedicated infrastructure
  still scores `medium` — there the owner does control the reverse zone. rDNS
  gates the **sending** IP, not the inbound MX.
- **Lookalikes** — shared NS with the primary → `info` (defensive registration).
- **Shadow Domains** — shared NS (≥2 overlap) → severity downgrade with an
  ownership signal.
- **TXT Hygiene** — record accumulation tiered (25+ → medium, 15–24 → low);
  duplicate verifications consolidated.
  ⚠️ The "stale integration" verdict (verification record present but no
  matching SPF include) is gated on `MAIL_SENDING_VERIFICATION_SERVICES`, **not**
  on membership of `SERVICE_SPF_DOMAINS` — the latter also holds ownership-only
  proofs (`google-site-verification=`, M365 `MS=`) that say nothing about mail.
  Ungated it misfired on 7/10 well-known domains for M365 and 4/10 for Search
  Console, stacking to −10. **Adding a service to `SERVICE_SPF_DOMAINS` does NOT
  make it stale-checkable** — add it only if its verification record implies the
  domain *sends* through that service.
- **Non-mail SPF** (`check_mx`) — no MX → verifies `v=spf1 -all`; missing SPF →
  medium, non-reject → low.
- **Subdomain takeover severity** — dangling-CNAME targets embedding a
  provider-assigned random ID (ELB / CloudFront / API Gateway) downgrade HIGH →
  MEDIUM: operational drift, not a reclaimable namespace.
  `classifyTargetNamespace()` in
  `packages/dns-checks/src/checks/subdomain-takeover-analysis.ts`.

⚠️ **Penalties are additive** — raising one `penaltyOverride` can stack with
another finding and zero a category. Only `subdomain_takeover` is capped. See
**bv-mcp-scoring**.

## Other conventions

- **Zod** centralized in `src/schemas/`. Tool `inputSchema` via
  `z.toJSONSchema()` (Zod v4); runtime validation via `validateToolArgs()`. Use
  `.passthrough()` and `.transform().pipe()` for case-insensitive enum
  normalization.
- `validateDomain()` + `sanitizeDomain()` from `lib/sanitize.ts` for all domain
  inputs, **after** Zod — see **bv-mcp-security-surface**.
- `mcpError()` / `mcpText()` from `handlers/tool-formatters.ts`.
- JSDoc on exports; `import type { ... }` for type-only imports.
- `check_mx` is **dynamically imported** in `handlers/tools.ts` for mock
  isolation.
- MCP server key `"blackveil-dns"` everywhere. `tools/call` accepts `scan` as an
  alias for `scan_domain`. SSRF constants in `lib/config.ts`.

## Red flags

- "This category scored 0" → check whether the probe ran. `checkStatus` +
  `partial`, not `missingControl`.
- "I added a fetch budget and the tests still pass" → they may be passing
  vacuously; the question is what the check emits when a fetch *throws*.
- "I parallelized the DNS queries and the score changed" → you hit the
  `spf`/`ns`/`caa`/`subdomailing` DFS-order rule. That is a scoring change.
- "The control looks unimplemented" → grep `createFinding(` package-wide before
  saying so.
- "`passed` is false so the control is missing" → no. `passed` means
  `score >= 50 && !hasMissingControl` — "did not penalize", not "exists". Four
  surfaces have already misread it (#705 #706 #725 #809).

## Provenance

Split out of `CLAUDE.md` 2026-09-11, verbatim, when that file was trimmed back
to pointers (28,897 B / ~7.2k tokens loaded unconditionally in every session).
No content was dropped in the move. Per `cc-repo-operations` §7.1: depth belongs
in a skill that loads on description match; CLAUDE.md carries the pointer.
