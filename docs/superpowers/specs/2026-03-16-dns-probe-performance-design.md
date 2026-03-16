# Two-Phase DNS Probing for check_lookalikes and check_shadow_domains

**Date:** 2026-03-16
**Status:** Approved
**Problem:** check_lookalikes P95=20s/72% fail rate, check_shadow_domains P95=14s/62% fail rate

## Context

Both tools make 70-130 DNS queries per invocation, probing every variant with full record types regardless of whether the domain exists. Production analytics (7 days ending 2026-03-16) show:

- `check_lookalikes`: 18 calls, avg 6.8s, P50 4.5s (fail), P95 20s (timeout)
- `check_shadow_domains`: 29 calls, avg 3.5s, P50 4.7s (fail), P95 14s

Most variants (~90%) are unregistered. Querying MX, TXT, DMARC records for non-existent domains wastes time and triggers adaptive backoff (halved concurrency + 500ms delays per batch), compounding the latency.

## Design

### Two-Phase Probing

Replace single-phase "query everything for every variant" with two phases:

**Phase 1 — Existence (fast, lean):**
- Query NS records for all variants with aggressive settings:
  - `retries: 0` (no retry on timeout — non-existence is expected)
  - `skipSecondaryConfirmation: true` (don't double-check empty results)
  - `timeoutMs: 2000` (reduced from 3000 — if NS doesn't resolve in 2s, domain likely unregistered or unreachable)
- High concurrency: all variants in a single `Promise.allSettled` (no adaptive batching — these are lightweight single-record queries that return NXDOMAIN quickly for non-existent domains)
- Result: a set of "registered" variants (those with NS records)

**Phase 2 — Detail (only registered variants):**
- For variants that passed Phase 1, run the existing full probe:
  - `check_lookalikes`: A + MX records
  - `check_shadow_domains`: A + MX + TXT + DMARC records (NS result from Phase 1 is passed through — no re-query)
- Normal DNS settings (3s timeout, 1 retry) — these are real domains worth accurate probing
- Existing adaptive batching applies here with current thresholds

### Why NS for Existence

NS records are the most reliable existence indicator:
- Every registered domain has NS records (delegated by the registrar)
- A domain can have NS but no A/MX (parked, email-only, etc.)
- NS queries are fast — authoritative nameservers are cached aggressively
- Using A records would miss MX-only or NS-only domains

### DNS Options

`QueryDnsOptions` in `src/lib/dns-types.ts` already supports `timeoutMs`, `retries`, `skipSecondaryConfirmation`, and `confirmWithSecondaryOnEmpty`. No changes needed to the DNS transport layer.

Both tools pass lean options for Phase 1:
```typescript
const leanDnsOpts: QueryDnsOptions = {
  timeoutMs: 2000,
  retries: 0,
  skipSecondaryConfirmation: true,
};
```

### check_lookalikes Changes

**Before:** 50 permutations × (A + MX) = 100+ queries, adaptive batches of 10
**After:**
1. Wildcard detection runs first (unchanged — canary probes for dot-insertion parent domains)
2. Phase 1: NS queries for all non-wildcard permutations in parallel (single `Promise.allSettled`, lean DNS) → ~300-500ms
3. Phase 2: ~2-5 resolved domains × (A + MX) = 4-10 queries, adaptive batching with existing `FAILURE_THRESHOLD = 2`
4. Total: ~55-65 queries (50 NS + canary probes + resolved × 2), ~1-2s typical

Additional: skip secondary DNS confirmation entirely (was enabled, unlike scan_domain checks). Lookalike domains that don't resolve on Cloudflare DoH won't resolve for attackers either.

**Wildcard detection ordering:** Wildcard canary probes (`_bv-wc-probe.<parent>` A queries) run before Phase 1, as they do today. Dot-insertion permutations under wildcard parents are filtered out before Phase 1 NS queries run. This prevents wildcard DNS from inflating the "registered" set.

### check_shadow_domains Changes

**Before:** 14-19 variants × 5 records = 71-96 queries, adaptive batches of 4 (backoff at >0 failures)
**After:**
1. Phase 1: 14-19 NS queries in parallel (single `Promise.allSettled`, lean DNS) → ~300-500ms
2. Phase 2: ~2-4 registered variants × 4 records (A + MX + TXT + DMARC) = 8-16 queries. NS result from Phase 1 is passed into the detail probe to avoid re-querying.
3. Total: ~25-35 queries, ~1-2s typical

Extract a `FAILURE_THRESHOLD` constant (currently inline `failures > 0`) to match the `check_lookalikes` pattern.

Note: `check_shadow_domains` already skips secondary confirmation. The main win is Phase 1 existence filtering.

### Phase 1 NS Result Passthrough (check_shadow_domains)

Phase 1 collects NS records for each variant. For `check_shadow_domains`, NS data is needed by `classifyVariant()` and `detectSharedNs()` in Phase 2. To avoid re-querying:
- Phase 1 returns `Map<string, DnsRecord[]>` mapping variant → NS records
- `probeVariant()` accepts optional pre-fetched NS records; if provided, it runs 4 queries (A, MX, TXT, DMARC) instead of 5
- This saves 1 query per registered variant (small but free)

For `check_lookalikes`, Phase 1 NS results are used only for filtering (exists/doesn't exist). Phase 2 queries A + MX independently — no passthrough needed since lookalikes don't use NS data in their analysis.

## Query Budget Estimates

| Scenario | check_lookalikes | check_shadow_domains |
|---|---|---|
| **Before (current)** | 100-130 queries | 71-96 queries |
| **After (0 variants exist)** | 50 + ~5 canary = ~55 queries | 14-19 queries |
| **After (3 variants exist)** | ~55 + 6 = ~61 queries | 14-19 + 12 = ~28-31 queries |
| **After (5 variants exist)** | ~55 + 10 = ~65 queries | 14-19 + 20 = ~34-39 queries |

## Expected Performance Impact

| Metric | check_lookalikes before | after (est.) | check_shadow_domains before | after (est.) |
|---|---|---|---|---|
| P50 | 4.5s | **1-2s** | 4.7s | **1-2s** |
| P95 | 20s | **4-6s** | 14s | **3-5s** |
| Fail rate | 72% | **<20%** | 62% | **<20%** |
| Queries/call | 100-130 | 55-65 | 71-96 | 25-35 |

## Files Modified

| File | Change |
|---|---|
| `src/tools/check-lookalikes.ts` | Two-phase probing: wildcard detection → Phase 1 NS filter → Phase 2 detail probe. Skip secondary DNS confirmation. |
| `src/tools/check-shadow-domains.ts` | Two-phase probing: Phase 1 NS filter → Phase 2 detail probe with NS passthrough. Extract `FAILURE_THRESHOLD` constant. |
| `test/check-lookalikes.spec.ts` | Add NS record mocks to all positive-case tests (Phase 1 filter requires NS). Add tests for two-phase behavior and lean DNS options. |
| `test/check-shadow-domains.spec.ts` | Add NS record mocks to positive-case tests. Add tests for two-phase behavior and NS passthrough. |

**No changes needed to:** `src/lib/dns-transport.ts`, `src/lib/dns-records.ts`, `src/lib/dns.ts`, `src/lib/dns-types.ts` — `QueryDnsOptions` already supports all required overrides.

## Non-Goals

- Reducing permutation count (50 is correct for thoroughness)
- Changing the scoring/severity of findings
- Changing the output format or MCP response structure
- Adding these tools to scan_domain (they remain standalone due to query volume)

## Risks

- **False negatives on NS-only check**: A domain could theoretically be registered without NS records (broken delegation). This is extremely rare and such domains can't receive email or serve web content, so missing them has no security impact.
- **Stale NXDOMAIN in edge cache**: Cloudflare's edge cache (`DOH_EDGE_CACHE_TTL = 300s`) may serve a cached NXDOMAIN for a recently registered domain. With `retries: 0`, there's no recovery path until the edge cache TTL expires. Risk is low (5-minute window) and affects only brand-new domain registrations. The 60-minute tool-level result cache means a subsequent call after edge cache refresh will pick up the domain.
- **Wildcard false positives**: Wildcard DNS parents could cause Phase 1 to mark a non-existent subdomain as "registered" (NS records inherited from parent). Mitigation: wildcard detection runs before Phase 1, filtering these out.
