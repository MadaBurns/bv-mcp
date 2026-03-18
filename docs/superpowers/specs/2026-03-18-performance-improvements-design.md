# Performance Improvements — Design Spec

**Date:** 2026-03-18
**Status:** Approved
**Scope:** Scan latency, resource efficiency, bundle size

---

## 1. Scan-scoped DNS query cache

### Problem

`scan_domain` runs 14 checks in parallel. Several make redundant DNS queries:

| Record | Queried by |
|--------|-----------|
| NS | check_ns, check_zone_hygiene |
| SOA | check_ns, check_zone_hygiene |
| MX | check_mx, check_dane, check_mta_sts |
| _dmarc TXT | check_dmarc, check_spf (trust surface) |

~5-6 redundant DNS roundtrips per scan (~100-500ms each).

### Design

Add `queryCache` field to `QueryDnsOptions` in `src/lib/dns-types.ts`:

```typescript
export interface QueryDnsOptions {
  skipSecondaryConfirmation?: boolean;
  queryCache?: Map<string, Promise<DnsResponse>>;
}
```

In `queryDns()` (`src/lib/dns-transport.ts`), check the cache before making a network call:

```typescript
const cacheKey = `${domain}:${type}:${dnssec}`;
if (opts?.queryCache?.has(cacheKey)) return opts.queryCache.get(cacheKey)!;
const promise = actualQueryDns(domain, type, dnssec, opts);
opts?.queryCache?.set(cacheKey, promise);
return promise;
```

Key behaviors:
- Cache stores the Promise itself, so concurrent checks coalesce on the same in-flight request
- Cache scoped to scan lifetime (created in `scan_domain`, garbage collected after)
- Standalone check calls (outside `scan_domain`) pass no `queryCache` — behavior unchanged
- Secondary DNS confirmation (Google fallback) uses a separate cache key (`${domain}:${type}:${dnssec}:secondary`) so it is not suppressed

In `scan_domain` (`src/tools/scan-domain.ts`):

```typescript
const scanDns: QueryDnsOptions = {
  skipSecondaryConfirmation: true,
  queryCache: new Map(),
};
```

All 14 `safeCheck()` calls receive the same `scanDns` object.

### Files changed

- `src/lib/dns-types.ts` — add `queryCache` to `QueryDnsOptions`
- `src/lib/dns-transport.ts` — cache check/store in `queryDns()`
- `src/tools/scan-domain.ts` — create shared `Map` in scan context
- `test/dns-transport.spec.ts` — test cache hit, concurrent coalescing, no cache when absent

### Expected impact

20-40% fewer DNS roundtrips per scan. Eliminates ~5-6 redundant queries.

---

## 2. Lazy-load explain-finding-data.ts

### Problem

`explain-finding.ts` statically imports `explain-finding-data.ts` (1,905 lines). This ~50-100 KB data structure is bundled into every request even though only `explain_finding` tool calls use it.

### Design

Convert static import to dynamic import inside `explainFinding()`:

```typescript
// src/tools/explain-finding.ts
export async function explainFinding(...) {
  const { DETAILS_PATTERNS, DEFAULT_EXPLANATION, ... } = await import('./explain-finding-data');
  // rest unchanged
}
```

Workers runtime caches dynamic imports per isolate — first call pays import cost, subsequent calls are instant.

### Files changed

- `src/tools/explain-finding.ts` — convert to dynamic import
- `test/explain-finding.spec.ts` — no changes needed (already uses dynamic import for the check function)

### Expected impact

~50-100 KB removed from critical bundle path. Scan requests never load it.

---

## 3. Deferred provider signature loading in check_mx

### Problem

`checkMx()` calls `loadProviderSignatures()` unconditionally, including when the domain has no MX records and returns early.

### Design

Move `loadProviderSignatures()` below the no-MX early return:

```typescript
export async function checkMx(domain, opts?) {
  const mxRecords = await queryMxRecords(domain, opts?.dnsOptions);
  if (mxRecords.length === 0) {
    return buildCheckResult('mx', findings);  // no signatures needed
  }
  const signatures = await loadProviderSignatures(...);  // moved here
  // ... provider detection
}
```

### Files changed

- `src/tools/check-mx.ts` — reorder `loadProviderSignatures()` call
- Tests unchanged (mock behavior identical)

### Expected impact

Saves 1 KV/fetch operation for domains with no MX records.

---

## 4. Cap sensitive subdomain probes

### Problem

`check_zone_hygiene` probes all `SENSITIVE_SUBDOMAINS` in parallel with unbounded concurrency, potentially spawning 10+ concurrent DNS queries.

### Design

Batch into groups of 5:

```typescript
const PROBE_BATCH_SIZE = 5;
for (let i = 0; i < SENSITIVE_SUBDOMAINS.length; i += PROBE_BATCH_SIZE) {
  const batch = SENSITIVE_SUBDOMAINS.slice(i, i + PROBE_BATCH_SIZE);
  await Promise.allSettled(batch.map(sub => queryDnsRecords(...)));
}
```

### Files changed

- `src/tools/check-zone-hygiene.ts` or `src/tools/zone-hygiene-analysis.ts` — add batching to subdomain probe loop
- `test/check-zone-hygiene.spec.ts` — verify batched behavior

### Expected impact

Bounded concurrency prevents thundering herd. More predictable resource usage under load.

---

## 5. Bump adaptive weight fetch timeout

### Problem

`ADAPTIVE_FETCH_TIMEOUT_MS = 50` in `scan-domain.ts`. Durable Object cold starts often exceed 50ms, causing most adaptive weight fetches to time out and silently fall back to static weights.

### Design

Increase constant from 50 to 200:

```typescript
const ADAPTIVE_FETCH_TIMEOUT_MS = 200;
```

### Files changed

- `src/tools/scan-domain.ts` — change constant value

### Expected impact

Higher adaptive weight adoption rate. 200ms is still well under the 8s per-check timeout and 12s scan timeout.

---

## Implementation order

1. **DNS query cache** (Section 1) — highest impact, most files
2. **Lazy-load explain data** (Section 2) — quick win, 1 file
3. **Deferred provider signatures** (Section 3) — quick win, 1 file
4. **Cap subdomain probes** (Section 4) — quick win, 1 file
5. **Adaptive weight timeout** (Section 5) — one-liner

## Non-goals

- No changes to the scoring engine or check logic
- No changes to the MCP protocol layer or session management
- No DNS batching (multiple queries in one HTTP request) — Cloudflare DoH doesn't support it
- No changes to KV caching strategy (already well-optimized with inflight dedup)
