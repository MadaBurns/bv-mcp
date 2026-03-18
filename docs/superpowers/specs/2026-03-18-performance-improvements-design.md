# Performance Improvements — Design Spec

**Date:** 2026-03-18
**Status:** Approved (post-review revision)
**Scope:** Scan latency, resource efficiency

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
  queryCache?: Map<string, Promise<DohResponse>>;  // DohResponse from dns-types.ts
}
```

In `queryDns()` (`src/lib/dns-transport.ts`), check the cache before making a network call. The function signature is `queryDns(domain, type, dnssecCheck, opts?)`:

```typescript
const cacheKey = `${domain}:${type}:${dnssecCheck}`;
if (opts?.queryCache?.has(cacheKey)) return opts.queryCache.get(cacheKey)!;
const promise = /* existing queryDns logic */;
opts?.queryCache?.set(cacheKey, promise);
return promise;
```

Key behaviors:
- Cache stores the Promise itself, so concurrent checks coalesce on the same in-flight request
- Cache scoped to scan lifetime (created in `scan_domain`, garbage collected after)
- Standalone check calls (outside `scan_domain`) pass no `queryCache` — behavior unchanged
- Secondary DNS confirmation (Google fallback) is a separate code path in `queryDns` that runs after the primary query. The primary result is cached; the secondary confirmation re-query should NOT be cached (it exists specifically to cross-check against a different resolver)

In `scan_domain` (`src/tools/scan-domain.ts`), the existing `scanDns` object at ~line 119 gains one field:

```typescript
const scanDns: QueryDnsOptions = {
  skipSecondaryConfirmation: true,
  queryCache: new Map(),
};
```

All 14 `safeCheck()` calls already receive `scanDns`. Note: `checkSsl` and `checkHttpSecurity` do not accept `dnsOptions` (they make no DNS calls via `queryDns`), so they are unaffected.

The cache is threaded through the call chain: check functions pass `dnsOptions` → `queryDnsRecords()` / `queryTxtRecords()` in `dns-records.ts` → `queryDns()` in `dns-transport.ts`. All intermediate functions already accept and forward `QueryDnsOptions`.

### Files changed

- `src/lib/dns-types.ts` — add `queryCache` to `QueryDnsOptions`
- `src/lib/dns-transport.ts` — cache check/store in `queryDns()`, wrapping the existing fetch logic
- `src/tools/scan-domain.ts` — add `queryCache: new Map()` to existing `scanDns` object
- `test/dns-transport.spec.ts` — add tests: cache hit returns same Promise, concurrent coalescing calls fetch once, no cache when `queryCache` absent

### Expected impact

Eliminates ~5-6 redundant DNS queries per scan. 20-40% fewer outbound DoH requests.

---

## 2. Cap sensitive subdomain probes

### Problem

`check_zone_hygiene` (`src/tools/check-zone-hygiene.ts`, ~line 119) probes all `SENSITIVE_SUBDOMAINS` (10 entries, defined in `zone-hygiene-analysis.ts`) via `Promise.allSettled` with unbounded concurrency — 10 concurrent DNS queries.

### Design

Batch into groups of 5 in `src/tools/check-zone-hygiene.ts`:

```typescript
const PROBE_BATCH_SIZE = 5;
const results: Array<{ subdomain: string; resolved: boolean }> = [];
for (let i = 0; i < SENSITIVE_SUBDOMAINS.length; i += PROBE_BATCH_SIZE) {
  const batch = SENSITIVE_SUBDOMAINS.slice(i, i + PROBE_BATCH_SIZE);
  const settled = await Promise.allSettled(
    batch.map(async (sub) => {
      const fqdn = `${sub}.${domain}`;
      const records = await queryDnsRecords(fqdn, 'A', dnsOptions);  // preserve dnsOptions
      return { subdomain: sub, resolved: records.length > 0 };
    }),
  );
  // collect results from settled...
}
```

Must preserve `dnsOptions` parameter passthrough (for scan-scoped query cache from Section 1).

### Files changed

- `src/tools/check-zone-hygiene.ts` — add batching to subdomain probe loop
- `test/check-zone-hygiene.spec.ts` — existing tests cover probe behavior; verify they still pass

### Expected impact

Bounded concurrency (5 concurrent DNS queries max per batch). More predictable resource usage under load. Adds one sequential batch boundary (~100ms) but reduces peak outbound query burst.

---

## 3. Bump adaptive weight fetch timeout

### Problem

`ADAPTIVE_FETCH_TIMEOUT_MS = 50` at `src/tools/scan-domain.ts:75`. Durable Object cold starts can exceed 50ms, causing adaptive weight fetches to time out and silently fall back to static weights.

### Design

Increase constant from 50 to 200:

```typescript
const ADAPTIVE_FETCH_TIMEOUT_MS = 200;
```

The adaptive fetch happens before scoring begins (not inside a check), so it does not block the parallel check execution. 200ms is well under both the 8s per-check timeout and 12s scan timeout.

### Files changed

- `src/tools/scan-domain.ts` — change constant value on line 75

### Expected impact

Higher adaptive weight adoption rate. Graceful fallback to static weights still applies if DO is unavailable.

---

## Dropped sections (from pre-review draft)

- **Lazy-load explain-finding-data.ts**: `explainFinding` and `resolveImpactNarrative` are synchronous functions called by `format-report.ts`, `tool-formatters.ts`, `handlers/tools.ts`, and re-exported via `package.ts`. Converting to async for a dynamic import would cascade through 5+ files and all their tests. Bundle savings (~50-100 KB) do not justify the blast radius.
- **Deferred provider signatures in check_mx**: `loadProviderSignatures()` is already called at line 94, after both the no-MX return (line 31) and null-MX return (line 49). Already optimized — no change needed.

---

## Implementation order

1. **DNS query cache** (Section 1) — highest impact, most files
2. **Cap subdomain probes** (Section 2) — quick win, 1 file
3. **Adaptive weight timeout** (Section 3) — one-liner

## Non-goals

- No changes to the scoring engine or check logic
- No changes to the MCP protocol layer or session management
- No DNS batching (multiple queries in one HTTP request) — Cloudflare DoH doesn't support it
- No changes to KV caching strategy (already well-optimized with inflight dedup)
- No async conversion of explain-finding exports (too invasive for marginal bundle gain)
