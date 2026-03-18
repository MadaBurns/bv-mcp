# Performance Improvements Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reduce scan_domain DNS roundtrips by ~30%, bound subdomain probe concurrency, and improve adaptive weight adoption.

**Architecture:** Add a scan-scoped `Map<string, Promise<DohResponse>>` to `QueryDnsOptions` that deduplicates identical DNS queries within a single scan. Thread it through the existing `dnsOptions` parameter chain. Separately, batch subdomain probes and relax the adaptive weight timeout.

**Tech Stack:** TypeScript, Vitest, Cloudflare Workers, DNS-over-HTTPS

---

### Task 1: Add `queryCache` to `QueryDnsOptions`

**Files:**
- Modify: `src/lib/dns-types.ts:52-58`
- Test: `test/dns-transport.spec.ts`

- [ ] **Step 1: Write the failing test — cache hit returns same Promise**

Add to `test/dns-transport.spec.ts`:

```typescript
it('returns cached Promise when queryCache contains the key', async () => {
	const dohResponse = {
		Status: 0, TC: false, RD: true, RA: true, AD: false, CD: false,
		Question: [{ name: 'example.com', type: RecordType.TXT }],
		Answer: [{ name: 'example.com', type: RecordType.TXT, TTL: 300, data: '"v=spf1 ~all"' }],
	};
	const cached = Promise.resolve(dohResponse);
	const queryCache = new Map<string, Promise<typeof dohResponse>>();
	queryCache.set('example.com:TXT:false', cached);

	globalThis.fetch = vi.fn() as unknown as typeof globalThis.fetch;

	const result = await queryDns('example.com', 'TXT', false, {
		retries: 0,
		confirmWithSecondaryOnEmpty: false,
		queryCache,
	});

	expect(result).toBe(dohResponse);
	expect(vi.mocked(globalThis.fetch)).not.toHaveBeenCalled();
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run test/dns-transport.spec.ts -t "returns cached Promise"`
Expected: FAIL — `queryCache` does not exist on type `QueryDnsOptions`

- [ ] **Step 3: Add `queryCache` field to `QueryDnsOptions`**

In `src/lib/dns-types.ts`, add to the interface:

```typescript
export interface QueryDnsOptions {
	timeoutMs?: number;
	retries?: number;
	confirmWithSecondaryOnEmpty?: boolean;
	/** When true, skip secondary resolver confirmation on empty results. Used in scan context for speed. */
	skipSecondaryConfirmation?: boolean;
	/** Scan-scoped DNS query cache. Stores Promises keyed by `domain:type:dnssecCheck` to deduplicate concurrent and sequential identical queries within a single scan. */
	queryCache?: Map<string, Promise<DohResponse>>;
}
```

- [ ] **Step 4: Run test to verify it still fails (type compiles but no cache logic yet)**

Run: `npx vitest run test/dns-transport.spec.ts -t "returns cached Promise"`
Expected: FAIL — `fetch` is still called (no cache check in `queryDns`)

- [ ] **Step 5: Commit type change**

```bash
git add src/lib/dns-types.ts test/dns-transport.spec.ts
git commit -m "test: add queryCache field to QueryDnsOptions"
```

---

### Task 2: Implement cache check/store in `queryDns`

**Files:**
- Modify: `src/lib/dns-transport.ts:76-134`
- Test: `test/dns-transport.spec.ts`

- [ ] **Step 1: Implement cache logic in `queryDns`**

At the top of `queryDns()` in `src/lib/dns-transport.ts` (after line 76, before line 77), add:

```typescript
export async function queryDns(domain: string, type: RecordTypeName, dnssecCheck = false, opts?: QueryDnsOptions): Promise<DohResponse> {
	// Scan-scoped DNS query cache: deduplicate identical queries
	const cacheKey = `${domain}:${type}:${dnssecCheck}`;
	if (opts?.queryCache) {
		const cached = opts.queryCache.get(cacheKey);
		if (cached) return cached;
	}

	const promise = queryDnsUncached(domain, type, dnssecCheck, opts);

	if (opts?.queryCache) {
		opts.queryCache.set(cacheKey, promise);
		// Remove from cache if the query fails, so retries can re-attempt
		promise.catch(() => opts.queryCache?.delete(cacheKey));
	}

	return promise;
}
```

Rename the existing `queryDns` body to `queryDnsUncached` (same signature, private):

```typescript
async function queryDnsUncached(domain: string, type: RecordTypeName, dnssecCheck = false, opts?: QueryDnsOptions): Promise<DohResponse> {
	const timeoutMs = opts?.timeoutMs ?? DNS_TIMEOUT_MS;
	// ... rest of existing queryDns body unchanged
}
```

- [ ] **Step 2: Run the cache hit test**

Run: `npx vitest run test/dns-transport.spec.ts -t "returns cached Promise"`
Expected: PASS

- [ ] **Step 3: Write test — concurrent queries coalesce on same Promise**

```typescript
it('coalesces concurrent identical queries into one fetch call', async () => {
	const dohResponse = {
		Status: 0, TC: false, RD: true, RA: true, AD: false, CD: false,
		Question: [{ name: 'example.com', type: RecordType.A }],
		Answer: [{ name: 'example.com', type: RecordType.A, TTL: 300, data: '1.2.3.4' }],
	};
	const fetchMock = vi.fn().mockResolvedValue({
		ok: true, status: 200,
		json: () => Promise.resolve(dohResponse),
	} as unknown as Response);
	globalThis.fetch = fetchMock as unknown as typeof globalThis.fetch;

	const queryCache = new Map();
	const opts = { retries: 0, confirmWithSecondaryOnEmpty: false, queryCache };

	const [r1, r2] = await Promise.all([
		queryDns('example.com', 'A', false, opts),
		queryDns('example.com', 'A', false, opts),
	]);

	expect(r1).toBe(r2);
	expect(fetchMock).toHaveBeenCalledTimes(1);
});
```

- [ ] **Step 4: Run test**

Run: `npx vitest run test/dns-transport.spec.ts -t "coalesces concurrent"`
Expected: PASS

- [ ] **Step 5: Write test — no cache when queryCache absent**

```typescript
it('does not cache when queryCache is not provided', async () => {
	const dohResponse = {
		Status: 0, TC: false, RD: true, RA: true, AD: false, CD: false,
		Question: [{ name: 'example.com', type: RecordType.A }],
		Answer: [{ name: 'example.com', type: RecordType.A, TTL: 300, data: '1.2.3.4' }],
	};
	const fetchMock = vi.fn().mockResolvedValue({
		ok: true, status: 200,
		json: () => Promise.resolve(dohResponse),
	} as unknown as Response);
	globalThis.fetch = fetchMock as unknown as typeof globalThis.fetch;

	await queryDns('example.com', 'A', false, { retries: 0, confirmWithSecondaryOnEmpty: false });
	await queryDns('example.com', 'A', false, { retries: 0, confirmWithSecondaryOnEmpty: false });

	expect(fetchMock).toHaveBeenCalledTimes(2);
});
```

- [ ] **Step 6: Run test**

Run: `npx vitest run test/dns-transport.spec.ts -t "does not cache when"`
Expected: PASS

- [ ] **Step 7: Write test — failed queries are evicted from cache**

```typescript
it('evicts failed queries from cache so retries can re-attempt', async () => {
	const fetchMock = vi.fn()
		.mockRejectedValueOnce(new Error('network fail'))
		.mockResolvedValueOnce({
			ok: true, status: 200,
			json: () => Promise.resolve({
				Status: 0, TC: false, RD: true, RA: true, AD: false, CD: false,
				Question: [{ name: 'fail.com', type: RecordType.A }],
				Answer: [{ name: 'fail.com', type: RecordType.A, TTL: 300, data: '1.2.3.4' }],
			}),
		} as unknown as Response);
	globalThis.fetch = fetchMock as unknown as typeof globalThis.fetch;

	const queryCache = new Map();
	const opts = { retries: 0, confirmWithSecondaryOnEmpty: false, queryCache };

	await expect(queryDns('fail.com', 'A', false, opts)).rejects.toThrow();
	expect(queryCache.has('fail.com:A:false')).toBe(false);

	const result = await queryDns('fail.com', 'A', false, opts);
	expect(result.Answer?.[0]?.data).toBe('1.2.3.4');
});
```

- [ ] **Step 8: Run test**

Run: `npx vitest run test/dns-transport.spec.ts -t "evicts failed queries"`
Expected: PASS

- [ ] **Step 9: Run full test suite**

Run: `npm test`
Expected: All tests pass (no regressions)

- [ ] **Step 10: Commit**

```bash
git add src/lib/dns-transport.ts test/dns-transport.spec.ts
git commit -m "feat: implement scan-scoped DNS query cache in queryDns"
```

---

### Task 3: Thread queryCache through scan_domain

**Files:**
- Modify: `src/tools/scan-domain.ts:119`

- [ ] **Step 1: Add `queryCache` to the existing `scanDns` object**

In `src/tools/scan-domain.ts`, change line 119 from:

```typescript
const scanDns: QueryDnsOptions = { skipSecondaryConfirmation: true };
```

to:

```typescript
const scanDns: QueryDnsOptions = { skipSecondaryConfirmation: true, queryCache: new Map() };
```

No other changes needed — all 14 checks already receive `scanDns`.

- [ ] **Step 2: Run full test suite**

Run: `npm test`
Expected: All tests pass. Scan tests should be slightly faster due to fewer DNS queries.

- [ ] **Step 3: Commit**

```bash
git add src/tools/scan-domain.ts
git commit -m "feat: thread scan-scoped DNS queryCache through all checks"
```

---

### Task 4: Cap sensitive subdomain probes

**Files:**
- Modify: `src/tools/check-zone-hygiene.ts:118-135`
- Test: `test/check-zone-hygiene.spec.ts`

- [ ] **Step 1: Replace unbounded parallel with batched probes**

In `src/tools/check-zone-hygiene.ts`, replace the probe block (~lines 118-144). The inner `try/catch` inside `batch.map` is **required** — it normalizes DNS failures into `{ resolves: false, ips: [] }` results. Without it, `Promise.allSettled` would produce `PromiseRejectedResult` entries that get silently dropped by the `fulfilled` filter, causing probes to disappear from results:

```typescript
	// Phase 2: Sensitive Subdomain Probing (batched to limit concurrent DNS queries)
	const PROBE_BATCH_SIZE = 5;
	const probeResults: SubdomainProbeResult[] = [];

	for (let i = 0; i < SENSITIVE_SUBDOMAINS.length; i += PROBE_BATCH_SIZE) {
		const batch = SENSITIVE_SUBDOMAINS.slice(i, i + PROBE_BATCH_SIZE);
		const settled = await Promise.allSettled(
			batch.map(async (subdomain) => {
				const fqdn = `${subdomain}.${domain}`;
				try {
					const aRecords = await queryDnsRecords(fqdn, 'A', dnsOptions);
					return {
						subdomain: fqdn,
						resolves: aRecords.length > 0,
						ips: aRecords,
					} as SubdomainProbeResult;
				} catch {
					return {
						subdomain: fqdn,
						resolves: false,
						ips: [],
					} as SubdomainProbeResult;
				}
			}),
		);
		for (const result of settled) {
			if (result.status === 'fulfilled') {
				probeResults.push(result.value);
			}
		}
	}
```

- [ ] **Step 2: Run zone hygiene tests**

Run: `npx vitest run test/check-zone-hygiene.spec.ts`
Expected: All tests pass

- [ ] **Step 3: Run full test suite**

Run: `npm test`
Expected: All tests pass

- [ ] **Step 4: Commit**

```bash
git add src/tools/check-zone-hygiene.ts
git commit -m "perf: batch sensitive subdomain probes to cap concurrency at 5"
```

---

### Task 5: Bump adaptive weight fetch timeout

**Files:**
- Modify: `src/tools/scan-domain.ts:75`

- [ ] **Step 1: Change the constant**

In `src/tools/scan-domain.ts`, change line 75 from:

```typescript
const ADAPTIVE_FETCH_TIMEOUT_MS = 50;
```

to:

```typescript
const ADAPTIVE_FETCH_TIMEOUT_MS = 200;
```

- [ ] **Step 2: Run full test suite**

Run: `npm test`
Expected: All tests pass

- [ ] **Step 3: Commit**

```bash
git add src/tools/scan-domain.ts
git commit -m "perf: increase adaptive weight fetch timeout from 50ms to 200ms"
```

---

### Task 6: Typecheck, lint, final verification

- [ ] **Step 1: Run typecheck**

Run: `npm run typecheck`
Expected: No errors

- [ ] **Step 2: Run lint**

Run: `npm run lint`
Expected: No errors (or only pre-existing warnings)

- [ ] **Step 3: Run full test suite with coverage**

Run: `npm test`
Expected: All tests pass, coverage unchanged or improved

- [ ] **Step 4: Commit any lint fixes if needed**

```bash
git add -A && git commit -m "chore: lint fixes"
```
