# Two-Phase DNS Probing Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cut check_lookalikes P95 from 20s to 4-6s and check_shadow_domains P95 from 14s to 3-5s by filtering unregistered variants with a fast NS existence check before detailed probing.

**Architecture:** Two-phase probing — Phase 1 queries NS records for all variants in parallel with lean DNS settings (2s timeout, no retries, no secondary confirmation). Only variants with NS records proceed to Phase 2 for full detail queries. This eliminates ~90% of wasted queries on non-existent domains.

**Tech Stack:** TypeScript, Cloudflare Workers runtime, DNS-over-HTTPS (Cloudflare DoH), Vitest

**Spec:** `docs/superpowers/specs/2026-03-16-dns-probe-performance-design.md`

---

## Chunk 1: check_lookalikes Two-Phase Probing

### Task 1: Add NS mock to existing lookalike positive-case tests

All existing tests that expect findings for specific domains (high/medium severity) currently mock A and MX records but not NS. Phase 1 filters on NS, so these tests must also return NS records for those domains to pass after the implementation.

**Files:**
- Modify: `test/check-lookalikes.spec.ts`

- [ ] **Step 1: Add NS responses to the "high finding for lookalike with MX" test mock**

In the fetch mock at line 38, add NS responses for the domains that should be detected. The mock should return NS records for any query with `type === 'NS' || type === '2'` for the target domains (`twst.com`, `tst.com`, `tes.com`, `testt.com`):

```typescript
if (name === 'twst.com' || name === 'tst.com' || name === 'tes.com' || name === 'testt.com') {
	if (type === 'NS' || type === '2') {
		return Promise.resolve(
			createDohResponse(
				[{ name, type: 2 }],
				[{ name, type: 2, TTL: 300, data: 'ns1.registrar.com.' }],
			),
		);
	}
	if (type === 'MX' || type === '15') {
		// ... existing MX mock
```

- [ ] **Step 2: Add NS responses to the "medium finding for lookalike with A but no MX" test mock**

Same pattern — line 70 mock. Add NS records for `tst.com` and `tes.com`:

```typescript
if (name === 'tst.com' || name === 'tes.com') {
	if (type === 'NS' || type === '2') {
		return Promise.resolve(
			createDohResponse(
				[{ name, type: 2 }],
				[{ name, type: 2, TTL: 300, data: 'ns1.registrar.com.' }],
			),
		);
	}
	if (type === 'A' || type === '1') {
		// ... existing A mock
```

- [ ] **Step 3: Add NS responses to null MX filtering tests**

Both null MX tests (lines 137, 172) mock A/MX for `tst.com`, `tes.com`, `testt.com`. Add NS records for these domains in the same `if` blocks.

- [ ] **Step 4: Add NS responses to wildcard DNS tests**

The "keep dot-insertion permutations" test (line 278) mocks `te.st.com` with A records. Add NS record for `te.st.com`. The "non-dot-insertion" test (line 305) mocks `tst.com` — add NS record for it too.

- [ ] **Step 5: Run existing tests to verify they still pass (before implementation)**

Run: `npx vitest run test/check-lookalikes.spec.ts`
Expected: All 11 tests PASS (NS mocks are harmless before Phase 1 is implemented — they're just extra responses that nothing queries yet)

- [ ] **Step 6: Commit**

```
git add test/check-lookalikes.spec.ts
git commit -m "test: add NS mocks to lookalike positive-case tests for two-phase probing"
```

---

### Task 2: Write failing tests for lookalike Phase 1 behavior

**Files:**
- Modify: `test/check-lookalikes.spec.ts`

- [ ] **Step 1: Write test — Phase 1 filters out variants without NS records**

Add to the main `checkLookalikes` describe block. This test verifies that a domain with A + MX but NO NS records is filtered out by Phase 1:

```typescript
it('should not report lookalikes that have no NS records (Phase 1 filter)', async () => {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const { name, type } = parseDohQuery(input);

		// tst.com has A and MX but NO NS records — should be filtered by Phase 1
		if (name === 'tst.com') {
			if (type === 'MX' || type === '15') {
				return Promise.resolve(
					createDohResponse(
						[{ name, type: 15 }],
						[{ name, type: 15, TTL: 300, data: '10 mail.evil.com.' }],
					),
				);
			}
			if (type === 'A' || type === '1') {
				return Promise.resolve(
					createDohResponse(
						[{ name, type: 1 }],
						[{ name, type: 1, TTL: 300, data: '1.2.3.4' }],
					),
				);
			}
		}
		return Promise.resolve(createDohResponse([], []));
	});
	const result = await run('test.com');
	// tst.com should NOT appear in findings — Phase 1 NS check eliminates it
	const tstFinding = result.findings.find((f) => f.title.includes('tst.com'));
	expect(tstFinding).toBeUndefined();
});
```

- [ ] **Step 2: Write test — Phase 1 passes variants with NS records to Phase 2**

```typescript
it('should report lookalikes that pass Phase 1 NS check', async () => {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const { name, type } = parseDohQuery(input);

		if (name === 'tst.com') {
			// Has NS → passes Phase 1
			if (type === 'NS' || type === '2') {
				return Promise.resolve(
					createDohResponse(
						[{ name, type: 2 }],
						[{ name, type: 2, TTL: 300, data: 'ns1.registrar.com.' }],
					),
				);
			}
			if (type === 'A' || type === '1') {
				return Promise.resolve(
					createDohResponse(
						[{ name, type: 1 }],
						[{ name, type: 1, TTL: 300, data: '1.2.3.4' }],
					),
				);
			}
		}
		return Promise.resolve(createDohResponse([], []));
	});
	const result = await run('test.com');
	const tstFinding = result.findings.find((f) => f.title.includes('tst.com'));
	expect(tstFinding).toBeDefined();
	expect(tstFinding!.severity).toBe('medium');
});
```

- [ ] **Step 3: Run tests to verify new tests fail**

Run: `npx vitest run test/check-lookalikes.spec.ts`
Expected: The Phase 1 filter test FAILS (tst.com is still detected because Phase 1 isn't implemented yet). The NS-passing test PASSES (NS mock is present, A mock returns data, existing code detects it).

- [ ] **Step 4: Commit**

```
git add test/check-lookalikes.spec.ts
git commit -m "test(red): add failing tests for lookalike Phase 1 NS filtering"
```

---

### Task 3: Implement two-phase probing in check_lookalikes

**Files:**
- Modify: `src/tools/check-lookalikes.ts`

- [ ] **Step 1: Add Phase 1 NS existence filter function**

Add after the `detectWildcardParents` function (after line 98). This function takes a list of domains and returns only those with NS records, using lean DNS options:

```typescript
import type { QueryDnsOptions } from '../lib/dns-types';

/** Lean DNS options for Phase 1 existence checks — fast, no retries, no secondary confirmation. */
const PHASE1_DNS_OPTS: QueryDnsOptions = {
	timeoutMs: 2000,
	retries: 0,
	skipSecondaryConfirmation: true,
};

/**
 * Phase 1: Fast NS existence check for all domains in parallel.
 * Returns only domains that have NS records (i.e., are registered).
 */
async function filterByNsExistence(domains: string[]): Promise<string[]> {
	const results = await Promise.allSettled(
		domains.map(async (domain) => {
			const ns = await queryDnsRecords(domain, 'NS', PHASE1_DNS_OPTS);
			return { domain, hasNs: ns.length > 0 };
		}),
	);
	return results
		.filter((r): r is PromiseFulfilledResult<{ domain: string; hasNs: boolean }> =>
			r.status === 'fulfilled' && r.value.hasNs)
		.map((r) => r.value.domain);
}
```

- [ ] **Step 2: Insert Phase 1 between wildcard filtering and adaptive batching**

In `checkLookalikesCore`, replace the direct `probeWithAdaptiveBatching(permsToProbe)` call (line 209) with a Phase 1 filter:

```typescript
	// Phase 1: Fast NS existence check — filter out unregistered domains
	const registeredPerms = await filterByNsExistence(permsToProbe);

	if (registeredPerms.length === 0) {
		findings.push(
			createFinding(
				'lookalikes',
				'No active lookalike domains detected',
				'info',
				`Checked ${permutations.length} domain permutations of ${domain}. No active registrations detected.`,
			),
		);
		return buildCheckResult('lookalikes', findings);
	}

	// Phase 2: Detail probe only registered domains
	const probeResults = await probeWithAdaptiveBatching(registeredPerms);
```

- [ ] **Step 3: Run tests to verify Phase 1 filter test passes**

Run: `npx vitest run test/check-lookalikes.spec.ts`
Expected: ALL tests PASS including the new Phase 1 filter test

- [ ] **Step 4: Commit**

```
git add src/tools/check-lookalikes.ts
git commit -m "perf: add Phase 1 NS existence filter to check_lookalikes"
```

---

### Task 4: Export Phase 1 DNS opts constant for test verification

**Files:**
- Modify: `src/tools/check-lookalikes.ts`
- Modify: `test/check-lookalikes.spec.ts`

- [ ] **Step 1: Export the PHASE1_DNS_OPTS constant**

Change `const PHASE1_DNS_OPTS` to `export const PHASE1_DNS_OPTS` in check-lookalikes.ts.

- [ ] **Step 2: Write test verifying Phase 1 DNS options**

```typescript
it('exports Phase 1 lean DNS options', async () => {
	const mod = await import('../src/tools/check-lookalikes');
	expect(mod.PHASE1_DNS_OPTS).toEqual({
		timeoutMs: 2000,
		retries: 0,
		skipSecondaryConfirmation: true,
	});
});
```

- [ ] **Step 3: Run tests**

Run: `npx vitest run test/check-lookalikes.spec.ts`
Expected: ALL tests PASS

- [ ] **Step 4: Commit**

```
git add src/tools/check-lookalikes.ts test/check-lookalikes.spec.ts
git commit -m "test: verify Phase 1 lean DNS options are exported correctly"
```

---

## Chunk 2: check_shadow_domains Two-Phase Probing

### Task 5: Write failing tests for shadow domains Phase 1 behavior

**Files:**
- Modify: `test/check-shadow-domains.spec.ts`

- [ ] **Step 1: Write test — Phase 1 filters variants without NS records**

Add to the main `checkShadowDomains` describe block. A variant with MX but no NS should be classified as "unregistered" (info), not probed for detailed records:

```typescript
it('should classify variant as unregistered when it has no NS records (Phase 1 filter)', async () => {
	const target = 'example.com';

	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const q = parseDohQuery(input);
		if (!q) return Promise.resolve(emptyResponse());
		const { name, type } = q;

		if (name === target && (type === 'MX' || type === '15')) {
			return Promise.resolve(mxRecords(target, ['10 mail.example.com.']));
		}

		// example.net has MX infrastructure but NO NS records — should not be detail-probed
		if (name === 'example.net') {
			if (type === 'MX' || type === '15') return Promise.resolve(mxRecords(name, ['10 mail.shadow.com.']));
			if (type === 'A' || type === '1') return Promise.resolve(aRecords(name, ['1.2.3.4']));
			if (type === 'TXT' || type === '16') return Promise.resolve(emptyResponse());
		}
		if (name === '_dmarc.example.net' && (type === 'TXT' || type === '16')) {
			return Promise.resolve(emptyResponse());
		}

		return Promise.resolve(emptyResponse());
	});

	const result = await run(target);
	// Without NS, example.net should be classified as "unregistered" (info), not critical
	const critical = result.findings.find(
		(f) => f.severity === 'critical' && f.detail.includes('example.net'),
	);
	expect(critical).toBeUndefined();

	const unregistered = result.findings.find(
		(f) => f.severity === 'info' && f.detail.includes('example.net') && /unregistered/i.test(f.title),
	);
	expect(unregistered).toBeDefined();
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run test/check-shadow-domains.spec.ts -t "Phase 1 filter"`
Expected: FAIL — currently example.net gets probed and classified as critical (it has MX, no SPF, no DMARC)

- [ ] **Step 3: Commit**

```
git add test/check-shadow-domains.spec.ts
git commit -m "test(red): add failing test for shadow domains Phase 1 NS filtering"
```

---

### Task 6: Implement two-phase probing in check_shadow_domains

**Files:**
- Modify: `src/tools/check-shadow-domains.ts`

- [ ] **Step 1: Add Phase 1 constants and NS existence filter**

Add after the `BACKOFF_DELAY_MS` constant (line 22) and export `FAILURE_THRESHOLD`:

```typescript
export const FAILURE_THRESHOLD = 0;

/** Lean DNS options for Phase 1 existence checks. */
export const PHASE1_DNS_OPTS: QueryDnsOptions = {
	timeoutMs: 2000,
	retries: 0,
	skipSecondaryConfirmation: true,
};
```

Add the Phase 1 filter function (after `probeVariant`):

```typescript
/**
 * Phase 1: Fast NS existence check for all variants in parallel.
 * Returns a Map of variant → NS records for registered domains.
 */
async function filterByNsExistence(
	variants: string[],
	dnsOpts: QueryDnsOptions,
): Promise<Map<string, string[]>> {
	const registered = new Map<string, string[]>();
	const results = await Promise.allSettled(
		variants.map(async (variant) => {
			const ns = await queryDnsRecords(variant, 'NS', { ...dnsOpts, ...PHASE1_DNS_OPTS });
			return { variant, ns };
		}),
	);
	for (const result of results) {
		if (result.status === 'fulfilled' && result.value.ns.length > 0) {
			registered.set(result.value.variant, result.value.ns);
		}
	}
	return registered;
}
```

- [ ] **Step 2: Modify probeVariant to accept pre-fetched NS records**

Change the `probeVariant` signature and implementation to optionally skip the NS query:

```typescript
async function probeVariant(
	variant: string,
	dnsOpts: QueryDnsOptions,
	prefetchedNs?: string[],
): Promise<VariantProbeResult> {
	const queries: Promise<unknown>[] = [
		prefetchedNs ? Promise.resolve(prefetchedNs) : queryDnsRecords(variant, 'NS', dnsOpts),
		queryDnsRecords(variant, 'A', dnsOpts),
		queryMxRecords(variant, dnsOpts),
		queryTxtRecords(variant, dnsOpts),
		queryTxtRecords(`_dmarc.${variant}`, dnsOpts),
	];

	const [nsResult, aResult, mxResult, txtResult, dmarcResult] = await Promise.allSettled(queries);

	const ns = nsResult.status === 'fulfilled' ? (nsResult.value as string[]) : [];
	const hasA = aResult.status === 'fulfilled' && (aResult.value as string[]).length > 0;
	const mx = mxResult.status === 'fulfilled'
		? (mxResult.value as Array<{ exchange: string }>).map((r) => r.exchange)
		: [];

	const txtValues = txtResult.status === 'fulfilled' ? (txtResult.value as string[]) : [];
	const hasSpf = txtValues.some((r) => r.toLowerCase().startsWith('v=spf1'));

	let dmarcPolicy: string | null = null;
	const dmarcValues = dmarcResult.status === 'fulfilled' ? (dmarcResult.value as string[]) : [];
	const dmarcRecord = dmarcValues.find((r) => r.toLowerCase().startsWith('v=dmarc1'));
	if (dmarcRecord) {
		const pMatch = dmarcRecord.match(/;\s*p=([^;\s]+)/i);
		dmarcPolicy = pMatch ? pMatch[1].toLowerCase() : 'none';
	}

	return { variant, ns, hasA, mx, hasSpf, dmarcPolicy };
}
```

- [ ] **Step 3: Replace single-phase batching with two-phase in checkShadowDomains**

In the `checkShadowDomains` function, replace the adaptive batching loop (lines 339-378) with:

```typescript
	// Phase 1: Fast NS existence check
	const registeredVariants = await filterByNsExistence(variants, dnsOpts);

	// Classify unregistered variants as info findings
	for (const variant of variants) {
		if (!registeredVariants.has(variant)) {
			findings.push(
				createFinding(
					'shadow_domains',
					'Brand variant unregistered',
					'info',
					`${variant} does not appear to be registered. Consider defensive registration to prevent brand abuse.`,
					{ variant, ns: [], mx: [], hasSpf: false, dmarcPolicy: null },
				),
			);
		}
	}

	// Phase 2: Detail probe only registered variants with NS passthrough
	const registeredList = [...registeredVariants.entries()];
	let batchSize = INITIAL_BATCH_SIZE;
	let delayMs = 0;
	const completedProbes: VariantProbeResult[] = [];
	let timedOut = false;

	for (let i = 0; i < registeredList.length; i += batchSize) {
		if (Date.now() >= deadline) {
			timedOut = true;
			break;
		}

		if (delayMs > 0) {
			await new Promise((resolve) => setTimeout(resolve, delayMs));
		}

		const batch = registeredList.slice(i, i + batchSize);
		const batchResults = await Promise.allSettled(
			batch.map(([variant, ns]) => probeVariant(variant, dnsOpts, ns)),
		);

		let failures = 0;
		for (const result of batchResults) {
			if (result.status === 'fulfilled') {
				completedProbes.push(result.value);
			} else {
				failures++;
			}
		}

		if (failures > FAILURE_THRESHOLD) {
			batchSize = Math.max(MIN_BATCH_SIZE, Math.floor(batchSize / 2));
			delayMs = BACKOFF_DELAY_MS;
		} else if (delayMs > 0) {
			batchSize = Math.min(INITIAL_BATCH_SIZE, batchSize + 1);
			delayMs = 0;
		}
	}

	let variantsChecked = registeredList.length;
```

Keep the rest of the function (classify probes, detectSharedNs, timeout finding, sorting) unchanged.

- [ ] **Step 4: Run all shadow domain tests**

Run: `npx vitest run test/check-shadow-domains.spec.ts`
Expected: ALL tests PASS including the new Phase 1 filter test

- [ ] **Step 5: Commit**

```
git add src/tools/check-shadow-domains.ts
git commit -m "perf: add Phase 1 NS existence filter to check_shadow_domains with NS passthrough"
```

---

### Task 7: Export shadow domains Phase 1 constant and add verification test

**Files:**
- Modify: `test/check-shadow-domains.spec.ts`

- [ ] **Step 1: Write test verifying Phase 1 DNS options and FAILURE_THRESHOLD export**

```typescript
it('exports Phase 1 lean DNS options and FAILURE_THRESHOLD', async () => {
	const mod = await import('../src/tools/check-shadow-domains');
	expect(mod.PHASE1_DNS_OPTS).toEqual({
		timeoutMs: 2000,
		retries: 0,
		skipSecondaryConfirmation: true,
	});
	expect(mod.FAILURE_THRESHOLD).toBe(0);
});
```

- [ ] **Step 2: Run tests**

Run: `npx vitest run test/check-shadow-domains.spec.ts`
Expected: ALL tests PASS

- [ ] **Step 3: Commit**

```
git add test/check-shadow-domains.spec.ts
git commit -m "test: verify shadow domains Phase 1 constants are exported"
```

---

## Chunk 3: Full Verification and Deployment

### Task 8: Run complete test suite and quality checks

**Files:** None (verification only)

- [ ] **Step 1: Run full test suite**

Run: `npm test`
Expected: All 907+ tests PASS, no regressions

- [ ] **Step 2: Run typecheck**

Run: `npm run typecheck`
Expected: Clean (no errors)

- [ ] **Step 3: Run lint**

Run: `npm run lint`
Expected: Clean (no errors)

- [ ] **Step 4: Verify no unintended changes**

Run: `git diff --stat HEAD~N` (where N = number of commits in this branch)
Expected: Only `src/tools/check-lookalikes.ts`, `src/tools/check-shadow-domains.ts`, `test/check-lookalikes.spec.ts`, `test/check-shadow-domains.spec.ts` modified

---

### Task 9: Create branch, push, and PR

- [ ] **Step 1: Create feature branch (if not already on one)**

```bash
git checkout -b perf/two-phase-dns-probing
```

- [ ] **Step 2: Push and create PR**

```bash
git push -u origin perf/two-phase-dns-probing
gh pr create --title "perf: two-phase DNS probing for check_lookalikes and check_shadow_domains" --body "..."
```

---

### Task 10: Deploy and validate with production metrics

- [ ] **Step 1: Merge and deploy**

```bash
gh pr merge --merge --admin
git checkout main && git pull
npm run deploy:private
```

- [ ] **Step 2: Run production validation**

Call `check_lookalikes` and `check_shadow_domains` via MCP tools against real domains. Verify:
- Responses complete in <5s (vs previous 7-20s)
- Findings are correct (no false negatives for known registered variants)
- No errors

- [ ] **Step 3: Check analytics after 24 hours**

Query Analytics Engine for `check_lookalikes` and `check_shadow_domains` P50/P95 and compare against pre-deploy baseline.
