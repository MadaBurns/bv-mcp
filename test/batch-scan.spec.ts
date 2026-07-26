import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import { env } from 'cloudflare:test';
import { IN_MEMORY_CACHE, buildScanCacheKey, buildCheckCacheKey } from '../src/lib/cache';
import { setupFetchMock, createDohResponse, txtResponse, nsResponse, caaResponse, dnssecResponse, httpResponse } from './helpers/dns-mock';
import { SCAN_CATEGORIES } from '../src/tools/scan-domain';

const { restore } = setupFetchMock();
beforeEach(() => IN_MEMORY_CACHE.clear());
afterEach(() => restore());

/**
 * Multi-dispatch fetch mock returning parseable DoH/HTTP responses for every check
 * category, so a scan completes (not errors) across the board — same routing shape
 * as scan-domain.spec.ts's `mockAllChecks`, duplicated here rather than imported
 * (that helper is module-local to scan-domain.spec.ts) to prove batchScan's REAL
 * scoring path independent of this suite's blanket-garbage `fetch` mock used by the
 * other tests in this file.
 */
function mockRealisticChecks(domain: string) {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

		if (url.includes('cloudflare-dns.com')) {
			if (url.includes('type=TXT') || url.includes('type=16')) {
				if (url.includes('_dmarc.')) return Promise.resolve(txtResponse(`_dmarc.${domain}`, ['v=DMARC1; p=reject']));
				if (url.includes('_domainkey.')) return Promise.resolve(txtResponse(`default._domainkey.${domain}`, ['v=DKIM1; k=rsa; p=MIGf']));
				if (url.includes('_mta-sts.')) return Promise.resolve(txtResponse(`_mta-sts.${domain}`, ['v=STSv1; id=20240101']));
				if (url.includes('_smtp._tls.'))
					return Promise.resolve(txtResponse(`_smtp._tls.${domain}`, ['v=TLSRPTv1; rua=mailto:tls@' + domain]));
				if (url.includes('default._bimi.'))
					return Promise.resolve(txtResponse(`default._bimi.${domain}`, [`v=BIMI1; l=https://${domain}/logo.svg`]));
				return Promise.resolve(txtResponse(domain, ['v=spf1 include:_spf.google.com -all']));
			}
			if (url.includes('type=NS') || url.includes('type=2'))
				return Promise.resolve(nsResponse(domain, [`ns1.${domain}.`, `ns2.${domain}.`]));
			if (url.includes('type=CAA') || url.includes('type=257')) return Promise.resolve(caaResponse(domain, ['0 issue "letsencrypt.org"']));
			if (url.includes('type=A') || url.includes('type=1')) return Promise.resolve(dnssecResponse(domain, true));
			// Fallback: valid, empty (NOERROR) DoH response — "no records found", a
			// genuine completed measurement, never a parse failure.
			return Promise.resolve(createDohResponse([], []));
		}
		if (url.includes('mta-sts.') && url.includes('.well-known')) {
			return Promise.resolve(httpResponse('version: STSv1\nmode: enforce\nmx: *.' + domain + '\nmax_age: 86400'));
		}
		return Promise.resolve(httpResponse('OK'));
	});
}

describe('batchScan', () => {
	beforeEach(() => {
		globalThis.fetch = vi.fn().mockResolvedValue(new Response('OK', { status: 200, headers: { 'content-type': 'text/plain' } }));
	});

	it('should scan multiple domains and return one result per domain', async () => {
		const { batchScan } = await import('../src/tools/batch-scan');
		const results = await batchScan(['example.com', 'test.com'], { kv: env.SCAN_CACHE });
		expect(results).toHaveLength(2);
		expect(results[0].domain).toBe('example.com');
		expect(results[1].domain).toBe('test.com');
		// This suite's blanket `globalThis.fetch` mock (above) returns plain-text "OK"
		// for EVERY fetch, DoH lookups included, so most check categories fail to parse
		// a response and error out (checkStatus: 'error') — under the evidence-sufficiency
		// gate (packages/dns-checks/src/scoring/engine.ts), a scan that completes fewer
		// than 60% of its attempted checks is correctly ungraded (score/grade: null),
		// same as a domain suffering a real DNS outage. `measured` stays true because
		// checks DID run (and produced errored/inconclusive results, not zero checks) —
		// it is a different signal from "was the evidence sufficient to grade".
		expect(results[0].measured).toBe(true);
		expect(results[0].score).toBeNull();
		expect(results[0].grade).toBeNull();
	});

	it('carries a numeric score and non-null grade for a genuinely well-measured scan (real scoring path, not a stub)', async () => {
		// L6 coverage regression fix: the test above proves the evidence gate correctly
		// ungrades a mostly-broken mock, but with its assertion flipped to null it no
		// longer proves batchScan can carry a REAL graded result end-to-end — a
		// regression that ungraded every batch scan unconditionally would now pass
		// every test in this file. This test closes that gap with a properly-routed
		// DoH/HTTP mock (mockRealisticChecks) so every check category gets a parseable
		// response and genuinely completes, driving evidence comfortably over the 60%
		// gate via the real scan_domain → computeScanScore path (no scanFn stub).
		const domain = 'realistic-scan-example.com';
		// Clear both cache-key shapes explicitly (in addition to the beforeEach's
		// blanket IN_MEMORY_CACHE.clear()) so a stale entry from another case can never
		// leak a cached score into this assertion.
		IN_MEMORY_CACHE.delete(buildScanCacheKey(domain));
		for (const category of SCAN_CATEGORIES) {
			IN_MEMORY_CACHE.delete(buildCheckCacheKey(domain, category));
		}
		mockRealisticChecks(domain);

		const { batchScan } = await import('../src/tools/batch-scan');
		const results = await batchScan([domain], { kv: env.SCAN_CACHE });

		expect(results).toHaveLength(1);
		expect(results[0].domain).toBe(domain);
		expect(results[0].measured).toBe(true);
		expect(typeof results[0].score).toBe('number');
		expect(results[0].score).toBeGreaterThanOrEqual(0);
		expect(results[0].score).toBeLessThanOrEqual(100);
		expect(typeof results[0].grade).toBe('string');
		expect(results[0].grade).not.toBeNull();
	});

	it('emits null score/grade/passed for an invalid domain instead of a fabricated F', async () => {
		const { batchScan } = await import('../src/tools/batch-scan');
		const results = await batchScan(['example.com', 'not--valid--domain!@#'], { kv: env.SCAN_CACHE });
		const errorResult = results.find((r) => r.error);
		expect(errorResult).toBeDefined();
		expect(errorResult!.score).toBeNull();
		expect(errorResult!.grade).toBeNull();
		expect(errorResult!.passed).toBeNull();
		expect(errorResult!.maturityStage).toBeNull();
		expect(errorResult!.measured).toBe(false);
	});

	it('an error placeholder reports zero evidence and does NOT claim the evidence gate fired', async () => {
		const { batchScan } = await import('../src/tools/batch-scan');
		const results = await batchScan(['not a domain']);
		expect(results).toHaveLength(1);
		expect(results[0].evidence).toEqual({ attempted: 0, completed: 0, ratio: 0 });
		expect(results[0].evidenceInsufficient).toBe(false);
		expect(results[0].evidenceNote).toBeNull();
	});

	it('should reject more than 10 domains', async () => {
		const { batchScan } = await import('../src/tools/batch-scan');
		const tooMany = Array.from({ length: 11 }, (_, i) => `domain${i}.com`);
		await expect(batchScan(tooMany)).rejects.toThrow(/max.*10/i);
	});

	// ---- Global wall-clock budget (production p95=p99=28,000ms finding) ----

	// Minimal ScanDomainResult shape for test stubs — fields match what
	// buildStructuredScanResult reads to compose the StructuredScanResult.
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	function fakeScanResult(domain: string, score = 80): any {
		return {
			domain,
			score: {
				overall: score,
				grade: 'B',
				summary: 'fake',
				categoryScores: {},
				findings: [],
			},
			checks: [],
			maturity: { stage: 2, label: 'Baseline', description: 'fake', nextStep: null },
			context: { profile: 'mail_enabled', signals: [] },
			cached: false,
			timestamp: '2026-04-25T00:00:00.000Z',
			scoringNote: null,
			adaptiveWeightDeltas: null,
			interactionEffects: [],
		};
	}

	it('emits null score/grade for a budget-exceeded domain instead of a fabricated F', async () => {
		const { batchScan } = await import('../src/tools/batch-scan');
		// Each scan takes 300ms; a 10ms budget guarantees every domain is
		// budget-exceeded before its worker slot opens.
		const slowScan = (async (domain: string) => {
			await new Promise((resolve) => setTimeout(resolve, 300));
			return fakeScanResult(domain);
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
		}) as any;
		const results = await batchScan(['a.com', 'b.com'], { kv: env.SCAN_CACHE, budgetMs: 10, scanFn: slowScan });

		const budgetExceeded = results.filter((r) => r.error === 'batch_budget_exceeded');
		// Non-empty guard: without this the loop below is vacuous.
		expect(budgetExceeded.length).toBeGreaterThan(0);
		for (const r of budgetExceeded) {
			expect(r.score).toBeNull();
			expect(r.grade).toBeNull();
			expect(r.passed).toBeNull();
			expect(r.measured).toBe(false);
		}
	});

	it('formatBatchScan renders "not measured" for an invalid domain', async () => {
		const { batchScan, formatBatchScan } = await import('../src/tools/batch-scan');
		const results = await batchScan(['not--valid--domain!@#'], { kv: env.SCAN_CACHE });
		const text = formatBatchScan(results, 'full');
		// This fixture's result always carries `error` truthy (validateDomain fails),
		// so it never reaches the score-rendering branch under either the buggy or
		// the fixed formatter — only this assertion is discriminating for this fixture.
		expect(text).toContain('not measured');
	});

	it('formatBatchScan does not fabricate a score for a scan that ran zero checks (NXDOMAIN/SERVFAIL shape)', async () => {
		// Mirrors what buildNonResolvingResult / buildDnsBrokenResult emitted BEFORE 3.35.0:
		// a domain that never resolves runs NO checks, but the raw ScanScore still carries a
		// placeholder overall/grade pair (neither is null) — only `checks: []` (→ measured:
		// false) signals "not measured". The producers now emit nulls; this hostile pair stays
		// pinned because gating formatBatchScan on score/grade nullness alone would render a
		// confident score for any OTHER ScanScore source that reintroduces a placeholder.
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const nonResolvingScan = (async (domain: string): Promise<any> => ({
			domain,
			score: { overall: 0, grade: 'N/A', summary: 'does not resolve', categoryScores: {}, findings: [] },
			checks: [],
			maturity: { stage: 0, label: 'Does not resolve', description: 'x', nextStep: null },
			context: { profile: 'mail_enabled', signals: [] },
			cached: false,
			timestamp: '2026-07-26T00:00:00.000Z',
			scoringNote: null,
			adaptiveWeightDeltas: null,
			interactionEffects: [],
			resolves: false,
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
		})) as any;

		const { batchScan, formatBatchScan } = await import('../src/tools/batch-scan');
		const results = await batchScan(['nxprobe.com'], { kv: env.SCAN_CACHE, scanFn: nonResolvingScan });
		expect(results[0].measured).toBe(false);

		const text = formatBatchScan(results, 'full');
		expect(text).toContain('not measured');
		expect(text).not.toContain('0/100');
		expect(text).toContain('Scanned 0/1 domain(s) successfully');
	});

	it('formatBatchScan handles an ungraded result that carries NO error field', async () => {
		// Slice 3 (the evidence gate) will emit ungraded results with no `error`.
		// The formatter must key off the null score, not off `error`, or that
		// future result renders as `null/100 (null)`. Constructed directly here
		// because no code path produces this shape yet.
		const { batchScan, formatBatchScan } = await import('../src/tools/batch-scan');
		const results = await batchScan(['example.com'], { kv: env.SCAN_CACHE });
		expect(results).toHaveLength(1);
		const ungraded = { ...results[0], score: null, grade: null, passed: null, measured: true };
		delete (ungraded as { error?: string }).error;

		const text = formatBatchScan([ungraded], 'full');
		expect(text).toContain('not measured');
		expect(text).not.toContain('null');
		expect(text).not.toContain('/100');
	});

	it('respects global wall-clock budget when scans are slow', async () => {
		const { batchScan } = await import('../src/tools/batch-scan');

		// Each scan takes 300ms. Budget is 500ms. With concurrency=2, first 2
		// scans finish around 300ms; next 2 finish around 600ms (budget exceeded
		// for most of those); remaining 6 never start and get budget-exceeded.
		const scanFn = vi.fn().mockImplementation(async (domain: string) => {
			await new Promise((r) => setTimeout(r, 300));
			return fakeScanResult(domain);
		});

		const domains = Array.from({ length: 10 }, (_, i) => `d${i}.example.com`);
		const start = Date.now();
		const results = await batchScan(domains, {
			kv: env.SCAN_CACHE,
			budgetMs: 500,
			concurrency: 2,
			scanFn,
		});
		const elapsed = Date.now() - start;

		expect(results).toHaveLength(10);
		expect(elapsed).toBeLessThan(1000); // not the 3s sequential worst-case
		const budgetErrors = results.filter((r) => /budget/i.test(r.error ?? ''));
		expect(budgetErrors.length).toBeGreaterThan(0);
	});

	it('first slow domain does not starve others when concurrency > 1', async () => {
		const { batchScan } = await import('../src/tools/batch-scan');

		// First domain hangs 5s; others finish in 50ms.
		const scanFn = vi.fn().mockImplementation(async (domain: string) => {
			const delay = domain.startsWith('slow.') ? 5000 : 50;
			await new Promise((r) => setTimeout(r, delay));
			return fakeScanResult(domain);
		});

		const domains = ['slow.com', 'a.com', 'b.com', 'c.com', 'd.com', 'e.com', 'f.com', 'g.com', 'h.com', 'i.com'];
		const results = await batchScan(domains, {
			kv: env.SCAN_CACHE,
			budgetMs: 1000,
			concurrency: 3,
			scanFn,
		});

		// The 9 fast domains should all have completed successfully despite slow.com hanging.
		const fastResults = results.filter((r) => r.domain !== 'slow.com' && !r.error);
		expect(fastResults.length).toBeGreaterThanOrEqual(8);
		// slow.com should have a budget error, not a completed scan
		const slow = results.find((r) => r.domain === 'slow.com');
		expect(slow?.error).toMatch(/budget/i);
	});

	it('does not call scanDomain for budget-exceeded tail', async () => {
		const { batchScan } = await import('../src/tools/batch-scan');

		let callCount = 0;
		const scanFn = vi.fn().mockImplementation(async (domain: string) => {
			callCount++;
			await new Promise((r) => setTimeout(r, 400));
			return fakeScanResult(domain);
		});

		const domains = Array.from({ length: 10 }, (_, i) => `q${i}.example.com`);
		await batchScan(domains, {
			kv: env.SCAN_CACHE,
			budgetMs: 500,
			concurrency: 1,
			scanFn,
		});

		// With 400ms per scan, budget 500ms, concurrency 1: only ~1 scan starts
		// before the deadline passes. Implementations should not keep calling
		// scanFn after the deadline.
		expect(callCount).toBeLessThan(5);
	});
});
