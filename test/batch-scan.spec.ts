import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import { env } from 'cloudflare:test';
import { IN_MEMORY_CACHE } from '../src/lib/cache';
import { setupFetchMock } from './helpers/dns-mock';

const { restore } = setupFetchMock();
beforeEach(() => IN_MEMORY_CACHE.clear());
afterEach(() => restore());

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
		// A domain that actually scanned must carry a real measurement.
		expect(results[0].measured).toBe(true);
		expect(typeof results[0].score).toBe('number');
		expect(typeof results[0].grade).toBe('string');
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
		// Mirrors buildNonResolvingResult / buildDnsBrokenResult in scan-domain.ts: a
		// domain that never resolves runs NO checks, but the raw ScanScore still carries
		// overall: 0 / grade: 'N/A' (neither is null) — only `checks: []` (→ measured:
		// false) signals "not measured". Gating formatBatchScan on score/grade nullness
		// alone would still render "0/100 (N/A)" and count it as a successful scan.
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
