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

	it('marks a zero-check scan without an NXDOMAIN/broken-DNS signal as retryable, unlike a genuine no-DNS abstain', async () => {
		const { batchScan } = await import('../src/tools/batch-scan');
		// This is the batch-only failure shape from #686: scanDomain returned without
		// an exception but also without ever starting its check matrix. It must not be
		// indistinguishable from the explicit NXDOMAIN short-circuit below.
		const noEvidenceScan = (async (domain: string) => ({
			...fakeScanResult(domain),
			score: { overall: null, grade: null, summary: 'no checks ran', categoryScores: {}, findings: [] },
			checks: [],
			context: { profile: 'mail_enabled', signals: [], weights: {}, detectedProvider: null },
			// No `resolves` status: this is not a confirmed absent/broken domain.
		})) as never;
		const nxdomainScan = (async (domain: string) => ({
			...fakeScanResult(domain),
			score: { overall: null, grade: null, summary: 'NXDOMAIN', categoryScores: {}, findings: [] },
			checks: [],
			context: { profile: 'mail_enabled', signals: [], weights: {}, detectedProvider: null },
			resolves: false,
		})) as never;

		const [unexpected, nxdomain] = await Promise.all([
			batchScan(['live-no-evidence.com'], { scanFn: noEvidenceScan }),
			batchScan(['missing-no-evidence.com'], { scanFn: nxdomainScan }),
		]);

		expect(unexpected[0]).toMatchObject({
			evidence: { attempted: 0, completed: 0, ratio: 0 },
			evidenceInsufficient: true,
			scoringProfile: null,
			error: 'scan_produced_no_evidence',
		});
		expect(unexpected[0].evidenceNote).toMatch(/retry/i);
		expect(nxdomain[0]).toMatchObject({
			resolves: false,
			evidenceInsufficient: false,
		});
		expect(nxdomain[0].error).toBeUndefined();
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

	it('makes compact structured batch output materially smaller while full results retain findings', async () => {
		const { batchScan, compactBatchScanResults } = await import('../src/tools/batch-scan');
		const detail = 'Repeated finding detail. '.repeat(100);
		/* eslint-disable @typescript-eslint/no-explicit-any -- fake ScanFn stub, see fakeScanResult() above */
		const verboseScan = async (domain: string): Promise<any> => ({
			...fakeScanResult(domain),
			// isMeasured() reads checks.length > 0 — a real scan always populates this,
			// so the stub needs at least one entry for `measured: true` to be exercised.
			checks: [{ category: 'dmarc', checkStatus: 'completed' }],
			score: {
				...fakeScanResult(domain).score,
				findings: Array.from({ length: 12 }, (_, i) => ({
					category: 'dmarc',
					title: `Finding ${i}`,
					severity: 'medium',
					detail,
				})),
			},
		});
		/* eslint-enable @typescript-eslint/no-explicit-any */
		const results = await batchScan(
			Array.from({ length: 10 }, (_, i) => `compact-${i}.example.com`),
			{ scanFn: verboseScan },
		);
		const compact = compactBatchScanResults(results);

		expect(results[0].findings).toHaveLength(12);
		expect(compact.results).toHaveLength(10);
		expect(compact.results[0]).toMatchObject({
			domain: 'compact-0.example.com',
			score: 80,
			grade: 'B',
			measured: true,
			findingCounts: { medium: 12 },
			scoringProfile: 'mail_enabled',
		});
		expect(compact.results[0]).not.toHaveProperty('findings');
		expect(compact.results[0]).not.toHaveProperty('checkStatuses');
		expect(compact).toHaveProperty('scoringModelVersion');
		expect(compact).toHaveProperty('scoringConfigHash');
		expect(JSON.stringify(compact).length).toBeLessThan(JSON.stringify(results).length / 10);
	});

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

	// Tail-drop regression: a batch that silently dropped its budget-exceeded tail
	// (e.g. a 10-domain estate scan that only measured 7) exposed NO top-level signal
	// that it was incomplete, so a caller that did not inspect every row's `measured`
	// flag treated the dropped domains as unscored/zero. The batch now carries an
	// explicit `incomplete`/`unscanned` summary in addition to the per-row placeholders.
	it('exposes a batch-level incomplete flag and unscanned list when the budget drops the tail', async () => {
		const { batchScan, compactBatchScanResults, formatBatchScan } = await import('../src/tools/batch-scan');
		// Each scan takes 300ms; a 10ms budget guarantees every domain is
		// budget-exceeded before its worker slot opens, so the whole tail is dropped.
		const slowScan = (async (domain: string) => {
			await new Promise((resolve) => setTimeout(resolve, 300));
			return fakeScanResult(domain);
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
		}) as any;
		const inputs = ['nec.co.nz', 'ird.govt.nz', 'nzta.govt.nz'];
		const results = await batchScan(inputs, { kv: env.SCAN_CACHE, budgetMs: 10, concurrency: 1, scanFn: slowScan });

		// Per-row contract is unchanged: budget-dropped rows still carry measured:false + error.
		const dropped = results.filter((r) => r.error === 'batch_budget_exceeded');
		expect(dropped.length).toBeGreaterThan(0);
		for (const r of dropped) expect(r.measured).toBe(false);

		// NEW batch-level signal on the compact wire payload.
		const compact = compactBatchScanResults(results);
		expect(compact.incomplete).toBe(true);
		expect(compact.unscanned).toEqual(expect.arrayContaining(dropped.map((r) => r.domain)));
		expect(compact.unscanned).toHaveLength(dropped.length);

		// NEW unmissable banner in the text summary (both compact and full formats).
		const text = formatBatchScan(results, 'compact');
		expect(text).toContain('INCOMPLETE');
		for (const r of dropped) expect(text).toContain(r.domain);
	});

	it('reports a complete batch as not incomplete with an empty unscanned list', async () => {
		const { batchScan, compactBatchScanResults, formatBatchScan } = await import('../src/tools/batch-scan');
		const fastScan = (async (domain: string) => ({
			...fakeScanResult(domain),
			// isMeasured() reads checks.length > 0 — populate one so measured: true.
			checks: [{ category: 'dmarc', checkStatus: 'completed' }],
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
		})) as any;
		const results = await batchScan(['a.com', 'b.com'], { kv: env.SCAN_CACHE, scanFn: fastScan });

		const compact = compactBatchScanResults(results);
		expect(compact.incomplete).toBe(false);
		expect(compact.unscanned).toEqual([]);
		expect(formatBatchScan(results, 'compact')).not.toContain('INCOMPLETE');
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

	it('formatBatchScan handles an ungraded result that carries NO error field and is not evidence-insufficient', async () => {
		// The formatter must key off the null score, not off `error`, or that result
		// renders as `null/100 (null)`. Constructed directly here to isolate the GENERIC
		// ungraded fallback from the evidence-insufficient case (F3 pins that one
		// separately, below) — this fixture explicitly clears evidenceInsufficient even
		// though `example.com`'s real batchScan result under this file's blanket fetch
		// mock happens to be evidence-insufficient itself, so the override is deliberate.
		const { batchScan, formatBatchScan } = await import('../src/tools/batch-scan');
		const results = await batchScan(['example.com'], { kv: env.SCAN_CACHE });
		expect(results).toHaveLength(1);
		const ungraded = {
			...results[0],
			score: null,
			grade: null,
			passed: null,
			measured: true,
			evidenceInsufficient: false,
			evidenceNote: null,
		};
		delete (ungraded as { error?: string }).error;

		const text = formatBatchScan([ungraded], 'full');
		expect(text).toContain('not measured');
		expect(text).not.toContain('null');
		expect(text).not.toContain('/100');
		expect(text).not.toContain('evidence insufficient');
	});

	// F3 (fix round 1): a gate-fired item (checks ran, evidence too thin to grade) must
	// render distinctly from a domain that was never scanned at all — both used to collapse
	// to the same "not measured" text.
	it('formatBatchScan renders "evidence insufficient" (not "not measured") for a gate-fired item', async () => {
		const { batchScan, formatBatchScan } = await import('../src/tools/batch-scan');
		const results = await batchScan(['example.com'], { kv: env.SCAN_CACHE });
		expect(results).toHaveLength(1);
		const gateFired = {
			...results[0],
			score: null,
			grade: null,
			passed: null,
			measured: true,
			evidence: { attempted: 19, completed: 8, ratio: 8 / 19 },
			evidenceInsufficient: true,
			evidenceNote: 'Only 8 of 19 checks completed (42%), below the 60% evidence threshold.',
		};
		delete (gateFired as { error?: string }).error;

		const text = formatBatchScan([gateFired], 'full');
		expect(text).toContain('evidence insufficient (8/19 checks completed)');
		expect(text).not.toContain('not measured');
	});

	it('formatBatchScan still renders "not measured" (not "evidence insufficient") for a truly never-ran domain', async () => {
		const { batchScan, formatBatchScan } = await import('../src/tools/batch-scan');
		const results = await batchScan(['not--valid--domain!@#'], { kv: env.SCAN_CACHE });
		const text = formatBatchScan(results, 'full');
		expect(text).toContain('not measured');
		expect(text).not.toContain('evidence insufficient');
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
		const scanFn = vi.fn().mockImplementation(async (domain: string, _kv: KVNamespace | undefined, opts: { signal?: AbortSignal }) => {
			const delay = domain.startsWith('slow.') ? 5000 : 50;
			await new Promise<void>((resolve, reject) => {
				const timer = setTimeout(resolve, delay);
				opts.signal?.addEventListener('abort', () => {
					clearTimeout(timer);
					reject(opts.signal?.reason);
				}, { once: true });
			});
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

	it('aborts and settles every losing scan before returning at the batch deadline', async () => {
		const { batchScan } = await import('../src/tools/batch-scan');
		let active = 0;
		let aborted = 0;
		const scanFn = vi.fn().mockImplementation((domain: string, _kv: KVNamespace | undefined, opts: { signal?: AbortSignal }) => {
			active++;
			return new Promise((resolve, reject) => {
				opts.signal?.addEventListener('abort', () => {
					active--;
					aborted++;
					reject(opts.signal?.reason);
				}, { once: true });
			});
		});

		const results = await batchScan(['a.com', 'b.com', 'c.com'], { budgetMs: 20, concurrency: 3, scanFn });

		expect(aborted).toBe(3);
		expect(active).toBe(0);
		expect(results.every((result) => result.error === 'batch_budget_exceeded' && !result.measured)).toBe(true);
	});

	it('shares one five-slot DNS semaphore across every scan in a batch', async () => {
		const { batchScan } = await import('../src/tools/batch-scan');
		const semaphores: unknown[] = [];
		const scanFn = vi.fn().mockImplementation(async (domain: string, _kv: KVNamespace | undefined, opts: { dnsSemaphore?: unknown }) => {
			semaphores.push(opts.dnsSemaphore);
			return fakeScanResult(domain);
		});

		await batchScan(['a.com', 'b.com', 'c.com'], { concurrency: 3, scanFn });

		expect(new Set(semaphores).size).toBe(1);
		const semaphore = semaphores[0] as { run<T>(fn: () => Promise<T>): Promise<T> };
		let active = 0;
		let peak = 0;
		await Promise.all(Array.from({ length: 12 }, () => semaphore.run(async () => {
			active++;
			peak = Math.max(peak, active);
			await new Promise((resolve) => setTimeout(resolve, 5));
			active--;
		})));
		expect(peak).toBe(5);
	});
});
