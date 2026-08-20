import { describe, it, expect, afterEach, vi } from 'vitest';
import type { CheckResult } from '../src/lib/scoring';
import type { ScanDomainResult } from '../src/tools/scan-domain';
import { setupFetchMock, createDohResponse, txtResponse, nsResponse, caaResponse, dnssecResponse, httpResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();
afterEach(() => restore());

function mockAllChecks() {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

		if (url.includes('cloudflare-dns.com')) {
			if (url.includes('type=TXT') || url.includes('type=16')) {
				if (url.includes('_dmarc.')) {
					return Promise.resolve(txtResponse('_dmarc.example.com', ['v=DMARC1; p=reject']));
				}
				if (url.includes('_domainkey.')) {
					return Promise.resolve(txtResponse('default._domainkey.example.com', ['v=DKIM1; k=rsa; p=MIGf']));
				}
				if (url.includes('_mta-sts.')) {
					return Promise.resolve(txtResponse('_mta-sts.example.com', ['v=STSv1; id=20240101']));
				}
				if (url.includes('_smtp._tls.')) {
					return Promise.resolve(txtResponse('_smtp._tls.example.com', ['v=TLSRPTv1; rua=mailto:tls@example.com']));
				}
				if (url.includes('default._bimi.')) {
					return Promise.resolve(txtResponse('default._bimi.example.com', ['v=BIMI1; l=https://example.com/logo.svg']));
				}
				return Promise.resolve(txtResponse('example.com', ['v=spf1 include:_spf.google.com -all']));
			}

			if (url.includes('type=NS') || url.includes('type=2')) {
				return Promise.resolve(nsResponse('example.com', ['ns1.example.com.', 'ns2.example.com.']));
			}

			if (url.includes('type=CAA') || url.includes('type=257')) {
				return Promise.resolve(caaResponse('example.com', ['0 issue "letsencrypt.org"']));
			}

			if (url.includes('type=A') || url.includes('type=1')) {
				return Promise.resolve(dnssecResponse('example.com', true));
			}

			return Promise.resolve(createDohResponse([], []));
		}

		if (url.includes('mta-sts.') && url.includes('.well-known')) {
			return Promise.resolve(httpResponse('version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 86400'));
		}

		if (url.startsWith('https://')) {
			return Promise.resolve(httpResponse('OK'));
		}

		return Promise.resolve(httpResponse('OK'));
	});
}

function createMockScan(overrides?: Partial<ScanDomainResult>): ScanDomainResult {
	return {
		domain: 'example.com',
		score: {
			overall: 90,
			grade: 'A',
			categoryScores: {
				spf: 100,
				dmarc: 100,
				dkim: 100,
				dnssec: 100,
				ssl: 100,
				mta_sts: 100,
				ns: 100,
				caa: 100,
				subdomain_takeover: 100,
				mx: 100,
				bimi: 100,
				tlsrpt: 100,
				lookalikes: 100,
			},
			findings: [],
			summary: '',
		},
		checks: [
			{ category: 'spf', passed: true, score: 90, findings: [] },
			{
				category: 'dmarc',
				passed: true,
				score: 95,
				findings: [{ category: 'dmarc', title: 'DMARC p=reject', severity: 'info', detail: '' }],
			},
			{ category: 'dkim', passed: true, score: 85, findings: [] },
			{ category: 'dnssec', passed: true, score: 70, findings: [] },
		],
		maturity: {
			stage: 3,
			label: 'Established',
			description: 'Strong controls with room for advanced hardening.',
			nextStep: 'Improve optional controls and monitoring depth.',
		},
		cached: false,
		timestamp: new Date().toISOString(),
		...overrides,
	};
}

describe('compare_baseline schema', () => {
	it('is registered in TOOLS', async () => {
		const { TOOLS } = await import('../src/schemas/tool-definitions');
		const tool = TOOLS.find((value) => value.name === 'compare_baseline');
		expect(tool).toBeDefined();
		expect(tool?.inputSchema.required).toContain('domain');
		expect(tool?.inputSchema.required).toContain('baseline');
	});
});

describe('compareBaseline', () => {
	it('returns no violations when domain meets baseline requirements', async () => {
		const { compareBaseline } = await import('../src/tools/compare-baseline');
		const result = compareBaseline(createMockScan(), { grade: 'B', require_spf: true });
		expect(result.passed).toBe(true);
		expect(result.violations).toHaveLength(0);
	});

	it('flags grade violation', async () => {
		const { compareBaseline } = await import('../src/tools/compare-baseline');
		const result = compareBaseline(
			createMockScan({
				domain: 'weak.com',
				score: { ...createMockScan().score, overall: 60, grade: 'D+', categoryScores: createMockScan().score.categoryScores },
			}),
			{ grade: 'B' },
		);
		expect(result.passed).toBe(false);
		expect(result.violations).toContainEqual(expect.objectContaining({ rule: 'grade', expected: 'B', actual: 'D+' }));
	});

	it('flags missing DMARC enforcement', async () => {
		const { compareBaseline } = await import('../src/tools/compare-baseline');
		const result = compareBaseline(
			createMockScan({
				domain: 'lax.com',
				score: { ...createMockScan().score, overall: 70, grade: 'C+' },
				checks: [
					{
						category: 'dmarc',
						passed: false,
						score: 40,
						findings: [{ category: 'dmarc', title: 'DMARC policy is none', severity: 'high', detail: 'p=none' }],
					},
				],
			}),
			{ require_dmarc_enforce: true },
		);
		expect(result.passed).toBe(false);
		expect(result.violations).toContainEqual(expect.objectContaining({ rule: 'require_dmarc_enforce' }));
	});

	it('flags critical finding count exceeding max', async () => {
		const { compareBaseline } = await import('../src/tools/compare-baseline');
		const result = compareBaseline(
			createMockScan({
				domain: 'bad.com',
				score: {
					...createMockScan().score,
					overall: 50,
					grade: 'E',
					findings: [
						{ category: 'ssl', title: 'Cert expired', severity: 'critical', detail: '' },
						{ category: 'dnssec', title: 'No DNSSEC', severity: 'critical', detail: '' },
					],
				},
			}),
			{ max_critical_findings: 0 },
		);
		expect(result.passed).toBe(false);
		expect(result.violations).toContainEqual(expect.objectContaining({ rule: 'max_critical_findings', expected: 0, actual: 2 }));
	});

	it('returns an inconclusive verdict — never pass, never fail — for an ungraded scan', async () => {
		const { compareBaseline } = await import('../src/tools/compare-baseline');
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const ungradedScan: any = {
			domain: 'never-measured.example',
			score: { overall: null, grade: null, categoryScores: {}, findings: [], summary: 'does not resolve' },
			checks: [],
			maturity: { stage: 0, label: 'Does not resolve', description: 'x', nextStep: null },
			context: { profile: 'mail_enabled', signals: [] },
			cached: false,
			timestamp: '2026-07-26T00:00:00.000Z',
		};

		const result = compareBaseline(ungradedScan, { score: 50, grade: 'B' });

		// The whole point of R7: `null < 50` is true in JS, so the pre-fix code
		// FAILED an unmeasured domain on the score rule while silently PASSING it
		// on the grade rule. Neither verdict is permitted now.
		expect(result.passed).toBeNull();
		expect(result.violations.filter((v) => v.rule === 'score')).toHaveLength(0);
		expect(result.violations.filter((v) => v.rule === 'grade')).toHaveLength(0);
		expect(result.inconclusiveRules).toContain('score');
		expect(result.inconclusiveRules).toContain('grade');
	});

	it('returns inconclusive for the control rules too when the scan ran zero checks', async () => {
		const { compareBaseline } = await import('../src/tools/compare-baseline');
		// The NXDOMAIN / DNS-broken shape: buildNonResolvingResult and
		// buildDnsBrokenResult BOTH emit `checks: []` AND `findings: []`.
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const unmeasuredScan: any = {
			domain: 'never-measured.example',
			score: { overall: null, grade: null, categoryScores: {}, findings: [], summary: 'does not resolve' },
			checks: [],
			maturity: { stage: 0, label: 'Does not resolve', description: 'x', nextStep: null },
			context: { profile: 'mail_enabled', signals: [] },
			cached: false,
			timestamp: '2026-07-26T00:00:00.000Z',
		};

		// The common CI baseline — note it carries NO grade/score key, so the
		// grade/score inconclusive path cannot rescue it.
		const result = compareBaseline(unmeasuredScan, { require_spf: true, require_dmarc_enforce: true, max_critical_findings: 0 });

		// Pre-fix this returned a confident `passed: false` with TWO violations
		// ("SPF is required but check did not pass") and `Rules checked: 3`, from
		// `check?.passed ?? false` coercing absence-of-measurement into failure —
		// i.e. a client report asserting a named org fails SPF and DMARC on a
		// domain that is not registered.
		expect(result.passed).toBeNull();
		expect(result.violations).toHaveLength(0);
		expect(result.checkedRules).toBe(0);
		// Includes `max_critical_findings`, which passed pre-fix by counting an EMPTY
		// findings array — "zero criticals" asserted about a domain nobody scanned.
		expect(result.inconclusiveRules).toEqual(['require_dmarc_enforce', 'require_spf', 'max_critical_findings']);
	});

	/**
	 * The PASSING side of the finding caps, which the failing-side tests cannot pin.
	 *
	 * "Zero criticals because nothing was measured" and "zero criticals because the
	 * domain is genuinely clean" are the two states this slice must keep apart, and
	 * only the first was guarded. The naive fix a reader takes straight from the bug
	 * description — `if (!scanMeasured || scan.score.findings.length === 0)` — is
	 * indistinguishable from the correct one on every failing-side fixture, because
	 * they all carry findings. It turns every genuinely-clean domain INCONCLUSIVE:
	 * a CI gate that can never go green, for the customers in the best shape.
	 */
	it('PASSES the finding caps for a measured, genuinely-clean scan — an empty findings list is a real result', async () => {
		const { compareBaseline } = await import('../src/tools/compare-baseline');
		// Checks ran; the domain is simply clean. `findings: []` here is a
		// MEASUREMENT of zero, not an absence of measurement.
		const measuredAndClean = createMockScan({ domain: 'clean.example' });
		expect(measuredAndClean.score.findings).toHaveLength(0);
		expect(measuredAndClean.checks.length).toBeGreaterThan(0);

		const result = compareBaseline(measuredAndClean, { max_critical_findings: 0, max_high_findings: 0 });

		expect(result.passed).toBe(true);
		expect(result.inconclusiveRules).toEqual([]);
		expect(result.violations).toHaveLength(0);
		// Both caps were genuinely evaluated, not quietly skipped.
		expect(result.checkedRules).toBe(2);
	});

	it('PASSES the critical cap for a scan with findings but none of that severity', async () => {
		const { compareBaseline } = await import('../src/tools/compare-baseline');
		// Distinct from the case above: findings EXIST, just none critical. Pins the
		// severity filter itself rather than the emptiness of the array.
		const noCriticals = createMockScan({
			domain: 'no-criticals.example',
			score: {
				...createMockScan().score,
				findings: [
					{ category: 'dnssec', title: 'DNSSEC not enabled', severity: 'high', detail: '' },
					{ category: 'caa', title: 'No CAA record', severity: 'medium', detail: '' },
				],
			},
		});

		const result = compareBaseline(noCriticals, { max_critical_findings: 0 });

		expect(result.passed).toBe(true);
		expect(result.inconclusiveRules).toEqual([]);
		expect(result.checkedRules).toBe(1);
		// Control: the same scan DOES breach a high cap, so the fixture is not
		// vacuously clean.
		expect(compareBaseline(noCriticals, { max_high_findings: 0 }).passed).toBe(false);
	});

	it('still FAILS a genuinely-measured control breach — the inconclusive path must not swallow real failures', async () => {
		const { compareBaseline } = await import('../src/tools/compare-baseline');
		// Checks DID run. SPF is genuinely absent and a critical finding is
		// genuinely present. This is a real policy breach and must stay one.
		const measuredButFailing = createMockScan({
			domain: 'measured-and-failing.example',
			score: {
				...createMockScan().score,
				overall: 30,
				grade: 'F',
				findings: [{ category: 'ssl', title: 'Cert expired', severity: 'critical', detail: '' }],
			},
			checks: [
				{ category: 'spf', passed: false, score: 0, findings: [] },
				{ category: 'dmarc', passed: false, score: 10, findings: [] },
			],
		});

		const result = compareBaseline(measuredButFailing, { require_spf: true, require_dmarc_enforce: true, max_critical_findings: 0 });

		expect(result.passed).toBe(false);
		expect(result.inconclusiveRules).toEqual([]);
		expect(result.checkedRules).toBe(3);
		expect(result.violations.map((v) => v.rule).sort()).toEqual(['max_critical_findings', 'require_dmarc_enforce', 'require_spf']);
	});

	it('evaluates control rules normally when checks ran but SCORING failed (the unscored shape)', async () => {
		const { compareBaseline } = await import('../src/tools/compare-baseline');
		// buildUnscoredResult keeps `checks: checkResults` — the checks genuinely
		// ran, only the scoring bundle failed. The control rules ARE measurable
		// here; only grade/score are not. Collapsing "no score" into "nothing was
		// measured" would throw away a real, usable SPF result.
		const unscored = createMockScan({
			domain: 'unscored.example',
			score: { ...createMockScan().score, overall: null, grade: null, findings: [] },
			checks: [{ category: 'spf', passed: true, score: 90, findings: [] }],
		});

		const result = compareBaseline(unscored, { score: 50, require_spf: true });

		expect(result.inconclusiveRules).toEqual(['score']);
		// require_spf was genuinely evaluated, and genuinely met.
		expect(result.checkedRules).toBe(1);
		expect(result.violations).toHaveLength(0);
		// Still no overall verdict: the score rule the caller asked for is unanswerable.
		expect(result.passed).toBeNull();
	});

	it('still passes and still fails a graded scan exactly as before', async () => {
		const { compareBaseline } = await import('../src/tools/compare-baseline');
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const gradedScan = (overall: number, grade: string): any => ({
			domain: 'measured.example',
			score: { overall, grade, categoryScores: {}, findings: [], summary: 'ok' },
			checks: [],
			maturity: { stage: 2, label: 'Baseline', description: 'x', nextStep: null },
			context: { profile: 'mail_enabled', signals: [] },
			cached: false,
			timestamp: '2026-07-26T00:00:00.000Z',
		});

		expect(compareBaseline(gradedScan(90, 'A'), { score: 50 }).passed).toBe(true);
		const failed = compareBaseline(gradedScan(30, 'F'), { score: 50 });
		expect(failed.passed).toBe(false);
		expect(failed.violations.map((v) => v.rule)).toContain('score');
		expect(failed.inconclusiveRules).toEqual([]);
	});
});

/**
 * Task 6b: a total outage — every attempted check errors out — previously read
 * `scanMeasured = isMeasured(scan.checks)` as `true` (checks.length > 0), so
 * `categoryPassed`'s `check?.passed ?? false` turned each transient
 * `checkStatus: 'error'` check into a genuine "did not pass" and manufactured
 * confident violations ("SPF is required but check did not pass",
 * "N critical findings exceed maximum of 0" from a findings array assembled
 * entirely from `check error` artifacts) for a domain nobody actually
 * measured. `hasCompletedEvidence` must read this the same way as zero checks:
 * every `scanMeasured`-gated rule becomes inconclusive, never evaluated.
 */
describe('compareBaseline: a total outage (all checks attempted, none completed) is honestly inconclusive', () => {
	it('treats all-transient like never-ran for every scanMeasured-gated rule', async () => {
		const { compareBaseline } = await import('../src/tools/compare-baseline');
		const { SCAN_CATEGORIES } = await import('../src/tools/scan-domain');
		const { buildCheckResult, createFinding } = await import('@blackveil/dns-checks/scoring');

		// Every attempted check errored out — a total outage, NOT the zero-check
		// (NXDOMAIN/broken-zone) case: there IS a CheckResult per category, it just
		// never completed. Mirrors the buildDnsErrorResult/safeCheck shape exactly
		// (see map-compliance.spec.ts's identical fixture pattern).
		const allTransient = SCAN_CATEGORIES.map((c) => ({
			...buildCheckResult(c, [createFinding(c, `${c} check error`, 'high', 'Check failed: DNS query failed')]),
			score: 0,
			passed: false,
			checkStatus: 'error' as const,
			partial: true,
		}));
		// Non-vacuity guard: prove check data actually existed before asserting on it.
		expect(allTransient.length).toBeGreaterThan(10);

		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const allTransientScan: any = {
			domain: 'total-outage.example',
			score: { overall: null, grade: null, categoryScores: {}, findings: [], summary: 'transient outage' },
			checks: allTransient,
			maturity: { stage: 0, label: 'Unknown', description: 'x', nextStep: null },
			context: { profile: 'mail_enabled', signals: [] },
			cached: false,
			timestamp: '2026-07-26T00:00:00.000Z',
		};

		const result = compareBaseline(allTransientScan, {
			require_spf: true,
			require_dmarc_enforce: true,
			max_critical_findings: 0,
		});

		expect(result.passed).toBeNull();
		expect(result.violations).toHaveLength(0);
		expect(result.checkedRules).toBe(0);
		expect(result.inconclusiveRules).toEqual(['require_dmarc_enforce', 'require_spf', 'max_critical_findings']);
	});

	it('keeps evaluating normally when at least one check completed (guard — no over-abstain)', async () => {
		const { compareBaseline } = await import('../src/tools/compare-baseline');
		const { SCAN_CATEGORIES } = await import('../src/tools/scan-domain');
		const { buildCheckResult, createFinding } = await import('@blackveil/dns-checks/scoring');

		// 1 of N checks completed (spf passes); the rest are transient. This must
		// evaluate exactly as it did before this change — `hasCompletedEvidence`
		// must not require EVERY check to complete.
		const mostlyTransient = SCAN_CATEGORIES.map((c) => {
			if (c === 'spf') {
				return { ...buildCheckResult('spf', []), score: 90, passed: true };
			}
			return {
				...buildCheckResult(c, [createFinding(c, `${c} check error`, 'high', 'Check failed: DNS query failed')]),
				score: 0,
				passed: false,
				checkStatus: 'error' as const,
				partial: true,
			};
		});
		expect(mostlyTransient.length).toBeGreaterThan(10);

		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const scan: any = {
			domain: 'partial-outage.example',
			score: { overall: null, grade: null, categoryScores: {}, findings: [], summary: 'partial outage' },
			checks: mostlyTransient,
			maturity: { stage: 0, label: 'Unknown', description: 'x', nextStep: null },
			context: { profile: 'mail_enabled', signals: [] },
			cached: false,
			timestamp: '2026-07-26T00:00:00.000Z',
		};

		const result = compareBaseline(scan, { require_spf: true });
		expect(result.inconclusiveRules).toEqual([]);
		expect(result.checkedRules).toBe(1);
		expect(result.violations).toHaveLength(0);
		expect(result.passed).toBe(true);
	});
});

/**
 * #706: the enforcement surface repeat of #705.
 *
 * `categoryPassed` read `CheckResult.passed`, which records whether a check
 * PENALIZED the domain — not whether the control exists. `require_dnssec`,
 * `require_caa` and `require_mta_sts` all leave `passed: true` on absence (a
 * graded finding, deliberately no `missingControl`, so the category still scores
 * 60), which meant a customer could wire `require_dnssec: true` into a CI gate
 * and have every unsigned domain in their portfolio PASS it — while the same
 * scan raised a high-severity "DNSSEC not enabled" finding.
 *
 * The shapes below are the ones MEASURED in production on 2026-08-19 (#705:
 * davidhf.com `check_dnssec` and `check_caa`), not shapes invented in this
 * tool's own vocabulary.
 */
describe('compare_baseline does not pass a control rule whose record was never published', () => {
	/** A check that COMPLETED, was not penalized, but observed no published record. */
	function absentButUnpenalized(category: string, title: string, severity: string, controlPresent?: boolean): CheckResult {
		return {
			category,
			passed: true,
			score: 60,
			controlPresent,
			recordPresent: false,
			findings: [{ category, title, severity, detail: '' }],
		} as CheckResult;
	}

	/**
	 * The registry-signed counter-fixture — `check-dnssec.ts` documents this exact
	 * `recordPresent: false` + `controlPresent: true` pair as a ccTLD/registry-signed
	 * zone that validates without publishing a DNSKEY/DS of its own. It IS protected.
	 */
	function absentRecordsButControlActive(category: string): CheckResult {
		return {
			category,
			passed: true,
			score: 85,
			controlPresent: true,
			recordPresent: false,
			// `info`, not `medium`: since #726 a medium-or-worse finding is itself
			// disqualifying, so grading THAT here would test the severity floor instead of
			// the recordPresent-rebuttal clause this fixture exists for. A note that the
			// zone's signing is registry-managed is informational anyway.
			findings: [{ category, title: 'DNSSEC is registry-managed', severity: 'info', detail: '' }],
		} as CheckResult;
	}

	function scanWith(domain: string, extraChecks: CheckResult[]): ScanDomainResult {
		return createMockScan({
			domain,
			checks: [{ category: 'spf', passed: true, score: 90, findings: [] }, ...extraChecks],
		});
	}

	it('FLAGS require_dnssec on an unsigned zone (recordPresent false, no controlPresent rebuttal)', async () => {
		const { compareBaseline } = await import('../src/tools/compare-baseline');
		const scan = scanWith('unsigned.example', [absentButUnpenalized('dnssec', 'DNSSEC not enabled', 'high')]);

		// Non-vacuity: this is precisely the shape that used to read as a PASS.
		const dnssec = scan.checks.find((c) => c.category === 'dnssec')!;
		expect(dnssec.passed).toBe(true);
		expect(dnssec.score).toBe(60);
		expect(dnssec.recordPresent).toBe(false);
		expect(dnssec.controlPresent).toBeUndefined();

		const result = compareBaseline(scan, { require_dnssec: true });

		expect(result.violations.map((v) => v.rule)).toContain('require_dnssec');
		expect(result.passed).toBe(false);
		expect(result.checkedRules).toBe(1);
		expect(result.inconclusiveRules).toEqual([]);
	});

	it('FLAGS require_caa when the CAA check observed no published record', async () => {
		const { compareBaseline } = await import('../src/tools/compare-baseline');
		const scan = scanWith('no-caa.example', [absentButUnpenalized('caa', 'No CAA records', 'medium', false)]);

		const result = compareBaseline(scan, { require_caa: true });

		expect(result.violations.map((v) => v.rule)).toContain('require_caa');
		expect(result.passed).toBe(false);
		expect(result.checkedRules).toBe(1);
	});

	it('FLAGS require_mta_sts when the MTA-STS check observed no published policy (mail-enabled domain)', async () => {
		const { compareBaseline } = await import('../src/tools/compare-baseline');
		const scan = scanWith('no-mta-sts.example', [
			absentButUnpenalized('mta_sts', 'No MTA-STS or TLS-RPT records found', 'low', false),
		]);

		const result = compareBaseline(scan, { require_mta_sts: true });

		expect(result.violations.map((v) => v.rule)).toContain('require_mta_sts');
		expect(result.passed).toBe(false);
		expect(result.checkedRules).toBe(1);
	});

	/**
	 * The load-bearing rebuttal. Without it the fix trades the false PASS for a
	 * false FAIL on a zone that is genuinely, cryptographically protected.
	 */
	it('still PASSES require_dnssec for a registry-signed zone (recordPresent false + controlPresent true)', async () => {
		const { compareBaseline } = await import('../src/tools/compare-baseline');
		const scan = scanWith('registry-signed.example', [absentRecordsButControlActive('dnssec')]);

		const result = compareBaseline(scan, { require_dnssec: true });

		expect(result.violations).toHaveLength(0);
		expect(result.inconclusiveRules).toEqual([]);
		expect(result.checkedRules).toBe(1);
		expect(result.passed).toBe(true);
	});

	/**
	 * #726 — the severity floor on the ENFORCEMENT surface.
	 *
	 * `require_spf` is backed by `spf`, one of the five checks that never emit
	 * `recordPresent`, so both presence clauses are structurally inert and the rule
	 * degraded back to bare `passed` — the #706 defect, re-opened for half the
	 * categories a `require_*` rule can name. A CI gate is exactly where that is worst:
	 * it prints a green build.
	 */
	it('VIOLATES require_spf when the SPF check passes but the same scan flags it at medium', async () => {
		const { compareBaseline } = await import('../src/tools/compare-baseline');
		const scan = createMockScan({
			domain: 'deficient-spf.example',
			checks: [
				{
					category: 'spf',
					passed: true,
					score: 85,
					findings: [{ category: 'spf', title: 'SPF trust surface: 4 shared platforms', severity: 'medium', detail: '' }],
				} as CheckResult,
			],
		});

		const result = compareBaseline(scan, { require_spf: true });

		expect(result.violations.map((v) => v.rule)).toContain('require_spf');
		expect(result.passed).toBe(false);
		expect(result.checkedRules).toBe(1);
		// The reason must be attributed honestly: this domain's SPF plainly IS in
		// effect, and telling a gate customer otherwise sends them hunting for a record
		// they already publish.
		const violation = result.violations.find((v) => v.rule === 'require_spf')!;
		expect(violation.message).toContain('medium severity or worse');
		expect(violation.message).not.toContain('no evidence');
	});

	it('keeps the absence wording when the control really is absent', async () => {
		const { compareBaseline } = await import('../src/tools/compare-baseline');
		const scan = scanWith('no-dnssec.example', [absentButUnpenalized('dnssec', 'DNSSEC not enabled', 'high', false)]);
		const result = compareBaseline(scan, { require_dnssec: true });
		const violation = result.violations.find((v) => v.rule === 'require_dnssec');
		expect(violation).toBeDefined();
		// `absentButUnpenalized` carries a high finding, so BOTH clauses disqualify here;
		// the deficiency wording legitimately wins. What must never happen is a PASS.
		expect(result.passed).toBe(false);
	});

	it('does NOT violate a require_* rule on an info-downgraded or unmeasured finding', async () => {
		const { compareBaseline } = await import('../src/tools/compare-baseline');

		// Post-processing downgrades DKIM/MTA-STS/BIMI findings to `info` under an SPF
		// noSendPolicy (and email-auth findings on a non-mail domain under an enforcing
		// parent DMARC). The floor must read that FINAL severity, or the fix becomes a
		// false FAIL on the domains those downgrades protect.
		const downgraded = createMockScan({
			domain: 'no-send.example',
			checks: [
				{
					category: 'dkim',
					passed: true,
					score: 100,
					findings: [{ category: 'dkim', title: 'No DKIM records found', severity: 'info', detail: '(expected — no MX records)' }],
				} as CheckResult,
			],
		});
		expect(compareBaseline(downgraded, { require_dkim: true }).violations).toHaveLength(0);

		// "Could not measure" is not evidence the control is unsatisfied.
		const unmeasured = createMockScan({
			domain: 'waf.example',
			checks: [
				{
					category: 'caa',
					passed: true,
					score: 100,
					findings: [
						{ category: 'caa', title: 'CAA lookup inconclusive', severity: 'medium', detail: '', metadata: { inconclusive: true, errorKind: 'dns_error' } },
					],
				} as CheckResult,
			],
		});
		expect(compareBaseline(unmeasured, { require_caa: true }).violations).toHaveLength(0);
	});

	/** A control that IS present and satisfied must keep passing — no regression. */
	it('still PASSES require_dnssec for a zone that publishes a validating DNSKEY/DS', async () => {
		const { compareBaseline } = await import('../src/tools/compare-baseline');
		const scan = scanWith('signed.example', [
			{ category: 'dnssec', passed: true, score: 100, controlPresent: true, recordPresent: true, findings: [] } as CheckResult,
		]);

		const result = compareBaseline(scan, { require_dnssec: true });

		expect(result.violations).toHaveLength(0);
		expect(result.passed).toBe(true);
		expect(result.checkedRules).toBe(1);
	});

	/**
	 * Over-correction guard. `recordPresent: undefined` means "this check does not
	 * report the signal" (spf, dkim, ssl, ns, http_security never set it) or "the
	 * query failed" — neither is evidence of absence.
	 */
	it('still PASSES require_spf when the check does not report the presence signal at all', async () => {
		const { compareBaseline } = await import('../src/tools/compare-baseline');
		const scan = createMockScan({ domain: 'silent-signal.example' });
		expect(scan.checks.every((c) => c.recordPresent === undefined)).toBe(true);

		const result = compareBaseline(scan, { require_spf: true, require_dkim: true });

		expect(result.violations).toHaveLength(0);
		expect(result.passed).toBe(true);
		expect(result.checkedRules).toBe(2);
	});
});

/**
 * #706, applicability leg. A `web_only`/`non_mail` domain legitimately publishes
 * no MTA-STS policy, and the scan's own applicability pass already declares that
 * category N/A. Grading it on presence would newly report a VIOLATION against a
 * domain that accepts no mail — the same defect with the opposite sign.
 *
 * It must not silently PASS either: "the rule cannot be evaluated here" and "the
 * rule passed" are different statements, and a gate consumer keyed on
 * `passed === true` has to be able to tell them apart. The rule therefore lands
 * in the existing not-evaluated channel.
 */
describe('compare_baseline abstains on a category the scan itself declared not applicable', () => {
	function webOnlyScanWithNoMtaSts(): ScanDomainResult {
		return {
			...createMockScan({
				domain: 'web-only.example',
				checks: [
					{ category: 'spf', passed: true, score: 90, findings: [] },
					{
						category: 'mta_sts',
						passed: true,
						score: 60,
						controlPresent: false,
						recordPresent: false,
						findings: [{ category: 'mta_sts', title: 'No MTA-STS or TLS-RPT records found', severity: 'low', detail: '' }],
					},
				] as CheckResult[],
			}),
			context: { profile: 'web_only', signals: [] },
		} as unknown as ScanDomainResult;
	}

	it('does not turn require_mta_sts into a violation on a web_only domain', async () => {
		const { compareBaseline } = await import('../src/tools/compare-baseline');
		const result = compareBaseline(webOnlyScanWithNoMtaSts(), { require_mta_sts: true });

		expect(result.violations.map((v) => v.rule)).not.toContain('require_mta_sts');
		expect(result.notApplicableRules).toEqual(['require_mta_sts']);
		// Out of the evaluated denominator, not sitting in it as a silent pass.
		expect(result.checkedRules).toBe(0);
	});

	it('reports the inapplicable rule as INCONCLUSIVE, never as a PASS', async () => {
		const { compareBaseline, formatBaselineResult } = await import('../src/tools/compare-baseline');
		const result = compareBaseline(webOnlyScanWithNoMtaSts(), { require_mta_sts: true });

		// The distinction a gate consumer depends on: `null`, never `true`.
		expect(result.passed).toBeNull();
		expect(result.passed).not.toBe(true);
		expect(result.inconclusiveRules).toContain('require_mta_sts');

		const full = formatBaselineResult(result, 'full');
		expect(full).toContain('INCONCLUSIVE');
		expect(full).not.toContain('**Result:** PASS');
		expect(full).not.toContain('All baseline rules met.');
		// And it must be attributed to APPLICABILITY, not to a missing measurement —
		// this scan measured MTA-STS perfectly well; the control just does not apply.
		expect(full).toContain('does not apply to this domain');
		expect(full).not.toContain('**Not evaluated (no measurement available for this scan):** require_mta_sts');

		const compact = formatBaselineResult(result, 'compact');
		expect(compact).toContain('INCONCLUSIVE');
		expect(compact).toContain('does not apply to this domain');
	});

	it('keeps grading an applicable category on the same scan (guard — no blanket abstention)', async () => {
		const { compareBaseline } = await import('../src/tools/compare-baseline');
		// `spf` is NOT in the mail-only N/A set for this fixture (it publishes a
		// real record and passes), so the profile must not disarm every rule.
		const result = compareBaseline(webOnlyScanWithNoMtaSts(), { require_spf: true });

		expect(result.checkedRules).toBe(1);
		expect(result.notApplicableRules).toEqual([]);
		expect(result.passed).toBe(true);
	});
});

describe('formatBaselineResult', () => {
	it('compact mode uses terse violation lines without headings', async () => {
		const { formatBaselineResult } = await import('../src/tools/compare-baseline');
		const result = {
			domain: 'example.com',
			passed: false,
			violations: [
				{ rule: 'grade', message: 'Grade F is below minimum B', expected: 'B', actual: 'F' },
				{ rule: 'require_spf', message: 'SPF not detected', expected: 'present', actual: 'missing' },
			],
			inconclusiveRules: [],
			notApplicableRules: [],
			checkedRules: 5,
			scoringProfile: 'mail_enabled',
			timestamp: '2026-01-01T00:00:00Z',
		};
		const compact = formatBaselineResult(result, 'compact');
		const full = formatBaselineResult(result, 'full');
		expect(compact.length).toBeLessThan(full.length);
		expect(compact).toContain('FAIL');
		expect(compact).toContain('2/5 violated');
		expect(compact).toContain('expected B, got F');
		expect(compact).not.toContain('##');
		expect(compact).not.toContain('### Violations');
	});

	it('renders the inconclusive verdict in prose rather than PASS or FAIL', async () => {
		const { compareBaseline, formatBaselineResult } = await import('../src/tools/compare-baseline');
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const ungradedScan: any = {
			domain: 'never-measured.example',
			score: { overall: null, grade: null, categoryScores: {}, findings: [], summary: 'does not resolve' },
			checks: [],
			maturity: { stage: 0, label: 'Does not resolve', description: 'x', nextStep: null },
			context: { profile: 'mail_enabled', signals: [] },
			cached: false,
			timestamp: '2026-07-26T00:00:00.000Z',
		};
		const text = formatBaselineResult(compareBaseline(ungradedScan, { score: 50 }), 'full');
		expect(text).toContain('INCONCLUSIVE');
		expect(text).not.toContain('**Result:** PASS');
		expect(text).not.toContain('**Result:** FAIL');
		// Names WHICH rule went unevaluated, and never claims the rules were met —
		// "All baseline rules met." on a domain that was never resolved is the same
		// confident-output-from-nothing this change removes.
		expect(text).toContain('**Not evaluated (no measurement available for this scan):** score');
		expect(text).not.toContain('All baseline rules met.');
	});

	it('renders the inconclusive verdict in compact mode too — the format interactive clients receive', async () => {
		const { compareBaseline, formatBaselineResult } = await import('../src/tools/compare-baseline');
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const ungradedScan: any = {
			domain: 'never-measured.example',
			score: { overall: null, grade: null, categoryScores: {}, findings: [], summary: 'does not resolve' },
			checks: [],
			maturity: { stage: 0, label: 'Does not resolve', description: 'x', nextStep: null },
			context: { profile: 'mail_enabled', signals: [] },
			cached: false,
			timestamp: '2026-07-26T00:00:00.000Z',
		};
		const compact = formatBaselineResult(compareBaseline(ungradedScan, { score: 50, grade: 'B' }), 'compact');

		expect(compact).toContain('INCONCLUSIVE');
		expect(compact).not.toContain('PASS');
		expect(compact).not.toContain('FAIL');
		expect(compact).toContain('not evaluated (no measurement available): grade, score');
	});

	it('never renders a control-rule breach for a scan that ran zero checks', async () => {
		const { compareBaseline, formatBaselineResult } = await import('../src/tools/compare-baseline');
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const unmeasuredScan: any = {
			domain: 'never-measured.example',
			score: { overall: null, grade: null, categoryScores: {}, findings: [], summary: 'does not resolve' },
			checks: [],
			maturity: { stage: 0, label: 'Does not resolve', description: 'x', nextStep: null },
			context: { profile: 'mail_enabled', signals: [] },
			cached: false,
			timestamp: '2026-07-26T00:00:00.000Z',
		};
		const text = formatBaselineResult(
			compareBaseline(unmeasuredScan, { require_spf: true, require_dmarc_enforce: true, max_critical_findings: 0 }),
			'full',
		);

		expect(text).toContain('INCONCLUSIVE');
		expect(text).not.toContain('**Result:** FAIL');
		// The pre-fix prose asserted a check outcome that never happened.
		expect(text).not.toContain('did not pass');
		expect(text).not.toContain('### Violations');
		expect(text).toContain('**Rules checked:** 0');
	});

	/**
	 * Minor-1 wording: `passed: null` also fires for the UNSCORED shape, where the
	 * domain resolved and checks ran but the scoring bundle failed — a
	 * scanner-side degradation. Blaming the customer's domain ("domain was not
	 * measured") misattributes that; scan_domain's own nextStep for the same path
	 * says "the scoring service is degraded — check the deployment."
	 */
	it('attributes the abstention to the missing measurement, not to the customer domain', async () => {
		const { compareBaseline, formatBaselineResult } = await import('../src/tools/compare-baseline');
		const unscored = createMockScan({
			domain: 'scoring-degraded.example',
			score: { ...createMockScan().score, overall: null, grade: null, findings: [] },
			checks: [{ category: 'spf', passed: true, score: 90, findings: [] }],
		});
		const result = compareBaseline(unscored, { score: 50, require_spf: true });

		for (const text of [formatBaselineResult(result, 'full'), formatBaselineResult(result, 'compact')]) {
			expect(text).toContain('INCONCLUSIVE');
			expect(text).toContain('no measurement available');
			// The domain resolved and its SPF check ran — saying otherwise is false.
			expect(text).not.toContain('domain not measured');
			expect(text).not.toContain('domain was not measured');
			// Second guard against the over-reaching fix (abstain whenever the scan is
			// ungraded): that would list require_spf here, discarding a real SPF result.
			// Cheap, and at a different layer from the object-level assertion above.
			expect(text).not.toContain('require_spf');
		}
	});
});

/**
 * The sibling defect this change must not repeat: `map_compliance` had its PROSE
 * corrected while its structured payload kept shipping a fabricated verdict to
 * every machine consumer. `compare_baseline` exists to be read by CI, so the
 * inconclusive state has to survive the serialization boundary — `undefined`
 * would be silently dropped by `JSON.stringify`, leaving a CI gate unable to
 * distinguish "not measured" from "field absent".
 */
describe('compare_baseline structured payload', () => {
	it('carries the inconclusive verdict into structuredContent and the STRUCTURED_RESULT comment', async () => {
		const { compareBaseline, formatBaselineResult } = await import('../src/tools/compare-baseline');
		const { buildToolResult } = await import('../src/handlers/tool-formatters');
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const ungradedScan: any = {
			domain: 'never-measured.example',
			score: { overall: null, grade: null, categoryScores: {}, findings: [], summary: 'does not resolve' },
			checks: [],
			maturity: { stage: 0, label: 'Does not resolve', description: 'x', nextStep: null },
			context: { profile: 'mail_enabled', signals: [] },
			cached: false,
			timestamp: '2026-07-26T00:00:00.000Z',
		};

		const result = compareBaseline(ungradedScan, { score: 50, grade: 'B' });
		const wire = buildToolResult(formatBaselineResult(result, 'full'), result, 'full');

		// MCP-standard machine channel.
		expect(wire.structuredContent?.passed).toBeNull();
		expect(wire.structuredContent?.inconclusiveRules).toEqual(['grade', 'score']);

		// Legacy comment channel — assert on the SERIALIZED text, because an
		// `undefined` verdict would vanish here while still reading as "not true"
		// in memory.
		const comment = wire.content.find((c) => c.text.includes('STRUCTURED_RESULT'));
		expect(comment).toBeDefined();
		expect(comment?.text).toContain('"passed":null');
		expect(comment?.text).toContain('"inconclusiveRules":["grade","score"]');

		// Control — a measured scan still serializes a real boolean verdict.
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const gradedScan: any = { ...ungradedScan, score: { ...ungradedScan.score, overall: 90, grade: 'A' } };
		const gradedWire = buildToolResult('', compareBaseline(gradedScan, { score: 50, grade: 'B' }), 'full');
		expect(gradedWire.structuredContent?.passed).toBe(true);
		expect(gradedWire.structuredContent?.inconclusiveRules).toEqual([]);
	});
});

describe('compare_baseline baseline-type validation', () => {
	it('rejects a string baseline with a message that redirects to analyze_drift', async () => {
		const { validateToolArgs } = await import('../src/handlers/tool-args');
		let message = '';
		try {
			validateToolArgs('compare_baseline', { domain: 'example.com', baseline: 'cached' });
		} catch (err) {
			message = err instanceof Error ? err.message : String(err);
		}
		// Allowlisted prefix preserved (sanitizeErrorMessage requires 'Invalid ').
		expect(message).toMatch(/^Invalid baseline:/);
		// Points the confused caller at the right tool.
		expect(message).toContain('analyze_drift');
		// Still names this as a policy/requirements object, not a prior scan.
		expect(message.toLowerCase()).toContain('object');
	});

	it('still accepts a valid policy-baseline object', async () => {
		const { validateToolArgs } = await import('../src/handlers/tool-args');
		const validated = validateToolArgs('compare_baseline', {
			domain: 'example.com',
			baseline: { grade: 'B', require_spf: true, max_critical_findings: 0 },
		});
		expect((validated.baseline as Record<string, unknown>).grade).toBe('B');
		expect((validated.baseline as Record<string, unknown>).require_spf).toBe(true);
	});

	it('still surfaces field-level errors inside the baseline object', async () => {
		const { validateToolArgs } = await import('../src/handlers/tool-args');
		let message = '';
		try {
			validateToolArgs('compare_baseline', { domain: 'example.com', baseline: { score: 'not-a-number' } });
		} catch (err) {
			message = err instanceof Error ? err.message : String(err);
		}
		// The object-level custom message must NOT clobber per-field validation.
		expect(message).not.toContain('analyze_drift');
		expect(message).toContain('score');
	});
});

describe('compare_baseline dispatch', () => {
	it('is listed by handleToolsList', async () => {
		const { handleToolsList } = await import('../src/handlers/tools');
		const list = handleToolsList();
		const tool = list.tools.find((value) => value.name === 'compare_baseline');
		expect(tool).toBeDefined();
	});

	it('is handled by handleToolsCall', async () => {
		mockAllChecks();
		const { handleToolsCall } = await import('../src/handlers/tools');
		const result = await handleToolsCall({
			name: 'compare_baseline',
			arguments: { domain: 'example.com', baseline: { grade: 'B', require_dmarc_enforce: true, max_critical_findings: 0 } },
		});

		expect(result.isError).toBeUndefined();
		expect(result.content).toHaveLength(2);
		expect(result.content[0].text).toContain('Baseline Comparison: example.com');
		expect(result.content[0].text).toContain('Result:');
	});
});
