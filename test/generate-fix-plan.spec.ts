// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, afterEach } from 'vitest';
import { vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

/**
 * Mock fetch to return different responses based on the queried domain name.
 * Covers the parallel checks that scan_domain runs.
 */
function mockScanResponses(options: { hasSpf?: boolean; hasDmarc?: boolean; hasDkim?: boolean } = {}) {
	const { hasSpf = true, hasDmarc = true, hasDkim = true } = options;

	globalThis.fetch = vi.fn().mockImplementation((url: string | URL | Request) => {
		const urlStr = typeof url === 'string' ? url : url instanceof URL ? url.toString() : url.url;
		const u = new URL(urlStr);

		// DoH requests
		if (u.hostname.includes('cloudflare-dns') || u.hostname.includes('dns.google')) {
			const name = u.searchParams.get('name') ?? '';
			const type = Number(u.searchParams.get('type') ?? '0');

			// TXT records
			if (type === 16) {
				if (name === 'example.com') {
					const records: Array<{ name: string; type: number; TTL: number; data: string }> = [];
					if (hasSpf) records.push({ name, type: 16, TTL: 300, data: '"v=spf1 include:_spf.google.com -all"' });
					return Promise.resolve(createDohResponse([{ name, type }], records));
				}
				if (name === '_dmarc.example.com') {
					const records: Array<{ name: string; type: number; TTL: number; data: string }> = [];
					if (hasDmarc) records.push({ name, type: 16, TTL: 300, data: '"v=DMARC1; p=none; rua=mailto:dmarc@example.com"' });
					return Promise.resolve(createDohResponse([{ name, type }], records));
				}
				if (name.includes('_domainkey')) {
					const records: Array<{ name: string; type: number; TTL: number; data: string }> = [];
					if (hasDkim) records.push({ name, type: 16, TTL: 300, data: '"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"' });
					return Promise.resolve(createDohResponse([{ name, type }], records));
				}
				if (name === '_mta-sts.example.com') {
					return Promise.resolve(createDohResponse([{ name, type }], []));
				}
				if (name === '_smtp._tls.example.com') {
					return Promise.resolve(createDohResponse([{ name, type }], []));
				}
				// Default: empty TXT
				return Promise.resolve(createDohResponse([{ name, type }], []));
			}
			// MX records
			if (type === 15) {
				return Promise.resolve(createDohResponse([{ name, type }], [{ name, type: 15, TTL: 300, data: '10 mail.example.com.' }]));
			}
			// NS records
			if (type === 2) {
				return Promise.resolve(
					createDohResponse(
						[{ name, type }],
						[
							{ name, type: 2, TTL: 300, data: 'ns1.example.com.' },
							{ name, type: 2, TTL: 300, data: 'ns2.example.com.' },
						],
					),
				);
			}
			// A records
			if (type === 1) {
				return Promise.resolve(createDohResponse([{ name, type }], [{ name, type: 1, TTL: 300, data: '93.184.216.34' }]));
			}
			// AAAA
			if (type === 28) {
				return Promise.resolve(createDohResponse([{ name, type }], []));
			}
			// CNAME
			if (type === 5) {
				return Promise.resolve(createDohResponse([{ name, type }], []));
			}
			// DNSKEY
			if (type === 48) {
				return Promise.resolve(createDohResponse([{ name, type }], []));
			}
			// DS
			if (type === 43) {
				return Promise.resolve(createDohResponse([{ name, type }], []));
			}
			// CAA
			if (type === 257) {
				return Promise.resolve(createDohResponse([{ name, type }], []));
			}
			// TLSA
			if (type === 52) {
				return Promise.resolve(createDohResponse([{ name, type }], []));
			}
			// SOA
			if (type === 6) {
				return Promise.resolve(
					createDohResponse(
						[{ name, type }],
						[{ name, type: 6, TTL: 300, data: 'ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400' }],
					),
				);
			}
			// SRV
			if (type === 33) {
				return Promise.resolve(createDohResponse([{ name, type }], []));
			}
			// Default: empty
			return Promise.resolve(createDohResponse([{ name, type }], []));
		}

		// HTTPS fetch (SSL check, MTA-STS policy, HTTP security headers)
		if (urlStr.startsWith('https://')) {
			return Promise.resolve({
				ok: true,
				status: 200,
				headers: new Headers({
					'content-type': 'text/plain',
				}),
				text: () => Promise.resolve(''),
				json: () => Promise.resolve({}),
			} as unknown as Response);
		}

		return Promise.resolve(createDohResponse([], []));
	});
}

describe('generateFixPlan', () => {
	async function run(domain = 'example.com', options?: { hasSpf?: boolean; hasDmarc?: boolean; hasDkim?: boolean }) {
		mockScanResponses(options);
		const { generateFixPlan } = await import('../src/tools/generate-fix-plan');
		return generateFixPlan(domain);
	}

	it('returns a fix plan with domain and score', async () => {
		const plan = await run();
		expect(plan.domain).toBe('example.com');
		expect(plan.score).toBeGreaterThanOrEqual(0);
		expect(plan.score).toBeLessThanOrEqual(100);
		expect(plan.grade).toBeDefined();
		expect(plan.maturityStage).toBeGreaterThanOrEqual(0);
		expect(plan.maturityStage).toBeLessThanOrEqual(4);
		expect(plan.totalActions).toBe(plan.actions.length);
	});

	it('produces more actions when email auth is missing', async () => {
		const planWithAuth = await run('example.com', { hasSpf: true, hasDmarc: true, hasDkim: true });
		const planWithoutAuth = await run('example.com', { hasSpf: false, hasDmarc: false, hasDkim: false });
		expect(planWithoutAuth.totalActions).toBeGreaterThanOrEqual(planWithAuth.totalActions);
	});

	it('sorts actions by priority descending', async () => {
		const plan = await run('example.com', { hasSpf: false, hasDmarc: false });
		if (plan.actions.length > 1) {
			for (let i = 1; i < plan.actions.length; i++) {
				expect(plan.actions[i - 1].priority).toBeGreaterThanOrEqual(plan.actions[i].priority);
			}
		}
	});

	it('actions have required fields', async () => {
		const plan = await run('example.com', { hasSpf: false });
		for (const action of plan.actions) {
			expect(action.category).toBeDefined();
			expect(action.action).toBeDefined();
			expect(action.severity).toBeDefined();
			expect(['low', 'medium', 'high']).toContain(action.effort);
			expect(['critical', 'high', 'medium', 'low']).toContain(action.impact);
			expect(action.dependencies).toBeInstanceOf(Array);
			expect(action.findingTitle).toBeDefined();
		}
	});
});

describe('formatFixPlan', () => {
	it('formats a plan as readable text', async () => {
		mockScanResponses({ hasSpf: false, hasDmarc: false });
		const { generateFixPlan, formatFixPlan } = await import('../src/tools/generate-fix-plan');
		const plan = await generateFixPlan('example.com');
		const text = formatFixPlan(plan);
		expect(text).toContain('Fix Plan: example.com');
		expect(text).toContain('Score:');
		expect(text).toContain('action');
	});

	it('shows "no actionable findings" for clean domain', async () => {
		const { formatFixPlan } = await import('../src/tools/generate-fix-plan');
		const text = formatFixPlan({
			domain: 'clean.com',
			score: 95,
			grade: 'A+',
			maturityStage: 4,
			totalActions: 0,
			actions: [],
			assessed: true,
			caveat: null,
			transientCategories: [],
		});
		expect(text).toContain('No actionable findings');
		expect(text).toContain('posture is strong');
	});

	it('compact mode uses one-liners and caps at 5 actions', async () => {
		const { formatFixPlan } = await import('../src/tools/generate-fix-plan');
		const actions = Array.from({ length: 7 }, (_, i) => ({
			category: 'spf' as const,
			severity: 'high' as const,
			action: `Action ${i + 1}`,
			effort: 'low' as const,
			impact: 'high' as const,
			dependencies: ['dep'],
		}));
		const plan = {
			domain: 'test.com',
			score: 30,
			grade: 'F',
			maturityStage: 0,
			totalActions: 7,
			actions,
			assessed: true,
			caveat: null,
			transientCategories: [],
		};
		const compact = formatFixPlan(plan, 'compact');
		const full = formatFixPlan(plan, 'full');
		expect(compact.length).toBeLessThan(full.length);
		expect(compact).toContain('Fix Plan: test.com');
		expect(compact).toContain('7 actions');
		expect(compact).toContain('Action 5');
		expect(compact).not.toContain('Action 6');
		expect(compact).toContain('... and 2 more');
		expect(compact).not.toContain('##');
		expect(compact).not.toContain('Dependencies');
	});
});

/**
 * A fix plan for a domain that was never measured has zero actions — and the
 * formatter answered that with "No actionable findings. Domain security posture
 * is strong." plus "Maturity Stage: 0/4". Both are fabricated: nothing was
 * looked at, so there is neither a clean bill of health nor a stage-0 posture.
 * `maturityStage: 0` also rides the structured payload, where it is a number
 * something will chart.
 */
describe('formatFixPlan — a domain that was never measured', () => {
	async function unmeasuredPlan() {
		const { UNASSESSED_FIX_PLAN_CAVEAT } = await import('../src/tools/generate-fix-plan');
		return {
			domain: 'never-measured.example',
			score: null,
			grade: null,
			maturityStage: null,
			totalActions: 0,
			actions: [],
			assessed: false,
			caveat: UNASSESSED_FIX_PLAN_CAVEAT,
			transientCategories: [],
		};
	}

	it.each(['compact', 'full'] as const)('never reports a clean bill of health for an unassessed domain [%s]', async (format) => {
		const { formatFixPlan } = await import('../src/tools/generate-fix-plan');
		const text = formatFixPlan(await unmeasuredPlan(), format);

		expect(text).toContain('not measured');
		expect(text).not.toContain('null');
		expect(text).not.toContain('posture is strong');
		expect(text).not.toContain('No actionable findings');
		expect(text.toLowerCase()).toMatch(/no checks ran/);
	});

	it('renders the maturity stage as not measured rather than 0/4', async () => {
		const { formatFixPlan } = await import('../src/tools/generate-fix-plan');
		const text = formatFixPlan(await unmeasuredPlan(), 'full');

		expect(text).not.toContain('0/4');
		expect(text).toMatch(/Maturity Stage: not measured/);
	});

	it('still reports a real stage and a clean bill of health for a MEASURED domain (control)', async () => {
		const { formatFixPlan } = await import('../src/tools/generate-fix-plan');
		// Without this control the assertions above would hold under a formatter that
		// abstained unconditionally.
		const text = formatFixPlan(
			{
				domain: 'clean.example',
				score: 95,
				grade: 'A+',
				maturityStage: 4,
				totalActions: 0,
				actions: [],
				assessed: true,
				caveat: null,
				transientCategories: [],
			},
			'full',
		);

		expect(text).toContain('Maturity Stage: 4/4');
		expect(text).toContain('posture is strong');
		expect(text).not.toContain('not measured');
	});

	it('emits the abstention on the machine channel, not only in the prose', async () => {
		const { formatFixPlan } = await import('../src/tools/generate-fix-plan');
		const { buildToolResult } = await import('../src/handlers/tool-formatters');
		const plan = await unmeasuredPlan();
		const result = buildToolResult(formatFixPlan(plan, 'full'), plan, 'full');

		const wire = JSON.stringify(result.structuredContent);
		expect(wire).toContain('"assessed":false');
		expect(wire).toContain('"maturityStage":null');
		expect(wire).not.toContain('"maturityStage":0');

		const comment = result.content.map((c) => c.text).find((t) => t.includes('STRUCTURED_RESULT'));
		expect(comment).toBeDefined();
		expect(comment).toContain('"maturityStage":null');
	});
});

/**
 * Task R4 (residual of the correctness-defect campaign): a transient DNS/network
 * failure for ONE category (e.g. DMARC) must not turn into a remediation action
 * just because OTHER categories completed normally (`assessed: true`). The
 * synthetic "check error" finding `buildDnsErrorResult` attaches carries
 * `metadata.errorKind: 'dns_error'` — that finding is the ABSENCE of a
 * measurement, not a customer gap to fix. Mirrors the equivalent
 * `map_compliance`/`map_csc_products` fix (see `src/tools/map-compliance.ts:272`
 * for the reference implementation this is modeled on).
 */
describe('evaluateFixPlan: a category that failed transiently is not turned into a remediation action', () => {
	async function buildFixtures() {
		const { buildCheckResult, createFinding } = await import('@blackveil/dns-checks/scoring');
		const transientDmarc = {
			...buildCheckResult('dmarc', [
				createFinding('dmarc', 'DMARC check error', 'high', 'Check failed: DNS query failed', { errorKind: 'dns_error' }),
			]),
			score: 0,
			passed: false,
			checkStatus: 'error' as const,
			partial: true,
		};
		// A genuine, non-transient high-severity finding on a DIFFERENT category —
		// this one MUST survive. A wrong implementation that filters on
		// `severity === 'high'` instead of the errorKind marker would drop this too,
		// which is exactly what this fixture is designed to catch.
		const genuineSsl = {
			...buildCheckResult('ssl', [createFinding('ssl', 'Certificate expired', 'high', 'The TLS certificate expired 3 days ago')]),
			score: 0,
			passed: false,
		};
		const cleanDnssec = { ...buildCheckResult('dnssec', []), score: 100, passed: true };
		return { transientDmarc, genuineSsl, cleanDnssec };
	}

	it('the transient "check error" finding never becomes a fix action, but a genuine finding on another category still does (discriminates errorKind from severity)', async () => {
		const { evaluateFixPlan } = await import('../src/tools/generate-fix-plan');
		const { transientDmarc, genuineSsl, cleanDnssec } = await buildFixtures();

		const plan = evaluateFixPlan([transientDmarc, genuineSsl, cleanDnssec], 'partial-outage.example', 40, 'F', 1);

		expect(plan.assessed).toBe(true); // ssl + dnssec completed
		expect(plan.caveat).toBeNull();

		const titles = plan.actions.map((a) => a.findingTitle);
		expect(titles).not.toContain('DMARC check error');
		expect(titles).toContain('Certificate expired');
		expect(plan.actions.some((a) => a.category === 'dmarc')).toBe(false);
		expect(plan.actions.some((a) => a.category === 'ssl')).toBe(true);
	});

	it('the excluded category is represented in transientCategories, not silently dropped', async () => {
		const { evaluateFixPlan } = await import('../src/tools/generate-fix-plan');
		const { transientDmarc, cleanDnssec } = await buildFixtures();
		const { buildCheckResult } = await import('@blackveil/dns-checks/scoring');
		const cleanSsl = { ...buildCheckResult('ssl', []), score: 100, passed: true };

		const plan = evaluateFixPlan([transientDmarc, cleanSsl, cleanDnssec], 'quiet-outage.example', 90, 'A', 4);

		// ssl/dnssec are clean and DMARC's only evidence was transient — zero real
		// actions — but this must NOT read as a clean bill of health: DMARC was
		// never actually measured.
		expect(plan.totalActions).toBe(0);
		expect(plan.assessed).toBe(true);
		expect(plan.transientCategories).toEqual(['dmarc']);
	});

	it('formatFixPlan surfaces the transient category instead of claiming a clean bill of health', async () => {
		const { evaluateFixPlan, formatFixPlan } = await import('../src/tools/generate-fix-plan');
		const { transientDmarc, cleanDnssec } = await buildFixtures();
		const { buildCheckResult } = await import('@blackveil/dns-checks/scoring');
		const cleanSsl = { ...buildCheckResult('ssl', []), score: 100, passed: true };

		const plan = evaluateFixPlan([transientDmarc, cleanSsl, cleanDnssec], 'quiet-outage.example', 90, 'A', 4);

		for (const text of [formatFixPlan(plan, 'full'), formatFixPlan(plan, 'compact')]) {
			expect(text.toLowerCase()).not.toContain('posture is strong');
			expect(text.toLowerCase()).toContain('dmarc');
			expect(text.toLowerCase()).toMatch(/not assess|could not be assessed|transient/);
		}
	});

	/**
	 * F2 (review round 1): `buildFixtures()` above uses `buildDnsErrorResult`-shaped
	 * transients (`metadata.errorKind: 'dns_error'`). But the ORCHESTRATOR's own
	 * transient producer — `safeCheck()` in `src/tools/scan-domain.ts`, which is
	 * what actually runs for any check with no top-level internal DNS-error
	 * handling of its own — sets `checkStatus: 'error' | 'timeout'` and NEVER sets
	 * `errorKind`. A fix gated only on `errorKind` would miss every
	 * safeCheck-produced transient: a `checkStatus: 'timeout'` result would render
	 * BOTH as a fix action ("Fix DMARC: DMARC check timed out — ...") AND, in the
	 * SAME plan, as a `transientCategories` entry — self-contradictory output.
	 * `evaluateFixPlan` gates on `checkStatus` (not `errorKind`) for exactly this
	 * reason; these fixtures are built the way `safeCheck` actually produces
	 * results to prove that gate is what is doing the work, covering both
	 * `checkStatus` values `safeCheck` can produce.
	 */
	describe('a safeCheck-shaped transient (no errorKind metadata) is still excluded — covers both checkStatus values', () => {
		async function safeCheckShapedFixtures() {
			const { buildCheckResult, createFinding } = await import('@blackveil/dns-checks/scoring');
			// No `metadata` argument at all — matches safeCheck()'s own
			// `createFinding(category, title, severity, detail)` call exactly.
			const timedOutDmarc = {
				...buildCheckResult('dmarc', [
					createFinding('dmarc', 'DMARC check timed out', 'low', 'Check did not complete within the 8s limit'),
				]),
				score: 0,
				checkStatus: 'timeout' as const,
				partial: true,
			};
			const erroredMx = {
				...buildCheckResult('mx', [createFinding('mx', 'MX check error', 'high', 'Check failed: DNS query failed')]),
				score: 0,
				passed: false,
				checkStatus: 'error' as const,
				partial: true,
			};
			const cleanSsl = { ...buildCheckResult('ssl', []), score: 100, passed: true };
			return { timedOutDmarc, erroredMx, cleanSsl };
		}

		it('neither the timeout- nor the error-shaped safeCheck transient becomes a fix action, and both are represented in transientCategories', async () => {
			const { evaluateFixPlan } = await import('../src/tools/generate-fix-plan');
			const { timedOutDmarc, erroredMx, cleanSsl } = await safeCheckShapedFixtures();

			const plan = evaluateFixPlan([timedOutDmarc, erroredMx, cleanSsl], 'safecheck-outage.example', 90, 'A', 4);

			expect(plan.assessed).toBe(true); // ssl completed
			expect(plan.totalActions).toBe(0);
			const titles = plan.actions.map((a) => a.findingTitle);
			expect(titles).not.toContain('DMARC check timed out');
			expect(titles).not.toContain('MX check error');
			expect(plan.transientCategories.sort()).toEqual(['dmarc', 'mx']);
		});

		it('formatFixPlan never emits a self-contradictory plan (an action for a category ALSO listed as not-assessed)', async () => {
			const { evaluateFixPlan, formatFixPlan } = await import('../src/tools/generate-fix-plan');
			const { timedOutDmarc, erroredMx, cleanSsl } = await safeCheckShapedFixtures();

			const plan = evaluateFixPlan([timedOutDmarc, erroredMx, cleanSsl], 'safecheck-outage.example', 90, 'A', 4);

			for (const text of [formatFixPlan(plan, 'full'), formatFixPlan(plan, 'compact')]) {
				expect(text).not.toContain('DMARC check timed out');
				expect(text).not.toContain('MX check error');
				expect(text.toLowerCase()).toMatch(/not|transient/);
			}
		});
	});

	/**
	 * Proves the `isDnsErrorFinding` per-finding filter is NOT dead code in this
	 * file (contrast with map-csc-products.ts, where the reviewer's M2a proved
	 * the equivalent per-finding filters ARE dead once the `checkStatus` guard
	 * exists). A check can COMPLETE (`checkStatus` absent/'completed') and still
	 * attach its OWN errorKind-tagged finding for a narrower reason than a full
	 * check failure — e.g. `discover-brand-domains.ts`'s "Brand-domain discovery
	 * could not complete" finding, emitted when every discovery signal failed
	 * but the check itself ran to completion. The `checkStatus`-level filter
	 * (F2's fix) cannot see this state at all — `checkStatus` is never
	 * `'error'`/`'timeout'` here — so only the per-finding filter catches it.
	 */
	it('a COMPLETED check whose own finding is errorKind-tagged still never becomes a fix action (proves the per-finding filter is load-bearing here)', async () => {
		const { evaluateFixPlan } = await import('../src/tools/generate-fix-plan');
		const { buildCheckResult, createFinding } = await import('@blackveil/dns-checks/scoring');

		// checkStatus intentionally ABSENT — the check itself completed normally;
		// only its own finding is errorKind-tagged.
		const inconclusiveBrandDiscovery = buildCheckResult('brand_discovery', [
			createFinding('brand_discovery', 'Brand-domain discovery could not complete', 'high', 'All signals failed', {
				errorKind: 'dns_error',
				missingControl: true,
			}),
		]);
		const cleanSsl = { ...buildCheckResult('ssl', []), score: 100, passed: true };

		const plan = evaluateFixPlan([inconclusiveBrandDiscovery, cleanSsl], 'inconclusive.example', 90, 'A', 4);

		expect(plan.assessed).toBe(true);
		expect(plan.actions.some((a) => a.category === 'brand_discovery')).toBe(false);
		// Not in transientCategories either — its checkStatus was never
		// 'error'/'timeout', so this state is invisible to that channel; it is
		// caught SOLELY by the per-finding errorKind filter.
		expect(plan.transientCategories).not.toContain('brand_discovery');
	});
});
