// SPDX-License-Identifier: BUSL-1.1

import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest';
import { setupFetchMock } from './helpers/dns-mock';
import type { CheckResult, Finding } from '../src/lib/scoring';

/**
 * Integration test for runBrandAuditPipeline when view='csc_complement'.
 *
 * The CSC branch fires AFTER classification and derives its cscComplement payload
 * from the pipeline's classifiedFindings array. This means the discovery stub must
 * return a valid CheckResult with candidate findings whose metadata drives the
 * classifier to the expected bucket distribution.
 *
 * Classification rules used:
 *   - ford.co.uk: signals ['dkim_key_reuse', 'san'], registrar GoDaddy (off-primary).
 *     Rule 2 → isExactBrandPortfolioDomain(ford.co.uk, ford.com)=true → realShadowItClassification
 *     → shadowIt/owned_off_primary_registrar.
 *   - ford.com.au: signals ['dkim_key_reuse', 'ns'], registrar CSC (same family as target).
 *     Rule 2 → isExactBrandPortfolioDomain(ford.com.au, ford.com)=true → isOffPrimaryRegistrar=false
 *     → consolidated/owned_primary.
 */

function makeSummaryFinding(seedDomain: string, candidateCount: number): Finding {
	return {
		category: 'brand_discovery',
		title: `Brand-domain discovery: ${candidateCount} candidate(s) at confidence ≥ 0.5`,
		severity: 'info',
		detail: `Seed=${seedDomain}`,
		metadata: {
			summary: true,
			signals: [],
			signalStatus: {},
			minConfidence: 0.5,
			totalAggregated: candidateCount,
			surfaced: candidateCount,
		},
	};
}

function makeCandidateFinding(domain: string, signals: string[], combinedConfidence: number): Finding {
	return {
		category: 'brand_discovery',
		title: `Discovered candidate: ${domain}`,
		severity: 'low',
		detail: `Found via ${signals.join(', ')}; combined confidence ${combinedConfidence}.`,
		metadata: {
			candidate: domain,
			signals,
			combinedConfidence,
			sharedTxtVerifications: [],
			sharedMxPlatform: null,
			lookalikeScore: 0,
			sources: {},
		},
	};
}

function makeDiscoveryResult(
	seedDomain: string,
	candidates: Array<{ domain: string; signals: string[]; confidence?: number }>,
): CheckResult {
	const findings: Finding[] = [
		makeSummaryFinding(seedDomain, candidates.length),
		...candidates.map((c) => makeCandidateFinding(c.domain, c.signals, c.confidence ?? 0.9)),
	];
	return { category: 'brand_discovery', score: 100, findings };
}

function makeRdapResult(registrar: string): CheckResult {
	return {
		category: 'rdap',
		score: 100,
		findings: [
			{
				category: 'rdap',
				title: 'RDAP registrar',
				severity: 'info',
				detail: registrar,
				metadata: {
					registrar,
					registrarIanaId: null,
					registrarSource: 'rdap',
					registrant: 'Ford Motor Company',
				},
			},
		],
	};
}

/** Sets up a URL-routing fetch mock for the MX (DoH) and HTTP enrichment passes. */
function setupEnrichmentFetchMock(candidates: string[]): void {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
		// Route DoH MX queries for any candidate domain.
		for (const domain of candidates) {
			if (url.includes('dns.google') && url.includes(encodeURIComponent(domain)) && url.includes('type=MX')) {
				return Promise.resolve({
					ok: true,
					status: 200,
					json: () => Promise.resolve({ Answer: [] }),
				});
			}
			// HTTP HEAD via safeFetch (candidate root URL).
			if (url === `https://${domain}/`) {
				return Promise.resolve({
					ok: true,
					status: 200,
					headers: new Headers(),
				});
			}
		}
		// Fallback: safe empty response for any other URL.
		return Promise.resolve({
			ok: true,
			status: 200,
			json: () => Promise.resolve({}),
			headers: new Headers(),
		});
	});
}

describe('runBrandAuditPipeline with view=csc_complement', () => {
	let mockHandle: ReturnType<typeof setupFetchMock>;

	beforeEach(() => {
		mockHandle = setupFetchMock();
	});

	afterEach(() => {
		mockHandle.restore();
	});

	it('emits cscComplement on the result when view=csc_complement', async () => {
		// Set up enrichment fetch mock for the two candidate domains.
		setupEnrichmentFetchMock(['ford.co.uk', 'ford.com.au']);

		const { runBrandAuditPipeline } = await import('../src/lib/brand-audit-pipeline');

		// Discovery stub: returns CheckResult with 2 candidates.
		// ford.co.uk → will classify as shadowIt (GoDaddy, off-primary registrar, strong dkim signal)
		// ford.com.au → will classify as consolidated (CSC, same registrar family, strong dkim signal)
		const discoverBrandDomains = async () =>
			makeDiscoveryResult('ford.com', [
				{ domain: 'ford.co.uk', signals: ['dkim_key_reuse', 'san'] },
				{ domain: 'ford.com.au', signals: ['dkim_key_reuse', 'ns'] },
			]);

		// RDAP stubs: target ford.com → CSC; ford.co.uk → GoDaddy; ford.com.au → CSC.
		const checkRdapLookup = async (domain: string) => {
			if (domain === 'ford.co.uk') return makeRdapResult('GoDaddy.com, LLC');
			return makeRdapResult('CSC Corporate Domains, Inc.');
		};

		const result = await runBrandAuditPipeline(
			'ford.com',
			{ view: 'csc_complement' },
			{ discoverBrandDomains: discoverBrandDomains as never, checkRdapLookup: checkRdapLookup as never },
		);

		const structured = (result as unknown as { cscComplement?: unknown }).cscComplement;
		expect(structured).toBeDefined();

		const { BrandAuditCscSchema } = await import('../src/schemas/brand-audit-csc');
		const parsed = BrandAuditCscSchema.parse(structured);

		expect(parsed.anchor.apex).toBe('ford.com');
		expect(parsed.anchor.managedByCsc).toBe(true);
		expect(parsed.registrarPortfolio.offPortfolioCount).toBe(1);
		expect(parsed.registrarPortfolio.offPortfolioApexes).toEqual(['ford.co.uk']);
		expect(parsed.shadowItHighlights).toHaveLength(1);
		expect(parsed.shadowItHighlights[0].apex).toBe('ford.co.uk');
		expect(parsed.postureSnapshot.stage).toBe('pending');
		expect(parsed.deepScan.stage).toBe('pending');
		expect(parsed.viewVersion).toBe(1);
		expect(parsed.reportId).toMatch(/^csc_rpt_/);
	});

	it('persists csc_complement_fast step when stepStore is provided', async () => {
		setupEnrichmentFetchMock(['ford.co.uk']);

		const { runBrandAuditPipeline } = await import('../src/lib/brand-audit-pipeline');
		const { createMemoryBrandAuditStepStore } = await import('../src/lib/brand-audit-step-store');

		const stepStore = createMemoryBrandAuditStepStore();
		const auditId = 'test-audit-csc';

		const discoverBrandDomains = async () =>
			makeDiscoveryResult('ford.com', [{ domain: 'ford.co.uk', signals: ['dkim_key_reuse', 'san'] }]);
		const checkRdapLookup = async (domain: string) => {
			if (domain === 'ford.co.uk') return makeRdapResult('GoDaddy.com, LLC');
			return makeRdapResult('CSC Corporate Domains, Inc.');
		};

		await runBrandAuditPipeline(
			'ford.com',
			{ view: 'csc_complement', auditId, stepStore },
			{ discoverBrandDomains: discoverBrandDomains as never, checkRdapLookup: checkRdapLookup as never },
		);

		const record = await stepStore.get(auditId, 'ford.com', 'csc_complement_fast');
		expect(record).not.toBeNull();
		expect(record?.status).toBe('completed');
		expect(record?.payload).toBeDefined();

		const { BrandAuditCscSchema } = await import('../src/schemas/brand-audit-csc');
		const parsed = BrandAuditCscSchema.parse(record?.payload);
		expect(parsed.anchor.managedByCsc).toBe(true);
	});

	it('does NOT emit cscComplement when view is omitted (default)', async () => {
		const { runBrandAuditPipeline } = await import('../src/lib/brand-audit-pipeline');

		const discoverBrandDomains = async () =>
			makeDiscoveryResult('ford.com', [{ domain: 'ford.co.uk', signals: ['dkim_key_reuse', 'san'] }]);
		const checkRdapLookup = async () => makeRdapResult('CSC Corporate Domains, Inc.');

		const result = await runBrandAuditPipeline(
			'ford.com',
			{},
			{ discoverBrandDomains: discoverBrandDomains as never, checkRdapLookup: checkRdapLookup as never },
		);

		expect((result as unknown as { cscComplement?: unknown }).cscComplement).toBeUndefined();
	});

	it('does NOT emit cscComplement when view=standard', async () => {
		const { runBrandAuditPipeline } = await import('../src/lib/brand-audit-pipeline');

		const discoverBrandDomains = async () =>
			makeDiscoveryResult('ford.com', [{ domain: 'ford.co.uk', signals: ['dkim_key_reuse', 'san'] }]);
		const checkRdapLookup = async () => makeRdapResult('CSC Corporate Domains, Inc.');

		const result = await runBrandAuditPipeline(
			'ford.com',
			{ view: 'standard' },
			{ discoverBrandDomains: discoverBrandDomains as never, checkRdapLookup: checkRdapLookup as never },
		);

		expect((result as unknown as { cscComplement?: unknown }).cscComplement).toBeUndefined();
	});

	it('enqueues a deep_scan message after fast_ready', async () => {
		setupEnrichmentFetchMock(['ford.co.uk']);

		const enqueued: unknown[] = [];
		const brandAuditQueue = {
			send: async (msg: unknown): Promise<void> => {
				enqueued.push(msg);
			},
		};

		const { runBrandAuditPipeline } = await import('../src/lib/brand-audit-pipeline');

		const discoverBrandDomains = async () =>
			makeDiscoveryResult('ford.com', [{ domain: 'ford.co.uk', signals: ['dkim_key_reuse', 'san'] }]);
		const checkRdapLookup = async (domain: string) => {
			if (domain === 'ford.co.uk') return makeRdapResult('GoDaddy.com, LLC');
			return makeRdapResult('CSC Corporate Domains, Inc.');
		};

		await runBrandAuditPipeline(
			'ford.com',
			{ view: 'csc_complement', auditId: 'audit-1' },
			{
				brandAuditQueue,
				discoverBrandDomains: discoverBrandDomains as never,
				checkRdapLookup: checkRdapLookup as never,
			},
		);

		expect(enqueued.length).toBe(1);
		expect(enqueued[0]).toMatchObject({ auditId: 'audit-1', target: 'ford.com', phase: 'deep_scan' });
	});

	it('does not propagate Queue send failures — deep_scan enqueue is best-effort', async () => {
		// Before brandAuditQueue was forwarded into pipeline deps, line 1061 was
		// dead in production. Activating it (PR #186) means a transient Cloudflare
		// Queues send() rejection — backpressure, regional issue, write-rate cap —
		// would propagate out of runBrandAuditPipeline. The queue consumer would
		// catch the throw at processBrandAuditMessage and flip the entire target
		// row to `failed` even though csc_complement_fast was already persisted.
		// The sync request path would surface a JSON-RPC error to the client even
		// though the same fast result is in step-store. Both are user-visible
		// regressions caused by a transient infrastructure blip.
		//
		// Policy: same as pdfQueue.send() at brand-audit-consumer.ts:425-429 —
		// best-effort, log on failure, never abort the audit.
		setupEnrichmentFetchMock(['ford.co.uk']);

		const brandAuditQueue = {
			send: async (): Promise<void> => {
				throw new Error('queue backpressure');
			},
		};

		const { runBrandAuditPipeline } = await import('../src/lib/brand-audit-pipeline');

		const discoverBrandDomains = async () =>
			makeDiscoveryResult('ford.com', [{ domain: 'ford.co.uk', signals: ['dkim_key_reuse', 'san'] }]);
		const checkRdapLookup = async (domain: string) => {
			if (domain === 'ford.co.uk') return makeRdapResult('GoDaddy.com, LLC');
			return makeRdapResult('CSC Corporate Domains, Inc.');
		};

		const result = await runBrandAuditPipeline(
			'ford.com',
			{ view: 'csc_complement', auditId: 'audit-1' },
			{
				brandAuditQueue,
				discoverBrandDomains: discoverBrandDomains as never,
				checkRdapLookup: checkRdapLookup as never,
			},
		);

		// Pipeline returns normally; csc_complement_fast is attached to the result.
		expect(result).toBeDefined();
		expect((result as unknown as { cscComplement?: unknown }).cscComplement).toBeDefined();
	});

	it('runs runDeepScanFromStepStore and merges to csc_complement_full', async () => {
		const stored = new Map<string, unknown>();
		const stepStore = {
			get: async (auditId: string, target: string, step: string): Promise<{ status: string; payload: unknown } | null> => {
				const v = stored.get(`${auditId}:${target}:${step}`);
				return v ? (v as { status: string; payload: unknown }) : null;
			},
			put: async (record: { auditId: string; target: string; step: string; status: string; payload: unknown }): Promise<void> => {
				stored.set(`${record.auditId}:${record.target}:${record.step}`, { status: record.status, payload: record.payload });
			},
		};

		stored.set('a-1:ford.com:csc_complement_fast', {
			status: 'completed',
			payload: {
				viewVersion: 1,
				anchor: { apex: 'ford.com', primaryRegistrar: { family: 'csc corporate domains', name: 'CSC', ianaId: null }, managedByCsc: true },
				registrarPortfolio: { totalApexes: 1, byFamily: [{ family: 'csc corporate domains', count: 1, percent: 100, exampleApexes: ['ford.com'] }], offPortfolioCount: 0, offPortfolioApexes: [] },
				shadowItHighlights: [],
				defensiveRegistrations: { count: 0, examples: [], enrichmentStatus: 'ready' },
				postureSnapshot: { stage: 'pending', apexesScanned: 0, apexesTotal: 0, apexes: [], medianGrade: null, distribution: {} },
				deepScan: { stage: 'pending', apexesScanned: 0, apexesTotal: 0, danglingDns: [], danglingDnsTotal: 0, subdomainInventoryByApex: {} },
				generatedAt: '2026-05-22T00:00:00Z',
				reportId: 'csc_rpt_abc',
			},
		});

		const internalCall = async (_tool: string, args: { domain: string }): Promise<unknown> => ({
			content: [],
			structured: { domain: args.domain, score: 80, grade: 'B+', categoryScores: {}, findings: [], totalSubdomains: 100, subdomains: [] },
		});

		const { runDeepScanFromStepStore } = await import('../src/lib/brand-audit-csc-deepscan-job');
		await runDeepScanFromStepStore({ auditId: 'a-1', target: 'ford.com', stepStore: stepStore as never, internalCall });

		const full = stored.get('a-1:ford.com:csc_complement_full') as { status: string; payload: { postureSnapshot: { stage: string } } };
		expect(full.status).toBe('completed');
		expect(full.payload.postureSnapshot.stage).toBe('ready');
	});
});
