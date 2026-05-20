// SPDX-License-Identifier: BUSL-1.1

/**
 * Tests for the discover_brand_domains MCP tool (Phase-4 brand-discovery
 * orchestrator).
 *
 * The tool aggregates output from the four phase-4 discovery signal modules
 * (SAN, NS, DMARC RUA, DKIM key reuse) and returns a unified candidate list
 * with combined-confidence scoring. The signal modules are stubbed via the
 * deps injection seam exposed on the orchestrator — no live DNS or HTTP.
 */

import { describe, it, expect, vi } from 'vitest';
import type {
	SanCorrelationResult,
	NsCorrelationResult,
	DmarcRuaResult,
	DkimKeyReuseResult,
} from '../src/tenants/discovery';
import { createDiscoveryDnsContext, type DiscoveryDnsContext } from '../src/tenants/discovery/dns-context';
import type { DiscoverBrandDomainsDeps } from '../src/tools/discover-brand-domains';

function jsonResponse(status: number, body: unknown): Response {
	return {
		status,
		json: vi.fn().mockResolvedValue(body),
	} as unknown as Response;
}

function okSan(coOwned: string[]): SanCorrelationResult {
	return { seedDomain: 'example.com', coOwnedDomains: coOwned, certIds: [], queryStatus: 'ok' };
}

function okNs(domains: Array<{ domain: string; confidence: number }>): NsCorrelationResult {
	return {
		seedDomain: 'example.com',
		seedNs: ['ns1.example.com'],
		coOwnedDomains: domains.map((d) => ({ domain: d.domain, sharedNs: ['ns1.example.com'], confidence: d.confidence })),
		queryStatus: 'ok',
	};
}

function okRua(domains: string[]): DmarcRuaResult {
	return {
		seedDomain: 'example.com',
		dmarcPresent: true,
		ruaUris: domains.map((d) => `mailto:dmarc@${d}`),
		ruaDomains: domains.map((d) => ({ domain: d, classification: 'related' as const, confidence: 0.6 })),
		queryStatus: 'ok',
	};
}

function okDkim(domains: string[]): DkimKeyReuseResult {
	return {
		seedDomain: 'example.com',
		seedSelectors: ['default'],
		coOwnedDomains: domains.map((d) => ({ domain: d, sharedKeys: ['abc123'], sharedSelectors: ['default'], confidence: 0.95 })),
		queryStatus: 'ok',
	};
}

function makeDeps(overrides: Partial<DiscoverBrandDomainsDeps> = {}): DiscoverBrandDomainsDeps {
	const okEmpty = { coOwnedDomains: [], queryStatus: 'ok' as const };
	return {
		correlateSans: vi.fn().mockResolvedValue(okSan([])),
		correlateSansRecursive: vi.fn().mockResolvedValue({
			seedDomain: 'example.com',
			crossConfirmed: [],
			probed: [],
			queryStatus: 'ok' as const,
		}),
		correlateNs: vi.fn().mockResolvedValue(okNs([])),
		mineDmarcRua: vi.fn().mockResolvedValue(okRua([])),
		detectDkimKeyReuse: vi.fn().mockResolvedValue(okDkim([])),
		detectHttpRedirect: vi.fn().mockResolvedValue(okEmpty),
		detectMxOverlap: vi.fn().mockResolvedValue(okEmpty),
		detectSharedTxtVerifications: vi.fn().mockResolvedValue({
			seedDomain: 'example.com',
			coOwnedDomains: [],
			queryStatus: 'ok' as const,
		}),
		detectSharedMxPlatform: vi.fn().mockResolvedValue({
			seedDomain: 'example.com',
			coOwnedDomains: [],
			queryStatus: 'ok' as const,
		}),
		detectSpfInclude: vi.fn().mockResolvedValue(okEmpty),
		extractSeedSpfIncludes: vi.fn().mockResolvedValue({
			seedDomain: 'example.com',
			candidates: [],
			queryStatus: 'ok' as const,
		}),
		detectCnameAlignment: vi.fn().mockResolvedValue(okEmpty),
		generateMarkovLookalikes: vi.fn().mockReturnValue([]),
		checkLookalikes: vi.fn().mockResolvedValue({
			category: 'lookalikes',
			score: 100,
			findings: [],
		}),
		domainLabelSimilarity: vi.fn().mockReturnValue(0),
		...overrides,
	};
}

describe('discoverBrandDomains', () => {
	it('reports discovery phase timings and progress events', async () => {
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		let now = 1_800_000_000_000;
		const events: unknown[] = [];
		const deps = makeDeps({
			correlateNs: vi.fn().mockImplementation(async () => {
				now += 25;
				return okNs([{ domain: 'example.net', confidence: 1 }]);
			}),
		});

		const result = await discoverBrandDomains(
			'example.com',
			{
				signals: ['ns'],
				candidate_domains: ['example.net'],
				min_confidence: 0.1,
				now: () => {
					now += 5;
					return now;
				},
				onProgress: async (event) => {
					events.push(event);
				},
			},
			deps,
		);

		const summary = result.findings.find((f) => f.metadata?.summary === true);
		expect(summary?.metadata?.discoveryPerformance).toMatchObject({
			phases: expect.arrayContaining([
				expect.objectContaining({ name: 'candidate_universe', status: 'completed', elapsedMs: expect.any(Number) }),
				expect.objectContaining({ name: 'signal_sweep', status: 'completed', elapsedMs: expect.any(Number) }),
				expect.objectContaining({ name: 'ns', status: 'ok', elapsedMs: expect.any(Number) }),
				expect.objectContaining({ name: 'aggregation', status: 'completed', elapsedMs: expect.any(Number) }),
			]),
		});
		expect(events).toEqual(
			expect.arrayContaining([
				expect.objectContaining({ name: 'signal_sweep', status: 'started' }),
				expect.objectContaining({ name: 'ns', status: 'ok' }),
			]),
		);
	});

	it('reports candidate-backed signal probe efficiency in discovery metadata', async () => {
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		const deps = makeDeps({
			correlateNs: vi.fn().mockResolvedValue(okNs([{ domain: 'shop.example.net', confidence: 1 }])),
			detectSharedMxPlatform: vi.fn().mockResolvedValue({
				seedDomain: 'example.com',
				coOwnedDomains: [],
				queryStatus: 'ok' as const,
			}),
		});

		const result = await discoverBrandDomains(
			'example.com',
			{
				signals: ['ns', 'mx_platform'],
				candidate_domains: ['shop.example.net', 'pay.example.net', 'login.example.net'],
				min_confidence: 0.1,
			},
			deps,
		);

		const summary = result.findings.find((f) => f.metadata?.summary === true);
		expect(summary?.metadata?.discoveryPerformance).toMatchObject({
			efficiency: {
				candidateSignalProbes: 58,
				surfacedCandidates: 1,
				probesPerSurfacedCandidate: 58,
				plannerMode: 'enforce',
			},
		});
	});

	it('defaults plannerMode to "enforce" when caller omits planner_mode', async () => {
		// Default flipped from 'observe' → 'enforce' after live + chaos validation
		// (44.8% probe reduction, zero recall regressions on walmart/bofa/marriott
		// + 3 chaos hypotheses on signal-failure recall held). Locking the default
		// here so an accidental revert to 'observe' is caught by CI.
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		const result = await discoverBrandDomains(
			'example.com',
			{ signals: ['ns'], candidate_domains: ['shop.example.net'], min_confidence: 0.1 },
			{
				correlateNs: vi.fn().mockResolvedValue(okNs([])),
			} as unknown as DiscoverBrandDomainsDeps,
		);
		const summary = result.findings.find((f) => f.metadata?.summary === true);
		const efficiency = (summary?.metadata?.discoveryPerformance as { efficiency?: { plannerMode?: string } } | undefined)?.efficiency;
		expect(efficiency?.plannerMode).toBe('enforce');
	});

	it('surfaces bounty-scope failed platform details in signal status and telemetry', async () => {
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
			const url = String(input);
			if (url.includes('/.well-known/')) return jsonResponse(404, null);
			if (url === 'https://hackerone.com/walmart.json') return jsonResponse(503, null);
			return jsonResponse(404, null);
		});
		vi.stubGlobal('fetch', fetchMock);
		try {
			const result = await discoverBrandDomains('brand-alpha.com', { signals: [] }, makeDeps());
			const summary = result.findings.find((f) => f.metadata?.summary === true);

			expect(summary?.metadata?.signalStatus).toMatchObject({
				bounty_scope: {
					status: 'failed',
					error: 'failedPlatforms=hackerone',
				},
			});
			expect(summary?.metadata?.discoveryPerformance).toMatchObject({
				phases: expect.arrayContaining([
					expect.objectContaining({
						name: 'bounty_scope',
						status: 'failed',
						detail: expect.objectContaining({
							failedPlatforms: ['hackerone'],
							fetchedPlatforms: [],
						}),
					}),
				]),
			});
		} finally {
			vi.unstubAllGlobals();
		}
	});

	it('filters a single-SAN candidate (SAN default 0.1 < default min_confidence 0.5)', async () => {
		// SAN was lowered from 0.7 to 0.1 as part of the "Zero False Positive"
		// mandate: SAN co-tenancy on multi-tenant CDNs is too noisy to surface alone.
		// A single SAN observation can no longer cross the 0.5 confidence threshold.
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		const deps = makeDeps({ correlateSans: vi.fn().mockResolvedValue(okSan(['sister.com'])) });
		const result = await discoverBrandDomains('example.com', { signals: ['san'] }, deps);

		expect(result.category).toBe('brand_discovery');
		const candidates = result.findings.filter((f) => f.metadata?.candidate);
		expect(candidates).toHaveLength(0);
	});

	it('returns missingControl when the only requested signal times out', async () => {
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		const deps = makeDeps({
			correlateSans: vi.fn().mockResolvedValue({
				seedDomain: 'example.com',
				coOwnedDomains: [],
				certIds: [],
				queryStatus: 'timeout',
			} satisfies SanCorrelationResult),
		});

		const result = await discoverBrandDomains('example.com', { signals: ['san'] }, deps);

		expect(result.findings).toHaveLength(1);
		expect(result.findings[0]).toMatchObject({
			title: 'Brand-domain discovery could not complete',
			metadata: {
				missingControl: true,
				signalStatus: { san: { status: 'timeout' } },
			},
		});
	});

	it('aggregates multi-signal candidates with combined-confidence math', async () => {
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		// Same candidate reported by SAN (0.1) AND DKIM (0.95).
		// combined = 1 - (1-0.1) * (1-0.95) = 1 - 0.9*0.05 = 1 - 0.045 = 0.955
		const deps = makeDeps({
			correlateSans: vi.fn().mockResolvedValue(okSan(['sister.com'])),
			detectDkimKeyReuse: vi.fn().mockResolvedValue(okDkim(['sister.com'])),
		});
		const result = await discoverBrandDomains(
			'example.com',
			{ signals: ['san', 'dkim_key_reuse'], candidate_domains: ['sister.com'] },
			deps,
		);
		const candidates = result.findings.filter((f) => f.metadata?.candidate);
		expect(candidates).toHaveLength(1);
		expect(candidates[0].metadata?.candidate).toBe('sister.com');
		expect(candidates[0].metadata?.combinedConfidence).toBeCloseTo(0.955, 3);
		expect((candidates[0].metadata?.signals as string[]).sort()).toEqual(['dkim_key_reuse', 'san']);
		// 0.955 > AUTO_INCLUDE_THRESHOLD (0.85) => severity 'low'
		expect(candidates[0].severity).toBe('low');
	});

	it('drops candidates whose corroborated confidence falls below min_confidence', async () => {
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		// Two-signal SAN(0.1)+NS(0.3) combines to 1 - (0.9*0.7) = 0.37, below default 0.5.
		// Needs two signals because post-v2.14.0 the corroboration gate would
		// short-circuit a single-signal NS candidate before min_confidence is checked.
		const deps = makeDeps({
			correlateSans: vi.fn().mockResolvedValue(okSan(['weak.com'])),
			correlateNs: vi.fn().mockResolvedValue(okNs([{ domain: 'weak.com', confidence: 0.3 }])),
		});
		const result = await discoverBrandDomains(
			'example.com',
			{ signals: ['san', 'ns'], candidate_domains: ['weak.com'] },
			deps,
		);
		const candidates = result.findings.filter((f) => f.metadata?.candidate);
		expect(candidates).toHaveLength(0);
	});

	it('keeps candidates at or above an explicit min_confidence', async () => {
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		// Two-signal NS(0.6)+DMARC(0.6) combines to 0.84, above explicit min_confidence 0.5.
		// (Post-v2.14.0 corroboration gate filters single-signal NS, so the test must
		// supply two signals to exercise the min_confidence threshold itself.)
		const deps = makeDeps({
			correlateNs: vi.fn().mockResolvedValue(okNs([{ domain: 'partner.com', confidence: 0.6 }])),
			mineDmarcRua: vi.fn().mockResolvedValue(okRua(['partner.com'])),
		});
		const result = await discoverBrandDomains(
			'example.com',
			{ signals: ['ns', 'dmarc_rua'], candidate_domains: ['partner.com'], min_confidence: 0.5 },
			deps,
		);
		const candidates = result.findings.filter((f) => f.metadata?.candidate);
		expect(candidates).toHaveLength(1);
		expect(candidates[0].metadata?.candidate).toBe('partner.com');
	});

	it('populates candidate seed provenance and classifier enrichment metadata', async () => {
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		const deps = makeDeps({
			correlateNs: vi.fn().mockResolvedValue(okNs([{ domain: 'example.net', confidence: 1 }])),
			mineDmarcRua: vi.fn().mockResolvedValue(okRua(['example.net'])),
			detectSharedTxtVerifications: vi.fn().mockResolvedValue({
				seedDomain: 'example.com',
				coOwnedDomains: [
					{ domain: 'example-shop.test', sharedTxtVerifications: ['google-site-verification=abc'], confidence: 0.9 },
				],
				queryStatus: 'ok',
			}),
			detectSharedMxPlatform: vi.fn().mockResolvedValue({
				seedDomain: 'example.com',
				coOwnedDomains: [
					{ domain: 'example-mail.test', sharedMxPlatform: 'google_workspace', confidence: 0.55 },
				],
				queryStatus: 'ok',
			}),
		});

		const result = await discoverBrandDomains(
			'example.com',
			{
				signals: ['ns', 'dmarc_rua', 'txt_verification', 'mx_platform'],
				candidate_domains: ['example-shop.test', 'example-mail.test'],
				min_confidence: 0.1,
			},
			deps,
		);

		const shop = result.findings.find((f) => f.metadata?.candidate === 'example-shop.test');
		const mail = result.findings.find((f) => f.metadata?.candidate === 'example-mail.test');
		const net = result.findings.find((f) => f.metadata?.candidate === 'example.net');
		const summary = result.findings.find((f) => f.metadata?.summary === true);

		expect(shop?.metadata?.sharedTxtVerifications).toEqual(['google-site-verification=abc']);
		expect(mail?.metadata?.sharedMxPlatform).toBe('google_workspace');
		expect(net?.metadata?.candidateSeedSources).toContain('tld_sweep');
		expect(summary?.metadata?.candidateUniverse).toMatchObject({ seeded: expect.any(Number), surfaced: 3 });
	});

	it('preserves DMARC external authorization metadata on dmarc_rua source notes', async () => {
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		const deps = makeDeps({
			mineDmarcRua: vi.fn().mockResolvedValue({
				seedDomain: 'example.com',
				dmarcPresent: true,
				ruaUris: ['mailto:reports@reports.example.net'],
				ruaDomains: [
					{
						domain: 'reports.example.net',
						classification: 'related',
						externalAuthorization: 'confirmed',
						confidence: 0.75,
					},
				],
				queryStatus: 'ok',
			}),
			detectDkimKeyReuse: vi.fn().mockResolvedValue(okDkim(['reports.example.net'])),
		});

		const result = await discoverBrandDomains(
			'example.com',
			{ signals: ['dmarc_rua', 'dkim_key_reuse'], min_confidence: 0.1 },
			deps,
		);

		const candidate = result.findings.find((f) => f.metadata?.candidate === 'reports.example.net');
		expect(candidate?.metadata?.sources).toMatchObject({
			dmarc_rua: {
				classification: 'related',
				externalAuthorization: 'confirmed',
			},
		});
	});

	it('threads deep candidate-universe provenance and cap drops into the summary', async () => {
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		const deps = makeDeps({
			correlateNs: vi.fn().mockResolvedValue(okNs([{ domain: 'examplecloud.com', confidence: 1 }])),
			generateMarkovLookalikes: vi.fn().mockReturnValue(Array.from({ length: 320 }, (_, i) => `candidate-${i}.example.net`)),
		});

		const result = await discoverBrandDomains(
			'example.com',
			{
				signals: ['ns'],
				depth: 'deep',
				min_confidence: 0.1,
			},
			deps,
		);

		const summary = result.findings.find((f) => f.metadata?.summary === true);
		expect(summary?.metadata?.candidateUniverse).toMatchObject({
			seeded: expect.any(Number),
			probed: expect.any(Number),
			sources: expect.objectContaining({ enterprise_affix: expect.any(Number) }),
			dropped: expect.objectContaining({ cap: expect.any(Number) }),
		});
		expect((summary?.metadata?.candidateUniverse as { seeded: number }).seeded).toBeLessThanOrEqual(250);
	});

	it('feeds DNS-active lookalikes into the active_lookalike candidate provenance source in deep mode', async () => {
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		const deps = makeDeps({
			checkLookalikes: vi.fn().mockResolvedValue({
				category: 'lookalikes',
				score: 80,
				findings: [
					{
						category: 'lookalikes',
						title: 'Lookalike domain registered: examp1e.com',
						severity: 'medium',
						detail: 'synthetic active lookalike',
						metadata: { lookalikeDomain: 'examp1e.com', hasA: true },
					},
				],
			}),
			detectDkimKeyReuse: vi.fn().mockResolvedValue(okDkim(['examp1e.com'])),
		});

		const result = await discoverBrandDomains(
			'example.com',
			{ signals: ['dkim_key_reuse'], depth: 'deep', min_confidence: 0.1 },
			deps,
		);

		const summary = result.findings.find((f) => f.metadata?.summary === true);
		const candidate = result.findings.find((f) => f.metadata?.candidate === 'examp1e.com');
		expect(summary?.metadata?.candidateUniverse).toMatchObject({
			sources: expect.objectContaining({ active_lookalike: 1 }),
		});
		expect(candidate?.metadata?.candidateSeedSources).toContain('active_lookalike');
	});

	it('does not include generated seed provenance in combined confidence', async () => {
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		const deps = makeDeps({
			checkLookalikes: vi.fn().mockResolvedValue({
				category: 'lookalikes',
				score: 80,
				findings: [
					{
						category: 'lookalikes',
						title: 'Lookalike domain registered: examp1e.com',
						severity: 'medium',
						detail: 'synthetic active lookalike',
						metadata: { lookalikeDomain: 'examp1e.com', hasA: true },
					},
				],
			}),
			correlateNs: vi.fn().mockResolvedValue(okNs([{ domain: 'examp1e.com', confidence: 0.6 }])),
			detectSharedMxPlatform: vi.fn().mockResolvedValue({
				seedDomain: 'example.com',
				coOwnedDomains: [{ domain: 'examp1e.com', sharedMxPlatform: 'proofpoint', confidence: 0.55 }],
				queryStatus: 'ok' as const,
			}),
		});

		const result = await discoverBrandDomains(
			'example.com',
			{ signals: ['ns', 'mx_platform'], depth: 'deep', min_confidence: 0.1 },
			deps,
		);

		const candidate = result.findings.find((f) => f.metadata?.candidate === 'examp1e.com');
		expect(candidate?.metadata?.signals).toEqual(['active_lookalike', 'mx_platform', 'ns']);
		expect(candidate?.metadata?.combinedConfidence).toBeCloseTo(0.82, 3);
		expect(candidate?.metadata?.combinedConfidence).toBeLessThan(0.85);
	});

	it('preserves partial first-order SAN candidates and marks the signal partial', async () => {
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		const deps = makeDeps({
			correlateSans: vi.fn().mockResolvedValue({
				seedDomain: 'example.com',
				coOwnedDomains: ['partial-san.example.net'],
				certIds: [123],
				queryStatus: 'partial',
			}),
			detectDkimKeyReuse: vi.fn().mockResolvedValue(okDkim(['partial-san.example.net'])),
		});

		const result = await discoverBrandDomains(
			'example.com',
			{ signals: ['san', 'dkim_key_reuse'], min_confidence: 0.1 },
			deps,
		);

		const summary = result.findings.find((f) => f.metadata?.summary === true);
		const candidate = result.findings.find((f) => f.metadata?.candidate === 'partial-san.example.net');
		expect(summary?.metadata?.signalStatus).toMatchObject({ san: { status: 'partial' } });
		expect(candidate).toBeDefined();
	});

	it('marks recursive SAN budget exhaustion as partial while preserving cross-confirmed candidates', async () => {
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		const deps = makeDeps({
			correlateSans: vi.fn().mockResolvedValue(okSan(['sibling.example.net'])),
			correlateSansRecursive: vi.fn().mockResolvedValue({
				seedDomain: 'example.com',
				crossConfirmed: [
					{ candidate: 'sibling.example.net', certIds: [321], queryStatus: 'ok' },
				],
				probed: ['sibling.example.net', 'later.example.net'],
				queryStatus: 'budget_exceeded',
			}),
		});

		const result = await discoverBrandDomains(
			'example.com',
			{ signals: ['san', 'san_recursive'], min_confidence: 0.1 },
			deps,
		);

		const summary = result.findings.find((f) => f.metadata?.summary === true);
		const candidate = result.findings.find((f) => f.metadata?.candidate === 'sibling.example.net');
		expect(summary?.metadata?.signalStatus).toMatchObject({
			san_recursive: { status: 'partial', error: 'budget_exceeded' },
		});
		expect(candidate?.metadata?.signals).toContain('san_recursive');
		expect(candidate?.metadata?.sources).toMatchObject({
			san_recursive: { certIds: [321], probedCount: 2 },
		});
	});

	it('skips recursive SAN when the audit deadline has too little headroom', async () => {
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		const correlateSansRecursive = vi.fn().mockResolvedValue({
			seedDomain: 'example.com',
			crossConfirmed: [],
			probed: [],
			queryStatus: 'ok',
		});
		const deps = makeDeps({
			correlateSans: vi.fn().mockResolvedValue(okSan(['sibling.example.net'])),
			correlateSansRecursive,
		});

		const result = await discoverBrandDomains(
			'example.com',
			{ signals: ['san', 'san_recursive'], deadlineMs: 20_000, now: () => 1_000, min_confidence: 0.1 },
			deps,
		);

		const summary = result.findings.find((f) => f.metadata?.summary === true);
		expect(correlateSansRecursive).not.toHaveBeenCalled();
		expect(summary?.metadata?.signalStatus).toMatchObject({
			san_recursive: { status: 'skipped_deadline' },
		});
		expect(summary?.metadata?.discoveryPerformance).toMatchObject({
			phases: expect.arrayContaining([
				expect.objectContaining({
					name: 'san_recursive',
					status: 'skipped_deadline',
					detail: expect.objectContaining({ remainingMs: 19_000 }),
				}),
			]),
		});
	});

	it('returns missingControl finding when signal modules all throw (DNS-failure resilience)', async () => {
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		const failing = vi.fn().mockRejectedValue(new Error('DNS error'));
		const deps = makeDeps({
			correlateSans: failing,
			correlateSansRecursive: failing,
			correlateNs: failing,
			mineDmarcRua: failing,
			detectDkimKeyReuse: failing,
			detectHttpRedirect: failing,
			detectMxOverlap: failing,
			detectSharedTxtVerifications: failing,
			detectSharedMxPlatform: failing,
			detectSpfInclude: failing,
			extractSeedSpfIncludes: failing,
			detectCnameAlignment: failing,
		});
		const result = await discoverBrandDomains('example.com', {}, deps);
		expect(result.category).toBe('brand_discovery');
		const missing = result.findings.find((f) => f.metadata?.missingControl);
		expect(missing).toBeDefined();
		expect(missing!.severity).toBe('high');
	});

	it('sorts candidates descending by combined confidence', async () => {
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		// low.com gets SAN(0.1)+DMARC(0.6) = 1 - (0.9*0.4) = 0.64
		// high.com gets SAN(0.1)+DKIM(0.95) = 1 - (0.9*0.05) = 0.955
		// Both above 0.5 threshold; high.com should sort first.
		const deps = makeDeps({
			correlateSans: vi.fn().mockResolvedValue(okSan(['low.com', 'high.com'])),
			mineDmarcRua: vi.fn().mockResolvedValue(okRua(['low.com'])),
			detectDkimKeyReuse: vi.fn().mockResolvedValue(okDkim(['high.com'])),
		});
		const result = await discoverBrandDomains(
			'example.com',
			{ signals: ['san', 'dmarc_rua', 'dkim_key_reuse'], candidate_domains: ['high.com', 'low.com'] },
			deps,
		);
		const candidates = result.findings.filter((f) => f.metadata?.candidate);
		expect(candidates).toHaveLength(2);
		expect(candidates[0].metadata?.candidate).toBe('high.com');
		expect(candidates[1].metadata?.candidate).toBe('low.com');
		expect(
			(candidates[0].metadata?.combinedConfidence as number) >=
				(candidates[1].metadata?.combinedConfidence as number),
		).toBe(true);
	});

	it('only invokes the requested signal modules', async () => {
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		const sanSpy = vi.fn().mockResolvedValue(okSan([]));
		const nsSpy = vi.fn().mockResolvedValue(okNs([]));
		const ruaSpy = vi.fn().mockResolvedValue(okRua([]));
		const dkimSpy = vi.fn().mockResolvedValue(okDkim([]));
		const deps = makeDeps({
			correlateSans: sanSpy,
			correlateNs: nsSpy,
			mineDmarcRua: ruaSpy,
			detectDkimKeyReuse: dkimSpy,
		});
		await discoverBrandDomains('example.com', { signals: ['san'] }, deps);
		expect(sanSpy).toHaveBeenCalled();
		expect(nsSpy).not.toHaveBeenCalled();
		expect(ruaSpy).not.toHaveBeenCalled();
		expect(dkimSpy).not.toHaveBeenCalled();
	});

	it('shares one audit-scoped DNS context across DNS-backed signals', async () => {
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		const baseQueryCalls: string[] = [];
		const deps = makeDeps({
			createDnsContext: vi.fn(() =>
				createDiscoveryDnsContext({
					baseQuery: async (name, type) => {
						baseQueryCalls.push(`${name}:${type}`);
						return { Status: 0, Answer: [] };
					},
				}),
			),
			correlateNs: vi.fn(async (_seedDomain, opts) => {
				await opts.dnsContext!.query('candidate.example.net', 'NS');
				await opts.dnsContext!.query('candidate.example.net', 'NS');
				return okNs([]);
			}),
			detectSharedMxPlatform: vi.fn(async (_seedDomain, opts) => {
				await opts.dnsContext!.query('candidate.example.net', 'NS');
				return {
					seedDomain: 'example.com',
					coOwnedDomains: [],
					queryStatus: 'ok' as const,
				};
			}),
		} as Partial<DiscoverBrandDomainsDeps>);

		await discoverBrandDomains(
			'example.com',
			{ depth: 'deep', signals: ['ns', 'mx_platform'], candidate_domains: ['candidate.example.net'] },
			deps,
		);

		expect(deps.createDnsContext).toHaveBeenCalledTimes(1);
		expect(baseQueryCalls).toEqual(['candidate.example.net:NS']);
	});

	it('uses a dedicated DNS context for DKIM key reuse so bulk signal fan-out cannot starve it', async () => {
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		const makeContext = (): DiscoveryDnsContext => ({
			query: vi.fn(async () => ({
				Status: 0,
				TC: false,
				RD: true,
				RA: true,
				AD: false,
				CD: false,
				Question: [],
				Answer: [],
			})),
			metrics: () => ({ queries: 0, cacheHits: 0, errors: 0 }),
		});
		const contexts = [makeContext(), makeContext()];
		let nextContext = 0;
		let nsContext: DiscoveryDnsContext | undefined;
		let dkimContext: DiscoveryDnsContext | undefined;
		const deps = makeDeps({
			createDnsContext: vi.fn(() => contexts[Math.min(nextContext++, contexts.length - 1)]),
			correlateNs: vi.fn(async (_seedDomain, opts) => {
				nsContext = opts.dnsContext;
				return okNs([]);
			}),
			detectDkimKeyReuse: vi.fn(async (_seedDomain, _candidateDomains, opts) => {
				dkimContext = opts.dnsContext;
				return okDkim([]);
			}),
		});

		await discoverBrandDomains('example.com', { signals: ['ns', 'dkim_key_reuse'] }, deps);

		expect(deps.createDnsContext).toHaveBeenCalledTimes(2);
		expect(nsContext).toBe(contexts[0]);
		expect(dkimContext).toBe(contexts[1]);
		expect(dkimContext).not.toBe(nsContext);
	});

	it('emits planner observe metrics without changing signal candidate lists', async () => {
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		const nsSpy = vi.fn().mockResolvedValue(okNs([]));
		const deps = makeDeps({ correlateNs: nsSpy });

		const result = await discoverBrandDomains(
			'example.com',
			{
				signals: ['ns'],
				candidate_domains: ['example.ca', 'example-support.net', 'noise-1.net'],
				depth: 'deep',
				planner_mode: 'observe',
			},
			deps,
		);

		const nsOptions = nsSpy.mock.calls[0]?.[1];
		expect(nsOptions?.candidateDomains).toEqual(expect.arrayContaining(['example.ca', 'example-support.net', 'noise-1.net']));
		expect(nsOptions?.candidateDomains.length).toBeGreaterThan(3);
		const summary = result.findings.find((f) => f.metadata?.summary === true);
		expect(summary?.metadata?.discoveryPerformance).toMatchObject({
			planner: {
				mode: 'observe',
				wouldProbeBySignal: { ns: expect.any(Number) },
				wouldDropBySignal: expect.any(Object),
			},
		});
	});

	it('passes planned candidate subsets to candidate-backed signals in enforce mode', async () => {
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		const dkimSpy = vi.fn().mockResolvedValue(okDkim([]));
		const nsSpy = vi.fn().mockResolvedValue(okNs([]));
		const deps = makeDeps({ detectDkimKeyReuse: dkimSpy, correlateNs: nsSpy });

		const result = await discoverBrandDomains(
			'example.com',
			{
				signals: ['dkim_key_reuse', 'ns'],
				candidate_domains: ['example.ca', 'examp1e.com', 'example-support.net', 'noise-1.net', 'noise-2.net'],
				depth: 'deep',
				planner_mode: 'enforce',
				planner_caps: { dkim_key_reuse: 3, ns: 4 },
			},
			deps,
		);

		// All five inputs come in via `candidate_domains`, which the candidate
		// universe sources as `caller_candidate`. Caller-asserted candidates are
		// guarded — they bypass per-signal caps so a user who explicitly named
		// 5 candidates always sees all 5 probed, even with cap=3.
		expect(dkimSpy).toHaveBeenCalledWith(
			'example.com',
			['example.ca', 'examp1e.com', 'example-support.net', 'noise-1.net', 'noise-2.net'],
			expect.any(Object),
		);
		expect(nsSpy).toHaveBeenCalledWith(
			'example.com',
			expect.objectContaining({
				candidateDomains: ['example.ca', 'examp1e.com', 'example-support.net', 'noise-1.net', 'noise-2.net'],
			}),
		);
		const summary = result.findings.find((f) => f.metadata?.summary === true);
		const efficiency = summary?.metadata?.discoveryPerformance?.efficiency as
			| { candidateSignalProbes?: number; baselineCandidateSignalProbes?: number; plannerMode?: string }
			| undefined;
		expect(efficiency).toMatchObject({
			candidateSignalProbes: 10,
			baselineCandidateSignalProbes: expect.any(Number),
			plannerMode: 'enforce',
		});
		expect(efficiency?.baselineCandidateSignalProbes).toBeGreaterThanOrEqual(10);
	});

	it('caps non-guarded candidates per signal in enforce mode while letting caller-asserted ones bypass', async () => {
		// Mix caller-asserted with a synthetic high-volume universe source.
		// `candidate_domains` plus universe-generated tld_sweep candidates lets
		// us check that planner caps actually bite the non-guarded bucket while
		// guarded ones (caller_candidate) remain present.
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		const dkimSpy = vi.fn().mockResolvedValue(okDkim([]));
		const deps = makeDeps({ detectDkimKeyReuse: dkimSpy });

		await discoverBrandDomains(
			'example.com',
			{
				signals: ['dkim_key_reuse'],
				candidate_domains: ['asserted-a.example', 'asserted-b.example'],
				depth: 'deep',
				planner_mode: 'enforce',
				planner_caps: { dkim_key_reuse: 1 },
			},
			deps,
		);

		const callArgs = dkimSpy.mock.calls[0][1] as string[];
		expect(callArgs).toContain('asserted-a.example');
		expect(callArgs).toContain('asserted-b.example');
	});

	it('throws on invalid seed domain (programmer error)', async () => {
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		await expect(discoverBrandDomains('not a domain!', {}, makeDeps())).rejects.toThrow(/Domain validation failed/);
	});

	it('skips candidates that are subdomains of the seed domain', async () => {
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		// SAN reports both seed-subdomain AND a true sibling; DKIM corroborates only the sibling.
		// Subdomain filter must drop `dmarc.example.com`; corroboration gate must keep `other.com`
		// (single-SAN at 0.1 would otherwise be filtered post-v2.14.0).
		const deps = makeDeps({
			correlateSans: vi.fn().mockResolvedValue(okSan(['dmarc.example.com', 'other.com'])),
			detectDkimKeyReuse: vi.fn().mockResolvedValue(okDkim(['other.com'])),
		});
		const result = await discoverBrandDomains(
			'example.com',
			{ signals: ['san', 'dkim_key_reuse'], candidate_domains: ['other.com'] },
			deps,
		);
		const candidates = result.findings.filter((f) => f.metadata?.candidate);

		// dmarc.example.com should be skipped, other.com should remain
		expect(candidates).toHaveLength(1);
		expect(candidates[0].metadata?.candidate).toBe('other.com');
	});

	it('format=compact omits emoji icons in formatter', async () => {
		const { formatDiscoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		const result = {
			category: 'brand_discovery' as const,
			passed: true,
			score: 100,
			findings: [
				{
					category: 'brand_discovery' as const,
					title: 'Discovered candidate: sister.com',
					severity: 'low' as const,
					detail: 'Found via 1 signal(s); confidence 0.7',
					metadata: {
						candidate: 'sister.com',
						signals: ['san'],
						combinedConfidence: 0.7,
					},
				},
			],
		};
		const compact = formatDiscoverBrandDomains(result, 'compact');
		const full = formatDiscoverBrandDomains(result, 'full');
		// Emoji set used in full mode
		expect(/[🔵🟡🟠🔴]/.test(full)).toBe(true);
		expect(/[🔵🟡🟠🔴]/.test(compact)).toBe(false);
	});
});

// ---------------------------------------------------------------------------
// T7: tiered discovery_mode tests
// ---------------------------------------------------------------------------

describe('discoverBrandDomains — discovery_mode=tiered', () => {
	const FRESH_FRESHNESS = {
		overallStaleness: 'fresh' as const,
		oldestSignalAgeMs: 1_000,
		latestSweepAtMs: 1_800_000_000_000,
	};
	const VERY_STALE_FRESHNESS = {
		overallStaleness: 'very_stale' as const,
		oldestSignalAgeMs: 60 * 24 * 60 * 60 * 1000,
		latestSweepAtMs: 1_800_000_000_000 - 60 * 24 * 60 * 60 * 1000,
	};

	function tier0Empty(): unknown {
		return { observations: [], status: 'ok', optedOut: false };
	}
	function tier0Ok(candidate: string): unknown {
		return {
			observations: [{ candidate, source: 'tenant_domains', tier: 0, confidence: 1.0 }],
			status: 'ok',
			optedOut: false,
		};
	}
	function tier1Empty(freshness = FRESH_FRESHNESS): unknown {
		return { observations: [], status: 'ok', triggerTier3Fallback: false, freshness };
	}
	function tier1Ok(candidate: string, freshness = FRESH_FRESHNESS): unknown {
		return {
			observations: [
				{
					candidate,
					source: 'infra_graph_signal',
					tier: 1,
					confidence: 0.8,
					specificityScore: 0.9,
					signalType: 'soa_admin',
					signalValue: 'admin@example.com',
					numSharedSignals: 1,
					maxSpecificity: 0.9,
					signalTypes: ['soa_admin'],
				},
			],
			status: 'ok',
			triggerTier3Fallback: false,
			freshness,
		};
	}
	function tier2Empty(): unknown {
		return { observations: [], status: 'ok' };
	}
	void tier1Empty;

	it('emits per-tier counts in discoveryPerformance.tiers when discovery_mode=tiered', async () => {
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		const tieredDeps = {
			...makeDeps(),
			tier0Lookup: vi.fn().mockResolvedValue(tier0Ok('tenant-portfolio.example.net')),
			tier1Lookup: vi.fn().mockResolvedValue(tier1Ok('infra-graph.example.net', FRESH_FRESHNESS)),
			tier2Lookup: vi.fn().mockResolvedValue({
				observations: [
					{ candidate: 'example.com', source: 'gsi_evidence', tier: 2, confidence: 0.9, threatLevel: 'low', capturedAt: 1 },
					{ candidate: 'example.com', source: 'score_alert_critical_drop', tier: 4, confidence: 0.5, alertType: 'drop', transition: 'low->critical' },
				],
				status: 'ok',
			}),
		};
		const result = await discoverBrandDomains(
			'example.com',
			{ discovery_mode: 'tiered', signals: ['ns'], candidate_domains: [] },
			tieredDeps as unknown as DiscoverBrandDomainsDeps,
		);
		const summary = result.findings.find((f) => f.metadata?.summary === true);
		const tiers = (summary?.metadata?.discoveryPerformance as { tiers?: Record<string, unknown> } | undefined)?.tiers;
		expect(tiers).toMatchObject({
			tier0Count: 1,
			tier1Count: 1,
			tier2Count: 1,
			tier4Count: 1,
			tier3Count: expect.any(Number),
			tier0Status: 'ok',
			tier1Status: 'ok',
			tier2Status: 'ok',
			tier3FallbackTriggered: expect.any(Number),
			tier1Freshness: expect.objectContaining({ overallStaleness: 'fresh' }),
			optOutsFiltered: expect.any(Number),
		});
	});

	it('does not trigger tier3 live sweep when tier1 freshness is fresh and returns candidates', async () => {
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		const correlateNs = vi.fn().mockResolvedValue(okNs([]));
		const tieredDeps = {
			...makeDeps({ correlateNs }),
			tier0Lookup: vi.fn().mockResolvedValue(tier0Empty()),
			tier1Lookup: vi.fn().mockResolvedValue(tier1Ok('related.example.net', FRESH_FRESHNESS)),
			tier2Lookup: vi.fn().mockResolvedValue(tier2Empty()),
		};
		const result = await discoverBrandDomains(
			'example.com',
			{ discovery_mode: 'tiered', signals: ['ns'], candidate_domains: [] },
			tieredDeps as unknown as DiscoverBrandDomainsDeps,
		);
		const summary = result.findings.find((f) => f.metadata?.summary === true);
		const tiers = (summary?.metadata?.discoveryPerformance as { tiers?: Record<string, unknown> } | undefined)?.tiers;
		expect(tiers).toBeDefined();
		expect(tiers?.tier3FallbackTriggered).toBe(0);
		expect(correlateNs).not.toHaveBeenCalled();
	});

	it('surfaces high-specificity tier1 observations without tier3 corroboration', async () => {
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		const correlateNs = vi.fn().mockResolvedValue(okNs([]));
		const tieredDeps = {
			...makeDeps({ correlateNs }),
			tier0Lookup: vi.fn().mockResolvedValue(tier0Empty()),
			tier1Lookup: vi.fn().mockResolvedValue(tier1Ok('infra-graph.example.net', FRESH_FRESHNESS)),
			tier2Lookup: vi.fn().mockResolvedValue(tier2Empty()),
		};
		const result = await discoverBrandDomains(
			'example.com',
			{ discovery_mode: 'tiered', signals: ['ns'], candidate_domains: [], min_confidence: 0.1 },
			tieredDeps as unknown as DiscoverBrandDomainsDeps,
		);

		const candidate = result.findings.find((f) => f.metadata?.candidate === 'infra-graph.example.net');
		expect(candidate?.metadata?.combinedConfidence).toBeGreaterThanOrEqual(0.8);
		expect(candidate?.metadata?.evidenceObservations).toEqual(
			expect.arrayContaining([
				expect.objectContaining({
					signal: 'markov_gen',
					tier: 1,
					specificityScore: 0.9,
				}),
			]),
		);
		expect(correlateNs).not.toHaveBeenCalled();
	});

	it('triggers tier3 fallback when tier1 freshness is very_stale', async () => {
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		const correlateNs = vi.fn().mockResolvedValue(okNs([]));
		const tieredDeps = {
			...makeDeps({ correlateNs }),
			tier0Lookup: vi.fn().mockResolvedValue(tier0Empty()),
			tier1Lookup: vi.fn().mockResolvedValue({
				observations: [],
				status: 'ok',
				triggerTier3Fallback: true,
				freshness: VERY_STALE_FRESHNESS,
			}),
			tier2Lookup: vi.fn().mockResolvedValue(tier2Empty()),
		};
		const result = await discoverBrandDomains(
			'example.com',
			{ discovery_mode: 'tiered', signals: ['ns'], candidate_domains: [] },
			tieredDeps as unknown as DiscoverBrandDomainsDeps,
		);
		const summary = result.findings.find((f) => f.metadata?.summary === true);
		const tiers = (summary?.metadata?.discoveryPerformance as { tiers?: Record<string, unknown> } | undefined)?.tiers;
		expect(tiers?.tier3FallbackTriggered).toBe(1);
		expect(correlateNs).toHaveBeenCalled();
	});

	it('triggers tier3 fallback when caller_candidates are not covered by tier 0/1/2', async () => {
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		const correlateNs = vi.fn().mockResolvedValue(okNs([]));
		const tieredDeps = {
			...makeDeps({ correlateNs }),
			tier0Lookup: vi.fn().mockResolvedValue(tier0Empty()),
			tier1Lookup: vi.fn().mockResolvedValue(tier1Ok('covered.example.net', FRESH_FRESHNESS)),
			tier2Lookup: vi.fn().mockResolvedValue(tier2Empty()),
		};
		const result = await discoverBrandDomains(
			'example.com',
			{
				discovery_mode: 'tiered',
				signals: ['ns'],
				candidate_domains: ['uncovered.example.net'],
			},
			tieredDeps as unknown as DiscoverBrandDomainsDeps,
		);
		const summary = result.findings.find((f) => f.metadata?.summary === true);
		const tiers = (summary?.metadata?.discoveryPerformance as { tiers?: Record<string, unknown> } | undefined)?.tiers;
		expect(tiers?.tier3FallbackTriggered).toBe(1);
		expect(correlateNs).toHaveBeenCalled();
	});

	it('classic mode does not emit tier counts and runs the legacy pipeline unchanged', async () => {
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		const tier0 = vi.fn();
		const tier1 = vi.fn();
		const tier2 = vi.fn();
		const tieredDeps = {
			...makeDeps(),
			tier0Lookup: tier0,
			tier1Lookup: tier1,
			tier2Lookup: tier2,
		};
		const result = await discoverBrandDomains(
			'example.com',
			{ discovery_mode: 'classic', signals: ['ns'] },
			tieredDeps as unknown as DiscoverBrandDomainsDeps,
		);
		const summary = result.findings.find((f) => f.metadata?.summary === true);
		const perf = summary?.metadata?.discoveryPerformance as Record<string, unknown> | undefined;
		expect(perf).toBeDefined();
		expect(perf && 'tiers' in perf).toBe(false);
		expect(tier0).not.toHaveBeenCalled();
		expect(tier1).not.toHaveBeenCalled();
		expect(tier2).not.toHaveBeenCalled();
	});

	it('default discovery_mode is "classic" (BSL boundary — never flip the public default)', async () => {
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		const tier0 = vi.fn();
		const tieredDeps = { ...makeDeps(), tier0Lookup: tier0, tier1Lookup: vi.fn(), tier2Lookup: vi.fn() };
		await discoverBrandDomains(
			'example.com',
			{ signals: ['ns'] },
			tieredDeps as unknown as DiscoverBrandDomainsDeps,
		);
		expect(tier0).not.toHaveBeenCalled();
	});

	it('applies opt-out filter to all surfaced tier 0/1/2 candidates', async () => {
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		const { __resetOptoutCacheForTests } = await import('../src/lib/brand-optout-enforcement');
		__resetOptoutCacheForTests();
		const tieredDeps = {
			...makeDeps(),
			tier0Lookup: vi.fn().mockResolvedValue(tier0Ok('opted-out.example.net')),
			tier1Lookup: vi.fn().mockResolvedValue(tier1Ok('opted-out.example.net', FRESH_FRESHNESS)),
			tier2Lookup: vi.fn().mockResolvedValue(tier2Empty()),
			fetchOptouts: vi.fn().mockResolvedValue(new Set(['opted-out.example.net'])),
		};
		const result = await discoverBrandDomains(
			'example.com',
			{ discovery_mode: 'tiered', signals: ['ns'], candidate_domains: [] },
			tieredDeps as unknown as DiscoverBrandDomainsDeps,
		);
		const summary = result.findings.find((f) => f.metadata?.summary === true);
		const tiers = (summary?.metadata?.discoveryPerformance as { tiers?: Record<string, number> } | undefined)?.tiers;
		expect(tiers?.optOutsFiltered).toBeGreaterThanOrEqual(1);
		const surfaced = result.findings
			.filter((f) => f.metadata?.candidate)
			.map((f) => f.metadata?.candidate as string);
		expect(surfaced).not.toContain('opted-out.example.net');
	});
});
