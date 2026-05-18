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
import { createDiscoveryDnsContext } from '../src/tenants/discovery/dns-context';
import type { DiscoverBrandDomainsDeps } from '../src/tools/discover-brand-domains';

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
				signals: ['ns', 'txt_verification', 'mx_platform'],
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
