// SPDX-License-Identifier: BUSL-1.1

/**
 * Slice 1 — corroboration-gate precision tests.
 *
 * Pins the orchestrator's filtering of low-confidence single-signal candidates.
 * The current gate at src/tools/discover-brand-domains.ts only blocks
 * `markov_gen`-only candidates; this suite asserts the generalized rule:
 *
 *   A candidate must be corroborated by ≥2 distinct signals OR be a single
 *   signal of `dkim_key_reuse` (near-deterministic ownership evidence).
 *
 * Refs: LR-1 (single dmarc_rua), LR-2 (single ns on multi-tenant infra).
 */

import { describe, it, expect, vi } from 'vitest';
import type {
	SanCorrelationResult,
	NsCorrelationResult,
	DmarcRuaResult,
	DkimKeyReuseResult,
} from '../src/tenants/discovery';
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

describe('discoverBrandDomains — corroboration gate', () => {
	it('LR-1: filters a single-signal dmarc_rua candidate', async () => {
		// A `related` RUA addressee at confidence 0.6 currently surfaces alone.
		// Unknown third-party aggregators (e.g. sendgrid.net, mailgun.org) get
		// `classification: related` from the miner because they aren't in its
		// 6-entry processor allowlist — so without corroboration, they leak.
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		const deps = makeDeps({
			mineDmarcRua: vi.fn().mockResolvedValue(okRua(['unknown-aggregator.io'])),
		});
		const result = await discoverBrandDomains('example.com', { signals: ['dmarc_rua'] }, deps);
		const candidates = result.findings.filter((f) => f.metadata?.candidate);
		expect(candidates).toHaveLength(0);
	});

	it('LR-2: filters an unsolicited single-signal ns candidate even at confidence 1.0', async () => {
		// ns-correlator emits confidence = sharedNs.size / seedNs.size.
		// Two unrelated zones parked on identical NS pairs (parkingcrew,
		// sedoparking, shared GoDaddy / DreamHost NS) score 1.0 today. Without
		// corroboration that's a false-positive shadow IT finding.
		// "Unsolicited" = caller did NOT list the domain in candidate_domains;
		// caller-asserted ownership bypasses the gate (covered separately).
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		const deps = makeDeps({
			correlateNs: vi.fn().mockResolvedValue(okNs([{ domain: 'parked-elsewhere.com', confidence: 1.0 }])),
		});
		const result = await discoverBrandDomains(
			'example.com',
			{ signals: ['ns'] },
			deps,
		);
		const candidates = result.findings.filter((f) => f.metadata?.candidate);
		expect(candidates).toHaveLength(0);
	});

	it('filters generated lookalike seeds corroborated only by NS overlap', async () => {
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		const deps = makeDeps({
			generateMarkovLookalikes: vi.fn().mockReturnValue(['examp1e.com']),
			correlateNs: vi.fn().mockResolvedValue(okNs([{ domain: 'examp1e.com', confidence: 1.0 }])),
		});

		const result = await discoverBrandDomains(
			'example.com',
			{ signals: ['ns'] },
			deps,
		);

		const candidates = result.findings.filter((f) => f.metadata?.candidate);
		expect(candidates).toHaveLength(0);
		const universe = result.findings.find((f) => f.metadata?.summary)?.metadata?.candidateUniverse as
			| { dropped?: { corroborationGate?: number } }
			| undefined;
		expect(universe?.dropped?.corroborationGate).toBeGreaterThanOrEqual(1);
	});

	it('filters active lookalikes corroborated only by broad MX platform plus one NS signal', async () => {
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		const deps = makeDeps({
			generateMarkovLookalikes: vi.fn().mockReturnValue([]),
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
				coOwnedDomains: [{ domain: 'examp1e.com', sharedMxPlatform: 'm365', confidence: 0.55 }],
				queryStatus: 'ok' as const,
			}),
		});

		const result = await discoverBrandDomains(
			'example.com',
			{ signals: ['ns', 'mx_platform'], depth: 'deep', min_confidence: 0.1 },
			deps,
		);

		const candidates = result.findings.filter((f) => f.metadata?.candidate);
		expect(candidates).toHaveLength(0);
		const universe = result.findings.find((f) => f.metadata?.summary)?.metadata?.candidateUniverse as
			| { dropped?: { corroborationGate?: number } }
			| undefined;
		expect(universe?.dropped?.corroborationGate).toBeGreaterThanOrEqual(1);
	});

	it('caller-asserted single-signal ns candidate bypasses the corroboration gate', async () => {
		// candidate_domains is the operator saying "this is one of mine, please
		// confirm via signals." When NS confirms, that's enough corroboration
		// (the caller's listing IS the second source). This preserves real
		// brand-discovery for co-owned zones (e.g. brand.com + brand.io on the
		// same NS) that would otherwise be filtered by the LR-2 gate.
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		const deps = makeDeps({
			correlateNs: vi.fn().mockResolvedValue(okNs([{ domain: 'asserted-brand.io', confidence: 1.0 }])),
		});
		const result = await discoverBrandDomains(
			'example.com',
			{ signals: ['ns'], candidate_domains: ['asserted-brand.io'], min_confidence: 0.1 },
			deps,
		);
		const candidates = result.findings.filter((f) => f.metadata?.candidate);
		expect(candidates).toHaveLength(1);
		expect(candidates[0].metadata?.candidate).toBe('asserted-brand.io');
		expect(candidates[0].metadata?.signals).toEqual(['ns']);
	});

	it('surfaces a single-signal dkim_key_reuse candidate (near-deterministic exception)', async () => {
		// DKIM key reuse is near-deterministic ownership evidence — the
		// generalized gate preserves it as the single permitted single-signal
		// surface so this positive case must keep passing.
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		const deps = makeDeps({
			detectDkimKeyReuse: vi.fn().mockResolvedValue(okDkim(['sister.com'])),
		});
		const result = await discoverBrandDomains(
			'example.com',
			{ signals: ['dkim_key_reuse'], candidate_domains: ['sister.com'] },
			deps,
		);
		const candidates = result.findings.filter((f) => f.metadata?.candidate);
		expect(candidates).toHaveLength(1);
		expect(candidates[0].metadata?.candidate).toBe('sister.com');
		expect(candidates[0].metadata?.signals).toEqual(['dkim_key_reuse']);
	});

	it('surfaces a two-signal san+dmarc_rua corroborated candidate', async () => {
		// combined = 1 - (1-0.1)(1-0.6) = 0.64 — above default min_confidence
		// and corroborated by two distinct signals, so the gate must let it
		// through. This is the case the audit calls "corroborated evidence".
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		const deps = makeDeps({
			correlateSans: vi.fn().mockResolvedValue(okSan(['sibling.com'])),
			mineDmarcRua: vi.fn().mockResolvedValue(okRua(['sibling.com'])),
		});
		const result = await discoverBrandDomains(
			'example.com',
			{ signals: ['san', 'dmarc_rua'] },
			deps,
		);
		const candidates = result.findings.filter((f) => f.metadata?.candidate);
		expect(candidates).toHaveLength(1);
		expect(candidates[0].metadata?.candidate).toBe('sibling.com');
		expect(candidates[0].metadata?.combinedConfidence).toBeCloseTo(0.64, 2);
		expect((candidates[0].metadata?.signals as string[]).sort()).toEqual(['dmarc_rua', 'san']);
	});

	it('filters markov generation corroborated only by broad m365 MX platform', async () => {
		const { discoverBrandDomains } = await import('../src/tools/discover-brand-domains');
		const deps = makeDeps({
			generateMarkovLookalikes: vi.fn().mockReturnValue(['upps.com']),
			detectSharedMxPlatform: vi.fn().mockResolvedValue({
				seedDomain: 'example.com',
				coOwnedDomains: [{ domain: 'upps.com', sharedMxPlatform: 'm365', confidence: 0.55 }],
				queryStatus: 'ok' as const,
			}),
		});

		const result = await discoverBrandDomains('example.com', { signals: ['mx_platform'] }, deps);

		const candidates = result.findings.filter((f) => f.metadata?.candidate);
		expect(candidates).toHaveLength(0);
		const universe = result.findings.find((f) => f.metadata?.summary)?.metadata?.candidateUniverse as
			| { dropped?: { corroborationGate?: number } }
			| undefined;
		expect(universe?.dropped?.corroborationGate).toBeGreaterThanOrEqual(1);
	});
});
