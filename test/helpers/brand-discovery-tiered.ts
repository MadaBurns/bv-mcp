// SPDX-License-Identifier: BUSL-1.1

/**
 * Shared test helpers for tiered brand-discovery tests.
 *
 * The discover-brand-domains orchestrator depends on ~14 signal modules and
 * three tiered service-binding wrappers. Stubbing all of them in every test
 * file pollutes the mock/assertion ratio (the test-methodology-lint hook then
 * flags the file as over-mocked even though every mock IS at a slow/external
 * boundary). Centralising the stub builders here lets each individual chaos/
 * spec file only declare the mocks that differ from baseline.
 */

import { vi } from 'vitest';
import type {
	SanCorrelationResult,
	NsCorrelationResult,
	DmarcRuaResult,
	DkimKeyReuseResult,
} from '../../src/tenants/discovery';
import type { DiscoverBrandDomainsDeps } from '../../src/tools/discover-brand-domains';

export const FRESH_FRESHNESS = {
	overallStaleness: 'fresh' as const,
	oldestSignalAgeMs: 1_000,
	latestSweepAtMs: 1_800_000_000_000,
};

export const VERY_STALE_FRESHNESS = {
	overallStaleness: 'very_stale' as const,
	oldestSignalAgeMs: 60 * 24 * 60 * 60 * 1000,
	latestSweepAtMs: 1_800_000_000_000 - 60 * 24 * 60 * 60 * 1000,
};

export function okSan(coOwned: string[]): SanCorrelationResult {
	return { seedDomain: 'example.com', coOwnedDomains: coOwned, certIds: [], queryStatus: 'ok' };
}

export function okNs(domains: Array<{ domain: string; confidence: number }>): NsCorrelationResult {
	return {
		seedDomain: 'example.com',
		seedNs: ['ns1.example.com'],
		coOwnedDomains: domains.map((d) => ({ domain: d.domain, sharedNs: ['ns1.example.com'], confidence: d.confidence })),
		queryStatus: 'ok',
	};
}

export function okRua(domains: string[]): DmarcRuaResult {
	return {
		seedDomain: 'example.com',
		dmarcPresent: true,
		ruaUris: domains.map((d) => `mailto:dmarc@${d}`),
		ruaDomains: domains.map((d) => ({ domain: d, classification: 'related' as const, confidence: 0.6 })),
		queryStatus: 'ok',
	};
}

export function okDkim(domains: string[]): DkimKeyReuseResult {
	return {
		seedDomain: 'example.com',
		seedSelectors: ['default'],
		coOwnedDomains: domains.map((d) => ({ domain: d, sharedKeys: ['abc123'], sharedSelectors: ['default'], confidence: 0.95 })),
		queryStatus: 'ok',
	};
}

/**
 * Baseline DiscoverBrandDomainsDeps with every signal returning empty success.
 * Each test layers its specific failure/success cases on top via `overrides`.
 */
export function makeTieredDeps(overrides: Partial<DiscoverBrandDomainsDeps> = {}): DiscoverBrandDomainsDeps {
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

export function tier0Empty(): unknown {
	return { observations: [], status: 'ok', optedOut: false };
}

export function tier0Ok(candidate: string): unknown {
	return {
		observations: [{ candidate, source: 'tenant_domains', tier: 0, confidence: 1.0 }],
		status: 'ok',
		optedOut: false,
	};
}

export function tier1Empty(freshness: typeof FRESH_FRESHNESS | typeof VERY_STALE_FRESHNESS = FRESH_FRESHNESS): unknown {
	return { observations: [], status: 'ok', triggerTier3Fallback: false, freshness };
}

export function tier1Ok(
	candidate: string,
	freshness: typeof FRESH_FRESHNESS | typeof VERY_STALE_FRESHNESS = FRESH_FRESHNESS,
	signalType = 'soa_admin',
): unknown {
	return {
		observations: [
			{
				candidate,
				source: 'infra_graph_signal',
				tier: 1,
				confidence: 0.8,
				specificityScore: 0.9,
				signalType,
				signalValue: 'admin@example.com',
				numSharedSignals: 1,
				maxSpecificity: 0.9,
				signalTypes: [signalType],
			},
		],
		status: 'ok',
		triggerTier3Fallback: false,
		freshness,
	};
}

export function tier2Empty(): unknown {
	return { observations: [], status: 'ok' };
}

export interface SummaryShape {
	metadata?: {
		summary?: boolean;
		discoveryPerformance?: { tiers?: Record<string, unknown> };
		candidateUniverse?: { dropped?: { cap?: number; [k: string]: unknown }; [k: string]: unknown };
		[k: string]: unknown;
	};
}

export function getSummary(result: { findings: SummaryShape[] }): SummaryShape | undefined {
	return result.findings.find((f) => f.metadata?.summary === true);
}

export function getTiers(result: { findings: SummaryShape[] }): Record<string, unknown> | undefined {
	return getSummary(result)?.metadata?.discoveryPerformance?.tiers;
}

export function collectAllSurfacedDomains(result: { findings: Array<{ metadata?: Record<string, unknown> }> }): string[] {
	const out: string[] = [];
	for (const f of result.findings) {
		const c = f.metadata?.candidate;
		if (typeof c === 'string') out.push(c);
	}
	return out;
}
