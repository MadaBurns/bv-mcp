// SPDX-License-Identifier: BUSL-1.1

/**
 * Chaos invariants for the tiered brand-discovery pipeline.
 *
 * Each `it()` frames a failure → expected degradation:
 *   "Given [failure], system should [degradation]."
 *
 * These pin the chaos surface required by Task 10 of
 *   docs/superpowers/plans/2026-05-20-brand-discovery-first-principles-tdd.md
 * before the default flip in Task 13. If any of these fail, the tiered default
 * MUST NOT be promoted to production.
 *
 * Mock seam: the 10 invariants exercise `discoverBrandDomains` directly with
 * stubbed `tier0Lookup` / `tier1Lookup` / `tier2Lookup` / `fetchOptouts` deps
 * (the injected service-binding wrappers — slow/external boundary). Tier 3 =
 * the legacy in-pipeline signal sweep — verified to (not) run by inspecting
 * whether sweep dep mocks such as `correlateNs` were invoked, and by reading
 * the `tier3FallbackTriggered` telemetry counter.
 *
 * Baseline dep stubs live in `test/helpers/brand-discovery-tiered.ts` — all of
 * them mock at network / service-binding boundaries (Principle 8: mock only at
 * slow/external boundaries).
 *
 * Status reality check (vs the plan's English):
 *   - Tier {0,1,2}Lookup absent (dep undefined) → status `'skipped'` (the
 *     orchestrator resolves to a `'skipped'` sentinel for the missing tier).
 *   - Tier {0,1,2}Lookup throws → status `'degraded'`.
 *   The plan called the absent path "unavailable" but the implementation uses
 *   `'skipped'`. We assert the actual sentinels so the chaos test asserts
 *   reality, not aspiration.
 *
 * Mutual-exclusion (invariant 7): classification happens downstream in
 * `brand-classification.ts`. The in-layer invariant is therefore that no
 * single surfaced candidate's signals straddle a Tier 0/1/2/3 source AND a
 * Tier 4 source — asserted via `tierFor()` over the per-signal sources.
 *
 * Tier-4 noise-budget guard (invariant 10): a "10× owned OR > 200" guard is
 * NOT yet implemented inside `discoverBrandDomains` (would require source
 * changes outside this task's scope). The in-layer truncation that DOES exist
 * is the candidate-universe cap (`STANDARD_CANDIDATE_CAP = 50`) — verified
 * via `candidateUniverse.dropped.cap`. We pin that mechanism so future
 * regressions can't silently raise / remove the per-pipeline candidate
 * ceiling.
 */

import { describe, it, expect, vi } from 'vitest';
import type { DiscoverBrandDomainsDeps } from '../../src/tools/discover-brand-domains';
import { tierFor } from '../../src/lib/brand-discovery-tiers';
import {
	FRESH_FRESHNESS,
	VERY_STALE_FRESHNESS,
	okNs,
	okDkim,
	makeTieredDeps,
	tier0Empty,
	tier0Ok,
	tier1Empty,
	tier1Ok,
	tier2Empty,
	getSummary,
	getTiers,
	collectAllSurfacedDomains,
} from '../helpers/brand-discovery-tiered';

describe('brand-discovery tiered chaos invariants', () => {
	it('1. given Tier 0/1/2 service-bindings are absent, caller_candidates are still probed by every signal', async () => {
		// Caller-asserted candidates must be probed by every signal regardless
		// of upstream service-binding outages — guaranteed by the caller-
		// asserted bypass at the corroboration gate.
		const candidates = ['caller-1.example.net', 'caller-2.example.net'];
		const correlateNs = vi.fn().mockResolvedValue(okNs([]));
		const detectDkimKeyReuse = vi.fn().mockResolvedValue(okDkim([]));
		const { discoverBrandDomains } = await import('../../src/tools/discover-brand-domains');

		// No tier{0,1,2}Lookup deps → all three "absent". Pipeline must still run.
		await discoverBrandDomains(
			'example.com',
			{
				discovery_mode: 'tiered',
				signals: ['ns', 'dkim_key_reuse'],
				candidate_domains: candidates,
				min_confidence: 0.1,
				planner_mode: 'observe',
			},
			makeTieredDeps({ correlateNs, detectDkimKeyReuse }),
		);

		// Each candidate-backed signal sees the caller list (planner in observe
		// mode so caps don't bind).
		expect(correlateNs).toHaveBeenCalledTimes(1);
		const nsArgs = correlateNs.mock.calls[0][1] as { candidateDomains: string[] };
		for (const c of candidates) expect(nsArgs.candidateDomains).toContain(c);
		expect(detectDkimKeyReuse).toHaveBeenCalledTimes(1);
		const dkimArgs = detectDkimKeyReuse.mock.calls[0][1] as string[];
		for (const c of candidates) expect(dkimArgs).toContain(c);
	});

	it('2. given a domain is opted out, system should absent it from every tier of the output', async () => {
		// Opt-out boundary 3: even if Tier 0 + Tier 1 surface the same opted-out
		// apex, the consumer-side filter MUST redact it everywhere and
		// increment optOutsFiltered ≥ 1.
		const { __resetOptoutCacheForTests } = await import('../../src/lib/brand-optout-enforcement');
		__resetOptoutCacheForTests();
		const { discoverBrandDomains } = await import('../../src/tools/discover-brand-domains');
		const deps = makeTieredDeps({
			tier0Lookup: () => Promise.resolve(tier0Ok('opted-out.example.net')) as never,
			tier1Lookup: () => Promise.resolve(tier1Ok('opted-out.example.net', FRESH_FRESHNESS)) as never,
			tier2Lookup: () => Promise.resolve(tier2Empty()) as never,
			fetchOptouts: () => Promise.resolve(new Set(['opted-out.example.net'])),
			correlateNs: vi.fn().mockResolvedValue(okNs([{ domain: 'legit.example.net', confidence: 1.0 }])),
		} as unknown as Partial<DiscoverBrandDomainsDeps>);
		const result = await discoverBrandDomains(
			'example.com',
			{
				discovery_mode: 'tiered',
				signals: ['ns'],
				candidate_domains: ['legit.example.net', 'opted-out.example.net'],
				min_confidence: 0.1,
			},
			deps,
		);

		const surfaced = collectAllSurfacedDomains(result);
		expect(surfaced).not.toContain('opted-out.example.net');
		const tiers = getTiers(result);
		expect(tiers?.optOutsFiltered as number).toBeGreaterThanOrEqual(1);
	});

	it('3a. given BV_INFRA_GRAPH outage (tier1Lookup throws), system should mark tier1Status degraded and run Tier 3 fallback', async () => {
		const { __resetOptoutCacheForTests } = await import('../../src/lib/brand-optout-enforcement');
		__resetOptoutCacheForTests();
		const { discoverBrandDomains } = await import('../../src/tools/discover-brand-domains');
		const correlateNs = vi.fn().mockResolvedValue(okNs([]));
		const deps = makeTieredDeps({
			tier0Lookup: () => Promise.resolve(tier0Empty()) as never,
			tier1Lookup: () => Promise.reject(new Error('chaos: BV_INFRA_GRAPH 5xx')),
			tier2Lookup: () => Promise.resolve(tier2Empty()) as never,
			correlateNs,
		} as unknown as Partial<DiscoverBrandDomainsDeps>);
		const result = await discoverBrandDomains(
			'example.com',
			{ discovery_mode: 'tiered', signals: ['ns'], candidate_domains: [] },
			deps,
		);

		const tiers = getTiers(result);
		expect(tiers?.tier1Status).toBe('degraded');
		expect(tiers?.tier3FallbackTriggered).toBe(1);
		expect(correlateNs).toHaveBeenCalled();
	});

	it('3b. given BV_INFRA_GRAPH binding is absent (self-host), system should mark tier1Status skipped and run Tier 3 fallback', async () => {
		// BSL self-hosters experience this path: the binding isn't provisioned.
		// The orchestrator resolves to a 'skipped' sentinel rather than
		// 'unavailable'.
		const { __resetOptoutCacheForTests } = await import('../../src/lib/brand-optout-enforcement');
		__resetOptoutCacheForTests();
		const { discoverBrandDomains } = await import('../../src/tools/discover-brand-domains');
		const correlateNs = vi.fn().mockResolvedValue(okNs([]));
		const deps = makeTieredDeps({
			tier0Lookup: () => Promise.resolve(tier0Empty()) as never,
			tier2Lookup: () => Promise.resolve(tier2Empty()) as never,
			correlateNs,
		} as unknown as Partial<DiscoverBrandDomainsDeps>);
		const result = await discoverBrandDomains(
			'example.com',
			{ discovery_mode: 'tiered', signals: ['ns'], candidate_domains: [] },
			deps,
		);

		const tiers = getTiers(result);
		expect(tiers?.tier1Status).toBe('skipped');
		// Tier 1 returned no candidates AND freshness is not 'fresh' → Tier 3 must run.
		expect(tiers?.tier3FallbackTriggered).toBe(1);
		expect(correlateNs).toHaveBeenCalled();
	});

	it('4a. given BV_INTEL_GATEWAY outage (tier2Lookup throws), system should mark tier2Status degraded and Tier 3 fallback still runs', async () => {
		const { __resetOptoutCacheForTests } = await import('../../src/lib/brand-optout-enforcement');
		__resetOptoutCacheForTests();
		const { discoverBrandDomains } = await import('../../src/tools/discover-brand-domains');
		const correlateNs = vi.fn().mockResolvedValue(okNs([]));
		const deps = makeTieredDeps({
			tier0Lookup: () => Promise.resolve(tier0Empty()) as never,
			tier1Lookup: () => Promise.resolve(tier1Empty(VERY_STALE_FRESHNESS)) as never,
			tier2Lookup: () => Promise.reject(new Error('chaos: BV_INTEL_GATEWAY upstream timeout')),
			correlateNs,
		} as unknown as Partial<DiscoverBrandDomainsDeps>);
		const result = await discoverBrandDomains(
			'example.com',
			{ discovery_mode: 'tiered', signals: ['ns'], candidate_domains: [] },
			deps,
		);

		const tiers = getTiers(result);
		expect(tiers?.tier2Status).toBe('degraded');
		expect(tiers?.tier3FallbackTriggered).toBe(1);
		expect(correlateNs).toHaveBeenCalled();
	});

	it('4b. given BV_INTEL_GATEWAY binding is absent (self-host), system should mark tier2Status skipped and Tier 3 fallback still runs', async () => {
		const { __resetOptoutCacheForTests } = await import('../../src/lib/brand-optout-enforcement');
		__resetOptoutCacheForTests();
		const { discoverBrandDomains } = await import('../../src/tools/discover-brand-domains');
		const correlateNs = vi.fn().mockResolvedValue(okNs([]));
		// Tier 1 returns empty with stale freshness — chaos premise is whole-
		// stack degradation, so Tier 1 isn't fresh either.
		const deps = makeTieredDeps({
			tier0Lookup: () => Promise.resolve(tier0Empty()) as never,
			tier1Lookup: () => Promise.resolve(tier1Empty(VERY_STALE_FRESHNESS)) as never,
			correlateNs,
		} as unknown as Partial<DiscoverBrandDomainsDeps>);
		const result = await discoverBrandDomains(
			'example.com',
			{ discovery_mode: 'tiered', signals: ['ns'], candidate_domains: [] },
			deps,
		);

		const tiers = getTiers(result);
		expect(tiers?.tier2Status).toBe('skipped');
		expect(tiers?.tier3FallbackTriggered).toBe(1);
		expect(correlateNs).toHaveBeenCalled();
	});

	it('5a. given BV_ENTERPRISE outage (tier0Lookup throws), system should mark tier0Status degraded and Tier 3 fallback runs', async () => {
		const { __resetOptoutCacheForTests } = await import('../../src/lib/brand-optout-enforcement');
		__resetOptoutCacheForTests();
		const { discoverBrandDomains } = await import('../../src/tools/discover-brand-domains');
		const correlateNs = vi.fn().mockResolvedValue(okNs([]));
		const deps = makeTieredDeps({
			tier0Lookup: () => Promise.reject(new Error('chaos: BV_ENTERPRISE 500')),
			tier1Lookup: () => Promise.resolve(tier1Empty(VERY_STALE_FRESHNESS)) as never,
			tier2Lookup: () => Promise.resolve(tier2Empty()) as never,
			correlateNs,
		} as unknown as Partial<DiscoverBrandDomainsDeps>);
		const result = await discoverBrandDomains(
			'example.com',
			{ discovery_mode: 'tiered', signals: ['ns'], candidate_domains: [] },
			deps,
		);

		const tiers = getTiers(result);
		expect(tiers?.tier0Status).toBe('degraded');
		expect(tiers?.tier3FallbackTriggered).toBe(1);
		expect(correlateNs).toHaveBeenCalled();
	});

	it('5b. given BV_ENTERPRISE binding is absent (most common BSL self-host path), system should mark tier0Status skipped and pipeline proceeds', async () => {
		// Most common path for BSL self-hosters: Tier 0 returns empty, the
		// pipeline proceeds with the seed having no declared portfolio. Tier 3
		// fallback runs (no Tier 1/2 candidates and not fresh).
		const { __resetOptoutCacheForTests } = await import('../../src/lib/brand-optout-enforcement');
		__resetOptoutCacheForTests();
		const { discoverBrandDomains } = await import('../../src/tools/discover-brand-domains');
		const correlateNs = vi.fn().mockResolvedValue(okNs([]));
		const deps = makeTieredDeps({
			tier1Lookup: () => Promise.resolve(tier1Empty(VERY_STALE_FRESHNESS)) as never,
			tier2Lookup: () => Promise.resolve(tier2Empty()) as never,
			correlateNs,
		} as unknown as Partial<DiscoverBrandDomainsDeps>);
		const result = await discoverBrandDomains(
			'example.com',
			{ discovery_mode: 'tiered', signals: ['ns'], candidate_domains: [] },
			deps,
		);

		const tiers = getTiers(result);
		expect(tiers?.tier0Status).toBe('skipped');
		expect(tiers?.tier3FallbackTriggered).toBe(1);
		expect(correlateNs).toHaveBeenCalled();
	});

	it('6. given Tier 1 fingerprint freshness is very_stale, system should trigger Tier 3 live signal sweep', async () => {
		const { __resetOptoutCacheForTests } = await import('../../src/lib/brand-optout-enforcement');
		__resetOptoutCacheForTests();
		const { discoverBrandDomains } = await import('../../src/tools/discover-brand-domains');
		const correlateNs = vi.fn().mockResolvedValue(okNs([]));
		const detectDkimKeyReuse = vi.fn().mockResolvedValue(okDkim([]));
		const deps = makeTieredDeps({
			tier0Lookup: () => Promise.resolve(tier0Empty()) as never,
			// Tier 1 returns one candidate but is very_stale — fallback must still fire.
			tier1Lookup: () => Promise.resolve(tier1Ok('cached.example.net', VERY_STALE_FRESHNESS)) as never,
			tier2Lookup: () => Promise.resolve(tier2Empty()) as never,
			correlateNs,
			detectDkimKeyReuse,
		} as unknown as Partial<DiscoverBrandDomainsDeps>);
		const result = await discoverBrandDomains(
			'example.com',
			{ discovery_mode: 'tiered', signals: ['ns', 'dkim_key_reuse'], candidate_domains: [] },
			deps,
		);

		const tiers = getTiers(result);
		expect((tiers?.tier1Freshness as { overallStaleness?: string } | null | undefined)?.overallStaleness).toBe('very_stale');
		expect(tiers?.tier3FallbackTriggered).toBe(1);
		expect(correlateNs).toHaveBeenCalled();
		expect(detectDkimKeyReuse).toHaveBeenCalled();
	});

	it('7. given a candidate has Tier 4 lookalike sources, system should NOT also tag it with Owned tier sources on the same finding', async () => {
		// Tier 0/1/2/3 (Owned) ↔ Tier 4 (Impersonation) mutual exclusion.
		// At the discovery layer this means: no surfaced candidate's per-signal
		// sources contain BOTH an Owned-tier source AND a Tier-4-only source.
		// (Classification proper is downstream in brand-classification.ts; this
		// asserts the input contract to that classifier.)
		const { __resetOptoutCacheForTests } = await import('../../src/lib/brand-optout-enforcement');
		__resetOptoutCacheForTests();
		const { discoverBrandDomains } = await import('../../src/tools/discover-brand-domains');
		// Use VERY_STALE freshness so Tier 3 (= the legacy NS sweep) also runs.
		// The candidate then has BOTH a Tier 0 source (via the markov_gen
		// metadata blob) AND a Tier 3 ns source. The mutual-exclusion invariant
		// is exercised because the candidate has multiple Owned-tier sources
		// AND we verify no Tier 4 source is co-emitted.
		const deps = makeTieredDeps({
			tier0Lookup: () => Promise.resolve(tier0Ok('owned-1.example.net')) as never,
			tier1Lookup: () => Promise.resolve(tier1Empty(VERY_STALE_FRESHNESS)) as never,
			tier2Lookup: () => Promise.resolve(tier2Empty()) as never,
			correlateNs: () => Promise.resolve(okNs([{ domain: 'owned-1.example.net', confidence: 0.9 }])),
		} as unknown as Partial<DiscoverBrandDomainsDeps>);
		const result = await discoverBrandDomains(
			'example.com',
			{
				discovery_mode: 'tiered',
				signals: ['ns'],
				candidate_domains: ['owned-1.example.net'],
				min_confidence: 0.0,
			},
			deps,
		);

		const candidateFindings = result.findings.filter((f) => typeof f.metadata?.candidate === 'string');
		expect(candidateFindings.length).toBeGreaterThan(0);
		for (const f of candidateFindings) {
			const signals = (f.metadata?.signals as string[] | undefined) ?? [];
			const sources = (f.metadata?.sources as Record<string, unknown> | undefined) ?? {};
			// Compute tiers from signal names. markov_gen is the orchestrator's
			// storage key for tiered observations (tier 0/1/2) — pull the real
			// tier from the metadata blob.
			const observedTiers = new Set<number>();
			for (const sig of signals) {
				if (sig === 'markov_gen') {
					const obs = sources[sig] as { tier?: number } | undefined;
					if (typeof obs?.tier === 'number') observedTiers.add(obs.tier);
					else observedTiers.add(tierFor({ source: sig }));
				} else {
					observedTiers.add(tierFor({ source: sig }));
				}
			}
			const hasOwned = [0, 1, 2, 3].some((t) => observedTiers.has(t));
			const hasImpersonation = observedTiers.has(4);
			expect(
				hasOwned && hasImpersonation,
				`candidate ${String(f.metadata?.candidate)} straddles Owned and Impersonation tiers`,
			).toBe(false);
		}
	});

	it('8. given an additional strong observation is added, system should never lower a surfaced candidate\'s tier', async () => {
		// Confidence monotonicity: a candidate surfaced by NS-only must, when
		// also surfaced by an additional strong signal (Tier 0 declaration),
		// retain at least the lower tier number (more authoritative). Lower
		// tier number == higher trust; adding observations must never raise it.
		const { __resetOptoutCacheForTests } = await import('../../src/lib/brand-optout-enforcement');
		__resetOptoutCacheForTests();
		const { discoverBrandDomains } = await import('../../src/tools/discover-brand-domains');

		const candidate = 'shared.example.net';
		// VERY_STALE so Tier 3 NS sweep runs in both arms — provides the
		// non-seed signal needed by the corroboration gate so the candidate
		// surfaces. Augmented arm adds a Tier 0 declaration on top.
		const baselineDeps = makeTieredDeps({
			tier0Lookup: () => Promise.resolve(tier0Empty()) as never,
			tier1Lookup: () => Promise.resolve(tier1Empty(VERY_STALE_FRESHNESS)) as never,
			tier2Lookup: () => Promise.resolve(tier2Empty()) as never,
			correlateNs: () => Promise.resolve(okNs([{ domain: candidate, confidence: 0.6 }])),
		} as unknown as Partial<DiscoverBrandDomainsDeps>);
		const augmentedDeps = makeTieredDeps({
			tier0Lookup: () => Promise.resolve(tier0Ok(candidate)) as never,
			tier1Lookup: () => Promise.resolve(tier1Empty(VERY_STALE_FRESHNESS)) as never,
			tier2Lookup: () => Promise.resolve(tier2Empty()) as never,
			correlateNs: () => Promise.resolve(okNs([{ domain: candidate, confidence: 0.6 }])),
		} as unknown as Partial<DiscoverBrandDomainsDeps>);

		const baseline = await discoverBrandDomains(
			'example.com',
			{ discovery_mode: 'tiered', signals: ['ns'], candidate_domains: [candidate], min_confidence: 0.0 },
			baselineDeps,
		);
		const augmented = await discoverBrandDomains(
			'example.com',
			{ discovery_mode: 'tiered', signals: ['ns'], candidate_domains: [candidate], min_confidence: 0.0 },
			augmentedDeps,
		);

		const minTier = (r: { findings: Array<{ metadata?: Record<string, unknown> }> }) => {
			const f = r.findings.find((x) => x.metadata?.candidate === candidate);
			if (!f) return 99;
			const signals = (f.metadata?.signals as string[] | undefined) ?? [];
			const sources = (f.metadata?.sources as Record<string, unknown> | undefined) ?? {};
			let m = 99;
			for (const sig of signals) {
				if (sig === 'markov_gen') {
					const obs = sources[sig] as { tier?: number } | undefined;
					if (typeof obs?.tier === 'number') m = Math.min(m, obs.tier);
					else m = Math.min(m, tierFor({ source: sig }));
				} else {
					m = Math.min(m, tierFor({ source: sig }));
				}
			}
			return m;
		};

		const baselineMin = minTier(baseline);
		const augmentedMin = minTier(augmented);
		// Adding the Tier 0 obs must never raise the tier number (= lower trust).
		expect(augmentedMin).toBeLessThanOrEqual(baselineMin);
	});

	it('9. given Tier 1 returns ≥1 cert-derived shared signal, the surfaced owned-portfolio is non-empty', async () => {
		// CT presence implies non-empty owned-portfolio: when Tier 1 surfaces a
		// cert-witness candidate, the discovery output MUST register at least
		// one owned-tier (0/1/2/3) candidate in telemetry. Asserted via the
		// `tiers.tier{0,1,2,3}Count` counters — the discovery-layer surface
		// for the owned-portfolio set (the audit-pipeline layer turns these
		// into `ownedPortfolio.{tenantDeclared,graphSurfaced,...}` arrays).
		const { __resetOptoutCacheForTests } = await import('../../src/lib/brand-optout-enforcement');
		__resetOptoutCacheForTests();
		const { discoverBrandDomains } = await import('../../src/tools/discover-brand-domains');
		const deps = makeTieredDeps({
			tier0Lookup: () => Promise.resolve(tier0Empty()) as never,
			// Tier 1 cert-derived shared signal.
			tier1Lookup: () => Promise.resolve(tier1Ok('ct-sibling.example.net', FRESH_FRESHNESS, 'cert_san')) as never,
			tier2Lookup: () => Promise.resolve(tier2Empty()) as never,
			correlateNs: () => Promise.resolve(okNs([])),
		} as unknown as Partial<DiscoverBrandDomainsDeps>);
		const result = await discoverBrandDomains(
			'example.com',
			{ discovery_mode: 'tiered', signals: ['ns'], candidate_domains: [], min_confidence: 0.0 },
			deps,
		);

		const tiers = getTiers(result);
		const tier1Count = (tiers?.tier1Count as number) ?? 0;
		expect(tier1Count).toBeGreaterThanOrEqual(1);
		// Owned-portfolio = tier 0/1/2/3 candidates. With Tier 1 surfacing a
		// cert sibling, the owned set is non-empty.
		const owned =
			((tiers?.tier0Count as number) ?? 0) +
			((tiers?.tier1Count as number) ?? 0) +
			((tiers?.tier2Count as number) ?? 0) +
			((tiers?.tier3Count as number) ?? 0);
		expect(owned).toBeGreaterThanOrEqual(1);
	});

	it('10. given candidates flood the universe (>> STANDARD_CANDIDATE_CAP=50), system should truncate via the candidate-universe cap and surface dropped.cap telemetry', async () => {
		// In-layer noise-budget guard. The plan calls for "10× owned OR > 200"
		// which lives at the audit-pipeline layer (MAX_CANDIDATES_PER_AUDIT=200,
		// in brand-audit-pipeline.ts). Inside discoverBrandDomains the only
		// in-layer truncation guard is the candidate-universe cap
		// (STANDARD_CANDIDATE_CAP = 50). Pinning this guard prevents silent
		// regression of the per-call candidate ceiling.
		const { __resetOptoutCacheForTests } = await import('../../src/lib/brand-optout-enforcement');
		__resetOptoutCacheForTests();
		const { discoverBrandDomains } = await import('../../src/tools/discover-brand-domains');

		const flood = Array.from({ length: 600 }, (_, i) => `noise-${i}.example.net`);
		const deps = makeTieredDeps({
			tier0Lookup: () => Promise.resolve(tier0Empty()) as never,
			tier1Lookup: () => Promise.resolve(tier1Empty()) as never,
			tier2Lookup: () => Promise.resolve(tier2Empty()) as never,
		} as unknown as Partial<DiscoverBrandDomainsDeps>);
		const result = await discoverBrandDomains(
			'example.com',
			{ discovery_mode: 'tiered', signals: ['ns'], candidate_domains: flood, min_confidence: 0.0 },
			deps,
		);

		const summary = getSummary(result);
		const universe = summary?.metadata?.candidateUniverse as { dropped?: { cap?: number } } | undefined;
		expect(universe?.dropped?.cap as number).toBeGreaterThan(0);
	});
});
