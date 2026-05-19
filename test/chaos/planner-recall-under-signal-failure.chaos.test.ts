// SPDX-License-Identifier: BUSL-1.1

/**
 * Chaos hypothesis: promoting `planner_mode='enforce'` as the production
 * default is safe IFF it never surfaces a strictly smaller candidate set than
 * `observe` mode under any single candidate-backed signal failure.
 *
 * The planner only changes which candidates each signal probes (it never
 * changes which signals run, nor the aggregator's surfacing threshold). If
 * the empirical asymmetry from the production benchmarks holds — high-yield
 * signals (ns/mx_platform/spf_include) stay at full coverage; low-yield
 * signals (dkim_key_reuse/mx_overlap/txt_verification/cname_alignment) are
 * capped — then enforce-mode recall under failure should always be ≥
 * observe-mode recall, because:
 *   1. When a low-yield signal fails: observe and enforce both lose every
 *      observation from it. Enforce probed a subset; observe probed the full
 *      universe. Either way, zero observations make it through.
 *   2. When a high-yield signal fails: same input set under both modes
 *      (caps are non-binding), so identical degradation.
 *   3. Caller-asserted candidates are guarded — they bypass caps in enforce
 *      mode, so callers naming high-trust domains can never be silently
 *      starved by the planner.
 *
 * These three tests inject those failures and assert no enforce-specific
 * recall gap. If any fail, do NOT promote enforce-default.
 */

import { describe, it, expect, vi } from 'vitest';
import type { NsCorrelationResult, DkimKeyReuseResult } from '../../src/tenants/discovery';
import type { DiscoverBrandDomainsDeps } from '../../src/tools/discover-brand-domains';

function okNs(domains: Array<{ domain: string; confidence: number }>): NsCorrelationResult {
	return {
		seedDomain: 'example.com',
		seedNs: ['ns1.example.com'],
		coOwnedDomains: domains.map((d) => ({ domain: d.domain, sharedNs: ['ns1.example.com'], confidence: d.confidence })),
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

// Minimal deps: the orchestrator only calls signal modules listed in the
// `signals` option, so a partial cast keeps the mock surface tight and the
// chaos contract obvious. Each test injects only the signals it exercises.
function minimalDeps(overrides: Partial<DiscoverBrandDomainsDeps>): DiscoverBrandDomainsDeps {
	return overrides as DiscoverBrandDomainsDeps;
}

function surfacedDomains(result: { findings: Array<{ metadata?: Record<string, unknown> }> }): Set<string> {
	const out = new Set<string>();
	for (const f of result.findings) {
		const candidate = f.metadata?.candidate;
		if (typeof candidate === 'string') out.add(candidate);
	}
	return out;
}

describe('chaos: planner enforce-mode recall under signal failure', () => {
	it('GIVEN a low-yield signal (dkim_key_reuse) throws, WHEN observe and enforce run on the same input, THEN enforce surfaces a superset of observe', async () => {
		// Two candidates surface via ns corroboration (high-yield) regardless of
		// dkim status. dkim_key_reuse throws under both modes. Enforce-mode
		// recall must not drop below observe-mode recall.
		const corroborated = ['shop.example.net', 'pay.example.net'];
		const candidate_domains = [...corroborated, 'noise-1.example.net', 'noise-2.example.net'];

		const buildDeps = () =>
			minimalDeps({
				correlateNs: vi.fn().mockResolvedValue(okNs(corroborated.map((d) => ({ domain: d, confidence: 1 })))),
				detectDkimKeyReuse: vi.fn().mockRejectedValue(new Error('chaos: dkim path down')),
			});

		const { discoverBrandDomains } = await import('../../src/tools/discover-brand-domains');
		const observe = await discoverBrandDomains(
			'example.com',
			{ signals: ['ns', 'dkim_key_reuse'], candidate_domains, min_confidence: 0.1, planner_mode: 'observe' },
			buildDeps(),
		);
		const enforce = await discoverBrandDomains(
			'example.com',
			{ signals: ['ns', 'dkim_key_reuse'], candidate_domains, min_confidence: 0.1, planner_mode: 'enforce' },
			buildDeps(),
		);

		const observeSet = surfacedDomains(observe);
		const enforceSet = surfacedDomains(enforce);
		for (const d of observeSet) expect(enforceSet).toContain(d);
		expect(enforceSet.size).toBeGreaterThanOrEqual(observeSet.size);
		expect(observeSet.has('shop.example.net')).toBe(true);
		expect(observeSet.has('pay.example.net')).toBe(true);
		expect(enforceSet.has('shop.example.net')).toBe(true);
		expect(enforceSet.has('pay.example.net')).toBe(true);
		// Noise candidates without ns corroboration must NOT surface in either mode.
		expect(enforceSet.has('noise-1.example.net')).toBe(false);
		expect(enforceSet.has('noise-2.example.net')).toBe(false);
		// Per-mode efficiency telemetry differentiates the modes even under failure.
		const observePlanner = (observe.findings.find((f) => f.metadata?.summary === true)?.metadata
			?.discoveryPerformance as { efficiency?: { plannerMode?: string } } | undefined)?.efficiency?.plannerMode;
		const enforcePlanner = (enforce.findings.find((f) => f.metadata?.summary === true)?.metadata
			?.discoveryPerformance as { efficiency?: { plannerMode?: string } } | undefined)?.efficiency?.plannerMode;
		expect(observePlanner).toBe('observe');
		expect(enforcePlanner).toBe('enforce');
	});

	it('GIVEN a high-yield signal (ns) throws, WHEN observe and enforce run on the same input, THEN both degrade identically (no enforce-specific gap)', async () => {
		// ns is the dominant surfacing signal in production. Under ns failure,
		// observe and enforce both lose all ns observations. dkim_key_reuse
		// remains available and corroborates the same candidates in both modes.
		const corroborated = ['shop.example.net', 'pay.example.net'];
		const candidate_domains = [...corroborated, 'noise-1.example.net', 'noise-2.example.net'];

		const buildDeps = () =>
			minimalDeps({
				correlateNs: vi.fn().mockRejectedValue(new Error('chaos: ns DNS path timing out')),
				detectDkimKeyReuse: vi.fn().mockResolvedValue(okDkim(corroborated)),
			});

		const { discoverBrandDomains } = await import('../../src/tools/discover-brand-domains');
		const observe = await discoverBrandDomains(
			'example.com',
			{ signals: ['ns', 'dkim_key_reuse'], candidate_domains, min_confidence: 0.1, planner_mode: 'observe' },
			buildDeps(),
		);
		const enforce = await discoverBrandDomains(
			'example.com',
			{ signals: ['ns', 'dkim_key_reuse'], candidate_domains, min_confidence: 0.1, planner_mode: 'enforce' },
			buildDeps(),
		);

		expect(surfacedDomains(enforce)).toEqual(surfacedDomains(observe));
	});

	it('GIVEN aggressively low caller-supplied caps under dkim failure, WHEN enforce probes guarded subset only, THEN caller-asserted candidates still surface via the surviving signal', async () => {
		// Worst-case planner pressure: cap dkim to 1 while supplying 5 candidates.
		// All 5 are caller_candidate-sourced → guarded → bypass cap regardless.
		// dkim throws. ns corroborates the first three. Enforce must surface
		// exactly those three, like observe would.
		const corroborated = ['a.example.net', 'b.example.net', 'c.example.net'];
		const candidate_domains = [...corroborated, 'd.example.net', 'e.example.net'];

		const buildDeps = () =>
			minimalDeps({
				correlateNs: vi.fn().mockResolvedValue(okNs(corroborated.map((d) => ({ domain: d, confidence: 1 })))),
				detectDkimKeyReuse: vi.fn().mockRejectedValue(new Error('chaos: dkim path down')),
			});

		const { discoverBrandDomains } = await import('../../src/tools/discover-brand-domains');
		const enforce = await discoverBrandDomains(
			'example.com',
			{
				signals: ['ns', 'dkim_key_reuse'],
				candidate_domains,
				min_confidence: 0.1,
				planner_mode: 'enforce',
				planner_caps: { dkim_key_reuse: 1, ns: 1 },
			},
			buildDeps(),
		);

		const enforceSet = surfacedDomains(enforce);
		for (const d of corroborated) expect(enforceSet).toContain(d);
	});
});
