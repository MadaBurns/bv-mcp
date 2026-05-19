// SPDX-License-Identifier: BUSL-1.1

/**
 * Audit: cross-pipeline invariant — no domain on the `gsi_domain_optouts`
 * list may appear in a brand-discovery surface, regardless of the tier (0/1/2/4)
 * at which the candidate was harvested.
 *
 * This is the third defensive layer. `bv-infrastructure-graph` and
 * `bv-intel-gateway` both filter source-side, but if either misses an
 * opt-out, the consumer-side filter in `src/lib/brand-optout-enforcement.ts`
 * must redact before bv-mcp surfaces.
 *
 * The fixture is synthetic — one opted-out apex per tier — and lives in
 * the test itself. We do not embed real opt-out domains here.
 *
 * Layer: Audit (cross-pipeline invariant).
 */

import { describe, expect, it } from 'vitest';

import { __resetOptoutCacheForTests, applyOptoutFilter } from '../../src/lib/brand-optout-enforcement';

/** Synthetic candidates labelled by their discovery tier. */
interface TieredCandidate {
	readonly apex: string;
	readonly tier: 0 | 1 | 2 | 4;
}

describe('brand discovery: consumer-side opt-out enforcement (cross-pipeline invariant)', () => {
	it('redacts a synthetic opt-out at every tier (0, 1, 2, 4) before surfacing', async () => {
		__resetOptoutCacheForTests();

		const fixture: readonly TieredCandidate[] = [
			// Tier 0 — seed apex.
			{ apex: 'tier0-seed.example', tier: 0 },
			{ apex: 'tier0-optout.example', tier: 0 },
			// Tier 1 — directly corroborated.
			{ apex: 'tier1-corroborated.example', tier: 1 },
			{ apex: 'tier1-optout.example', tier: 1 },
			// Tier 2 — single high-confidence signal.
			{ apex: 'tier2-single-signal.example', tier: 2 },
			{ apex: 'tier2-optout.example', tier: 2 },
			// Tier 4 — speculative.
			{ apex: 'tier4-speculative.example', tier: 4 },
			{ apex: 'tier4-optout.example', tier: 4 },
		];

		const optoutSet = new Set<string>([
			'tier0-optout.example',
			'tier1-optout.example',
			'tier2-optout.example',
			'tier4-optout.example',
		]);

		const result = await applyOptoutFilter(
			fixture.map((c) => c.apex),
			async () => optoutSet,
		);

		// Invariant 1: no opted-out apex survives, regardless of tier.
		for (const opted of optoutSet) {
			expect(result.filtered).not.toContain(opted);
		}

		// Invariant 2: every non-opted apex is preserved.
		const expectedSurvivors = fixture.filter((c) => !optoutSet.has(c.apex)).map((c) => c.apex);
		expect(result.filtered).toEqual(expectedSurvivors);

		// Invariant 3: redacted count equals the number of opt-outs in the fixture
		// (one per tier).
		expect(result.redactedCount).toBe(optoutSet.size);
	});

	it('redacts opt-outs that arrive with case or whitespace drift across tiers', async () => {
		__resetOptoutCacheForTests();

		// Same one-opt-out-per-tier fixture, but with intentional casing /
		// whitespace drift to confirm the audit invariant survives upstream
		// normalisation gaps.
		const candidates = [
			'Tier0-Optout.Example',
			'  tier1-OPTOUT.example',
			'TIER2-optout.example  ',
			'tier4-Optout.EXAMPLE',
			'kept-apex.example',
		];
		const optoutSet = new Set<string>([
			'tier0-optout.example',
			'tier1-optout.example',
			'tier2-optout.example',
			'tier4-optout.example',
		]);

		const result = await applyOptoutFilter(candidates, async () => optoutSet);

		expect(result.filtered).toEqual(['kept-apex.example']);
		expect(result.redactedCount).toBe(4);
	});

	it('redacts opt-outs that arrive with FQDN trailing-dot drift across tiers', async () => {
		__resetOptoutCacheForTests();

		// DNS-derived candidates routinely arrive as FQDNs with a trailing dot
		// (e.g. `example.com.`), while `gsi_domain_optouts` stores apex form
		// without the trailing dot. The audit invariant must hold across this
		// drift, regardless of which side carries the dot.
		const candidates = [
			'tier0-optout.example.', // candidate-side trailing dot
			'tier1-optout.example.', // candidate-side trailing dot
			'tier2-optout.example', // no drift
			'tier4-optout.example', // opt-out set side carries trailing dot
			'kept-apex.example',
		];
		const optoutSet = new Set<string>([
			'tier0-optout.example',
			'tier1-optout.example',
			'tier2-optout.example',
			'tier4-optout.example.', // opt-out set side carries trailing dot
		]);

		const result = await applyOptoutFilter(candidates, async () => optoutSet);

		expect(result.filtered).toEqual(['kept-apex.example']);
		expect(result.redactedCount).toBe(4);
	});
});
