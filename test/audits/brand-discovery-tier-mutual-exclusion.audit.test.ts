// SPDX-License-Identifier: BUSL-1.1

/**
 * Audit: brand-discovery tier mutual-exclusion invariant.
 *
 * A domain may NOT appear in both an Owned bucket (Tier 0/1/2/3 →
 * `consolidated` / `shadowIt` / `indeterminate` / `impersonation`) AND the
 * Impersonation Surface bucket (`impersonationSurface`, Tier 4). The
 * classifier in `src/lib/brand-classification.ts` enforces this at the
 * single-domain level by routing tier 0/1/2 evidence to `consolidated`
 * BEFORE the only-tier-4 short-circuit. This audit pins the invariant
 * across a fixture spanning every tier combination.
 *
 * Layer: Audit (cross-output invariant on a fixture, beyond what a single
 * unit test in `brand-classification.test.ts` can express).
 *
 * Plan: docs/superpowers/plans/2026-05-20-brand-discovery-first-principles-tdd.md
 * (Task 8 Step 5).
 */

import { describe, expect, it } from 'vitest';

import { classifyCandidate, type CandidateInput, type TargetContext } from '../../src/lib/brand-classification';
import type { BrandEvidenceObservation } from '../../src/lib/brand-evidence';

const OWNED_BUCKETS = new Set(['consolidated', 'shadowIt', 'indeterminate', 'impersonation']);

function makeTarget(overrides: Partial<TargetContext> = {}): TargetContext {
	return {
		domain: 'example.com',
		registrar: 'MarkMonitor Inc.',
		registrarFamily: 'MarkMonitor',
		...overrides,
	};
}

function makeCandidate(domain: string, observations: BrandEvidenceObservation[]): CandidateInput {
	return {
		domain,
		confidence: 0.5,
		signals: [],
		registrar: 'Unknown',
		registrarSource: 'unknown',
		evidenceObservations: observations,
	};
}

/**
 * Fixture: synthetic candidates exercising every tier combination that could
 * threaten the mutual-exclusion invariant. Each row is intentionally
 * minimal — the audit asserts a structural property of the classifier,
 * not the rich signal-routing covered in the unit tests.
 */
interface FixtureRow {
	readonly name: string;
	readonly observations: BrandEvidenceObservation[];
	readonly expectedSurface: 'owned' | 'impersonationSurface';
}

const FIXTURE: readonly FixtureRow[] = [
	{
		name: 'tier 0 alone',
		observations: [{ signal: 'http_redirect', tier: 0 }],
		expectedSurface: 'owned',
	},
	{
		name: 'tier 1 specific',
		observations: [{ signal: 'ns', tier: 1, specificityScore: 0.9 }],
		expectedSurface: 'owned',
	},
	{
		name: 'tier 2 alone',
		observations: [{ signal: 'dmarc_rua', tier: 2 }],
		expectedSurface: 'owned',
	},
	{
		name: 'tier 4 alone',
		observations: [{ signal: 'active_lookalike', tier: 4 }],
		expectedSurface: 'impersonationSurface',
	},
	{
		name: 'tier 0 + tier 4 — owned wins',
		observations: [
			{ signal: 'active_lookalike', tier: 4 },
			{ signal: 'http_redirect', tier: 0 },
		],
		expectedSurface: 'owned',
	},
	{
		name: 'tier 1 specific + tier 4 — owned wins',
		observations: [
			{ signal: 'active_lookalike', tier: 4 },
			{ signal: 'ns', tier: 1, specificityScore: 0.7 },
		],
		expectedSurface: 'owned',
	},
	{
		name: 'tier 2 + tier 4 — owned wins',
		observations: [
			{ signal: 'active_lookalike', tier: 4 },
			{ signal: 'dmarc_rua', tier: 2 },
		],
		expectedSurface: 'owned',
	},
	{
		name: 'tier 1 low specificity + tier 4 — falls through to legacy (no impersonationSurface)',
		// Tier 1 fails the specificity gate. Tier 4 is not alone, so the only-tier-4
		// short-circuit does not fire either. Legacy rules take over — the result MUST
		// be an Owned bucket (one of indeterminate/impersonation), never impersonationSurface.
		observations: [
			{ signal: 'ns', tier: 1, specificityScore: 0.2 },
			{ signal: 'active_lookalike', tier: 4 },
		],
		expectedSurface: 'owned',
	},
];

describe('brand-discovery tier mutual-exclusion invariant (Task 8)', () => {
	it.each(FIXTURE)('$name → expected surface is $expectedSurface', ({ observations, expectedSurface }) => {
		const candidate = makeCandidate('candidate.example', observations);
		const result = classifyCandidate(candidate, makeTarget());

		if (expectedSurface === 'impersonationSurface') {
			expect(result.bucket).toBe('impersonationSurface');
			expect(OWNED_BUCKETS.has(result.bucket)).toBe(false);
		} else {
			expect(OWNED_BUCKETS.has(result.bucket)).toBe(true);
			expect(result.bucket).not.toBe('impersonationSurface');
		}
	});

	it('NO single classification ever returns both an Owned bucket AND impersonationSurface', () => {
		// The classifier returns exactly one bucket — so the per-domain invariant is
		// trivially that bucket ∈ Owned XOR bucket === 'impersonationSurface'. This
		// assertion pins the structural exclusivity across the entire fixture so a
		// future refactor that (e.g.) returns an array of buckets cannot silently
		// violate the invariant without breaking this audit.
		for (const row of FIXTURE) {
			const candidate = makeCandidate('candidate.example', row.observations);
			const { bucket } = classifyCandidate(candidate, makeTarget());
			const inOwned = OWNED_BUCKETS.has(bucket);
			const inImpersonationSurface = bucket === 'impersonationSurface';
			// XOR — exactly one of the two must be true.
			expect(inOwned !== inImpersonationSurface).toBe(true);
		}
	});
});
