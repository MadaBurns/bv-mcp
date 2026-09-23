// SPDX-License-Identifier: BUSL-1.1

/**
 * Regression coverage for SQ-39.
 *
 * The ticket's spike observed (correctly, in isolation) that `isImpersonation`'s
 * veto — `hasSharedInfrastructureSignal`, which checks membership in
 * SHARED_INFRA_SIGNALS (brand-classification.ts:118-129) — does not recognize
 * `app_links` / `bounty_scope` as shared-infra evidence, even though both are
 * members of STRONG_INFRA_SIGNALS (brand-classification.ts:108-116). It then
 * concluded this was "the ONLY reachable classic-mode impersonation path" and
 * "a false positive by construction".
 *
 * That consequence does NOT hold. `classifyCandidate`'s Rule 2
 * (`hasStrongInfraSignal`, brand-classification.ts:477-486) inspects the same
 * `c.signals` array for STRONG_INFRA_SIGNALS membership and returns
 * unconditionally — `consolidated`, or `shadowIt` for an exact
 * brand-portfolio domain — BEFORE Rule 4.6 ever calls `isImpersonation`
 * (brand-classification.ts:549). Since `app_links` and `bounty_scope` are
 * themselves STRONG_INFRA_SIGNALS members, any candidate carrying one is
 * intercepted by Rule 2 and never reaches Rule 4.6. `isImpersonation`'s
 * incomplete veto set is real but dead code with respect to these two
 * signals — the premise is false, not merely latent. These tests pin that
 * rule ordering so a future refactor can't silently reorder Rule 2 after
 * Rule 4.6 and revive the false positive.
 */
import { describe, expect, it } from 'vitest';
import { classifyCandidate, isImpersonation, type CandidateInput, type TargetContext } from '../src/lib/brand-classification';

const TARGET: TargetContext = {
	domain: 'fabpay.com',
	registrar: 'MarkMonitor Inc.',
	registrarFamily: 'MarkMonitor',
};

function candidate(overrides: Partial<CandidateInput> & { domain: string }): CandidateInput {
	return {
		confidence: 0.55,
		signals: ['markov_gen'],
		registrar: 'NameCheap, Inc.',
		registrarSource: 'rdap',
		...overrides,
	};
}

describe('SQ-39: Rule 2 (strong infra signal) precedes Rule 4.6 (isImpersonation)', () => {
	it.each(['app_links', 'bounty_scope'] as const)(
		'routes a typosquat-shaped candidate carrying %s to consolidated, never impersonation',
		(signal) => {
			// Every isImpersonation gate is independently satisfied here: high lookalike
			// score, cross-registrar-family mismatch, and no SHARED_INFRA_SIGNALS member
			// present — the exact shape the spike claimed "passes the veto" and reaches
			// impersonation. Rule 2 fires first and short-circuits before that predicate runs.
			const result = classifyCandidate(candidate({ domain: 'paypa1.com', signals: [signal], lookalikeScore: 0.95 }), TARGET);
			expect(result.bucket).toBe('consolidated');
			expect(result.relationshipType).toBe('owned_primary');
			expect(result.reasons.join(' ')).not.toMatch(/impersonation/i);
		},
	);

	it('confirms the narrow fact behind the spike: isImpersonation alone does not veto app_links/bounty_scope', () => {
		// True in isolation — this is what the spike actually measured — but unreachable
		// through classifyCandidate, per the test above.
		const c = candidate({ domain: 'paypa1.com', signals: ['app_links'], lookalikeScore: 0.95 });
		expect(isImpersonation(c, TARGET).length).toBeGreaterThan(0);
	});

	it('sanity: a candidate with no strong/shared signal at all still reaches Rule 4.6 and lands in impersonation', () => {
		const result = classifyCandidate(candidate({ domain: 'paypa1.com', signals: ['markov_gen'], lookalikeScore: 0.95 }), TARGET);
		expect(result.bucket).toBe('impersonation');
	});
});
