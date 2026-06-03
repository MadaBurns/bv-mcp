// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import { classifyCandidate, isCombosquat, type CandidateInput, type TargetContext } from '../src/lib/brand-classification';

const TARGET: TargetContext = {
	domain: 'paypal.com',
	registrar: 'MarkMonitor Inc.',
	registrarFamily: 'MarkMonitor',
};

function candidate(overrides: Partial<CandidateInput> & { domain: string }): CandidateInput {
	return {
		confidence: 0.45,
		signals: ['markov_gen'],
		registrar: 'NameCheap, Inc.',
		registrarSource: 'rdap',
		...overrides,
	};
}

describe('combosquat classification (Rule 4.7)', () => {
	it('routes a cross-registrar combosquat to the impersonation bucket', () => {
		const result = classifyCandidate(candidate({ domain: 'paypal-login.com' }), TARGET);
		expect(result.bucket).toBe('impersonation');
		expect(result.relationshipType).toBe('impersonation_risk');
		// Proves it routed via Rule 4.7 (token containment) and not the Rule 8
		// low-confidence catch-all — the reason names the embedded brand token.
		expect(result.reasons.join(' ')).toMatch(/combosquat: label embeds brand token 'paypal'/);
		expect(result.reasons.join(' ')).toMatch(/lure keyword/);
	});

	it('catches combosquats that whole-label similarity misses (lookalikeScore stays 0)', () => {
		// No lookalikeScore supplied → isImpersonation (Rule 4.6) cannot fire;
		// only the token-containment branch can flag this.
		const result = classifyCandidate(candidate({ domain: 'secure-paypal.net' }), TARGET);
		expect(result.bucket).toBe('impersonation');
		expect(result.reasons.join(' ')).toMatch(/combosquat/);
	});

	it('does NOT fire for a brand+generic-token combo with no lure keyword (manual-review case)', () => {
		// `paypal-shop` embeds the brand token but `shop` is not a lure keyword —
		// as often legitimate/defensive as abusive, so it stays indeterminate
		// rather than being accused of impersonation.
		const result = classifyCandidate(candidate({ domain: 'paypal-shop.com', confidence: 0.6 }), TARGET);
		expect(result.bucket).toBe('indeterminate');
		expect(result.reasons.join(' ')).not.toMatch(/combosquat/);
	});

	it('does NOT fire for a same-registrar-family combosquat (defensive registration)', () => {
		// Same family ⇒ brand-owned defensive registration. With confidence in the
		// indeterminate band, the combosquat guard sends it to indeterminate, NOT
		// impersonation — proving the guard, not the Rule 8 catch-all, decided it.
		const result = classifyCandidate(
			candidate({ domain: 'paypal-business.com', confidence: 0.6, registrar: 'MarkMonitor Inc.' }),
			TARGET,
		);
		expect(result.bucket).toBe('indeterminate');
		expect(result.reasons.join(' ')).not.toMatch(/combosquat/);
	});
});

describe('isCombosquat predicate guards', () => {
	it('returns reasons for a genuine cross-family combosquat', () => {
		expect(isCombosquat(candidate({ domain: 'paypal-verify.com' }), TARGET).length).toBeGreaterThan(0);
	});

	it('returns [] when the registrar family matches the target (defensive)', () => {
		expect(isCombosquat(candidate({ domain: 'paypal-verify.com', registrar: 'MarkMonitor Inc.' }), TARGET)).toEqual([]);
	});

	it('returns [] when the candidate shares infrastructure with the target (routes to shadowIt earlier)', () => {
		expect(isCombosquat(candidate({ domain: 'paypal-verify.com', signals: ['ns', 'san'] }), TARGET)).toEqual([]);
	});

	it('returns [] for an unrelated domain with no brand-token containment', () => {
		expect(isCombosquat(candidate({ domain: 'totally-different.com' }), TARGET)).toEqual([]);
	});
});
