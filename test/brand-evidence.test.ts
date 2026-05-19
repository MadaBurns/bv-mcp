// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import { clearsOwnershipGate, evidenceTier } from '../src/lib/brand-evidence';

describe('brand evidence tier policy', () => {
	it('treats broad shared MX platforms as weak evidence', () => {
		expect(evidenceTier('mx_platform', { sharedMxPlatform: 'm365' })).toBe('weak');
		expect(evidenceTier('mx_platform', { sharedMxPlatform: 'google_workspace' })).toBe('weak');
	});

	it('does not let markov generation plus broad MX platform clear ownership', () => {
		expect(
			clearsOwnershipGate(
				[
					{ signal: 'markov_gen' },
					{ signal: 'mx_platform', metadata: { sharedMxPlatform: 'm365' } },
				],
				{ callerAsserted: false },
			),
		).toBe(false);
	});

	it('does not let generated lookalike seeds corroborate a single medium ownership signal', () => {
		expect(
			clearsOwnershipGate(
				[
					{ signal: 'markov_gen' },
					{ signal: 'ns' },
				],
				{ callerAsserted: false },
			),
		).toBe(false);
		expect(
			clearsOwnershipGate(
				[
					{ signal: 'active_lookalike' },
					{ signal: 'ns' },
				],
				{ callerAsserted: false },
			),
		).toBe(false);
	});

	it('lets deterministic TXT verification clear ownership alone', () => {
		expect(evidenceTier('txt_verification')).toBe('strong');
		expect(clearsOwnershipGate([{ signal: 'txt_verification' }], { callerAsserted: false })).toBe(true);
	});

	it('lets DKIM key reuse clear ownership alone', () => {
		expect(evidenceTier('dkim_key_reuse')).toBe('strong');
		expect(clearsOwnershipGate([{ signal: 'dkim_key_reuse' }], { callerAsserted: false })).toBe(true);
	});

	it('does not let one medium signal plus broad weak MX platform clear ownership', () => {
		expect(
			clearsOwnershipGate(
				[
					{ signal: 'mx_platform', metadata: { sharedMxPlatform: 'm365' } },
					{ signal: 'ns' },
				],
				{ callerAsserted: false },
			),
		).toBe(false);
		expect(
			clearsOwnershipGate(
				[
					{ signal: 'mx_platform', metadata: { sharedMxPlatform: 'm365' } },
					{ signal: 'active_lookalike' },
				],
				{ callerAsserted: false },
			),
		).toBe(false);
	});

	it('lets two medium non-seed signals clear ownership', () => {
		expect(
			clearsOwnershipGate(
				[
					{ signal: 'mx_platform', metadata: { sharedMxPlatform: 'proofpoint' } },
					{ signal: 'ns' },
				],
				{ callerAsserted: false },
			),
		).toBe(true);
	});

	it('lets caller asserted candidates clear when any real observation exists', () => {
		expect(clearsOwnershipGate([{ signal: 'ns' }], { callerAsserted: true })).toBe(true);
		expect(clearsOwnershipGate([{ signal: 'mx_platform', metadata: { sharedMxPlatform: 'm365' } }], { callerAsserted: true })).toBe(true);
		expect(clearsOwnershipGate([{ signal: 'markov_gen' }], { callerAsserted: true })).toBe(false);
	});

	it('does not let speculative lookalike or markov seeds clear alone', () => {
		expect(clearsOwnershipGate([{ signal: 'active_lookalike' }], { callerAsserted: false })).toBe(false);
		expect(clearsOwnershipGate([{ signal: 'markov_gen' }], { callerAsserted: false })).toBe(false);
	});

	// T6: tier metadata short-circuits the legacy N-of-M corroboration gate.
	describe('tier-based ownership-gate bypass (T6)', () => {
		it('clears ownership for a single tier-0 observation (tenant-declared)', () => {
			// `ns` alone is medium and would otherwise fail the legacy gate —
			// so a `true` result here can only come from the tier-0 bypass.
			expect(
				clearsOwnershipGate([{ signal: 'ns', confidence: 1.0, tier: 0 }], { callerAsserted: false }),
			).toBe(true);
		});

		it('clears ownership for a tier-1 observation with specificityScore >= 0.5', () => {
			expect(
				clearsOwnershipGate(
					[{ signal: 'ns', confidence: 0.7, tier: 1, specificityScore: 0.7 }],
					{ callerAsserted: false },
				),
			).toBe(true);
		});

		it('does NOT auto-clear for a tier-1 observation with specificityScore < 0.5', () => {
			// Use a weak (seed) signal so legacy fall-through cannot accidentally
			// clear it — proving the tier-1 bypass is gated on specificityScore.
			expect(
				clearsOwnershipGate(
					[{ signal: 'active_lookalike', confidence: 0.1, tier: 1, specificityScore: 0.1 }],
					{ callerAsserted: false },
				),
			).toBe(false);
		});

		it('clears ownership for a single tier-2 observation (declared/witnessed evidence)', () => {
			// Solo `ns` would fail legacy; clearing must come from the tier-2 bypass.
			expect(
				clearsOwnershipGate([{ signal: 'ns', confidence: 0.95, tier: 2 }], { callerAsserted: false }),
			).toBe(true);
		});

		it('falls through to legacy N-of-M gate when no observations carry a tier (Tier 3 fallback)', () => {
			// Two non-seed medium signals → legacy gate clears (unchanged behavior).
			expect(
				clearsOwnershipGate(
					[
						{ signal: 'ns' },
						{ signal: 'mx_overlap' },
					],
					{ callerAsserted: false },
				),
			).toBe(true);
			// Single medium without tier → legacy gate rejects (unchanged behavior).
			expect(clearsOwnershipGate([{ signal: 'ns' }], { callerAsserted: false })).toBe(false);
		});
	});
});
