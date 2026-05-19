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

	// T6: tier-aware bypass of N-of-M corroboration. Tier 0/1/2 carry enough
	// source-side confidence to short-circuit the gate; Tier 3 stays on the
	// legacy live-signal sweep path.
	describe('tier-aware ownership gate (T6)', () => {
		it('returns true for a single tier-0 observation', () => {
			// Tier 0 = tenant-declared (gold standard). A weak signal name should
			// not matter — provenance dominates.
			expect(
				clearsOwnershipGate(
					[{ signal: 'mx_platform', confidence: 1.0, tier: 0, metadata: { sharedMxPlatform: 'm365' } }],
					{ callerAsserted: false },
				),
			).toBe(true);
		});

		it('returns true for a tier-1 observation with specificityScore >= 0.5', () => {
			expect(
				clearsOwnershipGate(
					[{ signal: 'mx_overlap', confidence: 0.7, tier: 1, specificityScore: 0.7 }],
					{ callerAsserted: false },
				),
			).toBe(true);
		});

		it('does NOT auto-clear for tier-1 with specificityScore < 0.5', () => {
			// e.g. shared gmail MX, low signal-graph specificity.
			expect(
				clearsOwnershipGate(
					[{ signal: 'mx_platform', confidence: 0.1, tier: 1, specificityScore: 0.1, metadata: { sharedMxPlatform: 'gmail' } }],
					{ callerAsserted: false },
				),
			).toBe(false);
		});

		it('does NOT auto-clear for tier-1 with missing specificityScore', () => {
			// Tier 1 requires the specificity threshold to be met explicitly.
			expect(
				clearsOwnershipGate(
					[{ signal: 'mx_platform', confidence: 0.4, tier: 1, metadata: { sharedMxPlatform: 'gmail' } }],
					{ callerAsserted: false },
				),
			).toBe(false);
		});

		it('returns true for a single tier-2 observation', () => {
			// Tier 2 = declared/witnessed (e.g. RDAP registrant match). Specificity
			// is not required.
			expect(
				clearsOwnershipGate(
					[{ signal: 'ns', confidence: 0.95, tier: 2 }],
					{ callerAsserted: false },
				),
			).toBe(true);
		});

		it('legacy N-of-M gate still applies when observations carry no tier (Tier 3 fallback)', () => {
			// Two medium non-seed signals without tier metadata should still clear
			// via the existing rule.
			expect(
				clearsOwnershipGate(
					[
						{ signal: 'ns' },
						{ signal: 'mx_overlap' },
					],
					{ callerAsserted: false },
				),
			).toBe(true);
		});

		it('legacy N-of-M gate still rejects under-corroborated tierless observations', () => {
			// A single medium tierless signal should still fail the gate.
			expect(
				clearsOwnershipGate(
					[{ signal: 'ns' }],
					{ callerAsserted: false },
				),
			).toBe(false);
		});
	});
});
