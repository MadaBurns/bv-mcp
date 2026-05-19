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
});
