// SPDX-License-Identifier: BUSL-1.1

/**
 * Pure-function unit tests for the lookalike severity calibrator.
 *
 * Covers the severity matrix from issue #264:
 *   - mail-infra alone                       → MEDIUM
 *   - mail-infra + recent registration (<90d) → HIGH
 *   - mail-infra + disposable MX provider     → HIGH
 *   - mail-infra + no web content             → HIGH
 *   - web only                                → LOW
 *   - web only + recent registration          → MEDIUM
 *
 * No DNS or HTTP mocks — these tests assert the matrix verbatim against the
 * pure calibrator. Integration wiring is exercised in check-lookalikes.spec.ts.
 */

import { describe, it, expect } from 'vitest';
import {
	calibrateLookalikeSeverity,
	type LookalikeSignals,
} from '../src/tools/lookalike-severity';

function base(overrides: Partial<LookalikeSignals> = {}): LookalikeSignals {
	return {
		hasA: false,
		hasMX: false,
		registrationDays: null,
		mxOnDisposable: false,
		hasWebContent: true,
		...overrides,
	};
}

describe('calibrateLookalikeSeverity — issue #264 matrix', () => {
	it('returns medium for mail-infra alone (no corroborator)', () => {
		expect(calibrateLookalikeSeverity(base({ hasA: true, hasMX: true, registrationDays: 1500, hasWebContent: true })))
			.toBe('medium');
	});

	it('returns high for mail-infra + recent registration (<90d)', () => {
		expect(calibrateLookalikeSeverity(base({ hasA: true, hasMX: true, registrationDays: 30, hasWebContent: true })))
			.toBe('high');
	});

	it('returns high for mail-infra + registration exactly at 89 days', () => {
		expect(calibrateLookalikeSeverity(base({ hasA: true, hasMX: true, registrationDays: 89, hasWebContent: true })))
			.toBe('high');
	});

	it('returns medium for mail-infra + registration at exactly 90 days (not recent)', () => {
		expect(calibrateLookalikeSeverity(base({ hasA: true, hasMX: true, registrationDays: 90, hasWebContent: true })))
			.toBe('medium');
	});

	it('returns high for mail-infra + disposable MX provider', () => {
		expect(calibrateLookalikeSeverity(base({ hasA: true, hasMX: true, mxOnDisposable: true, hasWebContent: true })))
			.toBe('high');
	});

	it('returns high for mail-infra + no web content (parked/connection refused)', () => {
		expect(calibrateLookalikeSeverity(base({ hasA: true, hasMX: true, hasWebContent: false })))
			.toBe('high');
	});

	it('returns low for web-only (A record, no MX, has web content)', () => {
		expect(calibrateLookalikeSeverity(base({ hasA: true, hasMX: false, hasWebContent: true })))
			.toBe('low');
	});

	it('returns medium for web-only + recent registration (<90d)', () => {
		expect(calibrateLookalikeSeverity(base({ hasA: true, hasMX: false, registrationDays: 30, hasWebContent: true })))
			.toBe('medium');
	});

	it('treats unknown registration age (null) as not-recent fallback (not high)', () => {
		// RDAP infra returned no date or failed — must not elevate to high on this signal alone.
		expect(calibrateLookalikeSeverity(base({ hasA: true, hasMX: true, registrationDays: null, hasWebContent: true })))
			.toBe('medium');
	});

	it('returns medium for web-only + unknown registration age (not recent fallback)', () => {
		expect(calibrateLookalikeSeverity(base({ hasA: true, hasMX: false, registrationDays: null, hasWebContent: true })))
			.toBe('low');
	});

	it('disposable MX alone (no A) — treated as mail-infra HIGH (disposable corroborator)', () => {
		expect(calibrateLookalikeSeverity(base({ hasA: false, hasMX: true, mxOnDisposable: true })))
			.toBe('high');
	});
});
