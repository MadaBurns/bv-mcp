// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect } from 'vitest';
import { hasRegistrationEvidence } from './registration-evidence';

const none = { ns: [] as string[], hasA: false, mx: [] as string[], hasSpf: false, dmarcPolicy: null as string | null };

describe('hasRegistrationEvidence', () => {
	it('is false only when NO DNS presence exists at all', () => {
		expect(hasRegistrationEvidence({ ...none })).toBe(false);
	});

	it('treats a published SPF TXT as proof of registration (the bnz.co contradiction)', () => {
		// No NS, no A, no MX — but an SPF record cannot exist for an unregistered domain.
		expect(hasRegistrationEvidence({ ...none, hasSpf: true })).toBe(true);
	});

	it.each([
		['NS delegation', { ns: ['ns1.registrar.com.'] }],
		['A record', { hasA: true }],
		['MX records', { mx: ['10 mail.example.com.'] }],
		['DMARC policy', { dmarcPolicy: 'none' }],
	])('treats %s as proof of registration', (_label, override) => {
		expect(hasRegistrationEvidence({ ...none, ...override })).toBe(true);
	});
});
