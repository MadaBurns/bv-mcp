// SPDX-License-Identifier: BUSL-1.1

/**
 * BIMI must not be recommended to a domain that cannot send email.
 *
 * DMARC enforcement is BIMI's PREREQUISITE, not the whole eligibility test: a
 * BIMI logo only ever renders beside mail the domain sends. A domain publishing
 * `v=spf1 -all` (no authorizing mechanisms) has declared it sends nothing, so
 * "This domain has DMARC enforcement and is eligible for BIMI" was factually
 * wrong there — and it contradicted the same scan's own no-send findings.
 *
 * The fix is wording only: severity stays `low` and `controlPresent` stays
 * unchanged on BOTH branches, so no score moves.
 */

import { describe, expect, it, vi } from 'vitest';
import { checkBIMI } from '../../checks/check-bimi';
import type { DNSQueryFunction } from '../../types';

function createMockDNS(records: Record<string, string[]>): DNSQueryFunction {
	return vi.fn(async (domain: string, _type: string) => records[domain] ?? []);
}

const NO_BIMI = 'default._bimi.example.com';
const DMARC = '_dmarc.example.com';

describe('checkBIMI — non-sending domains are not told they are "eligible for BIMI"', () => {
	it('does NOT claim BIMI eligibility for a domain publishing v=spf1 -all', async () => {
		const queryDNS = createMockDNS({
			[NO_BIMI]: [],
			[DMARC]: ['v=DMARC1; p=reject'],
			'example.com': ['v=spf1 -all'],
		});

		const result = await checkBIMI('example.com', queryDNS);
		const finding = result.findings[0];

		expect(finding.title).toBe('No BIMI record found');
		expect(finding.detail).not.toContain('eligible for BIMI');
		expect(finding.detail).toContain('does not send email');
		expect(finding.detail).toContain('BIMI is not applicable');
		// Wording-only fix — severity and control determination must be untouched.
		expect(finding.severity).toBe('low');
		expect(result.controlPresent).toBe(false);
	});

	it('treats "~all" with no authorizing mechanisms as no-send too', async () => {
		const queryDNS = createMockDNS({
			[NO_BIMI]: [],
			[DMARC]: ['v=DMARC1; p=quarantine'],
			'example.com': ['v=spf1 ~all'],
		});

		const finding = (await checkBIMI('example.com', queryDNS)).findings[0];
		expect(finding.detail).not.toContain('eligible for BIMI');
		expect(finding.severity).toBe('low');
	});

	it('STILL recommends BIMI when SPF authorizes senders (an actual sending domain)', async () => {
		const queryDNS = createMockDNS({
			[NO_BIMI]: [],
			[DMARC]: ['v=DMARC1; p=reject'],
			'example.com': ['v=spf1 include:_spf.google.com -all'],
		});

		const finding = (await checkBIMI('example.com', queryDNS)).findings[0];
		expect(finding.detail).toContain('eligible for BIMI');
		expect(finding.severity).toBe('low');
	});

	it('STILL recommends BIMI when the domain publishes no SPF record at all', async () => {
		const queryDNS = createMockDNS({
			[NO_BIMI]: [],
			[DMARC]: ['v=DMARC1; p=reject'],
		});

		const finding = (await checkBIMI('example.com', queryDNS)).findings[0];
		expect(finding.detail).toContain('eligible for BIMI');
	});

	it('falls back to the eligible wording when the apex TXT lookup fails (fail-soft)', async () => {
		const queryDNS: DNSQueryFunction = vi.fn(async (domain: string) => {
			if (domain === NO_BIMI) return [];
			if (domain === DMARC) return ['v=DMARC1; p=reject'];
			throw new Error('SERVFAIL');
		});

		const finding = (await checkBIMI('example.com', queryDNS)).findings[0];
		expect(finding.detail).toContain('eligible for BIMI');
		expect(finding.severity).toBe('low');
	});

	it('does not probe SPF at all when DMARC is not enforcing (that branch is unchanged)', async () => {
		const queryDNS = vi.fn(async (domain: string) => {
			if (domain === DMARC) return ['v=DMARC1; p=none'];
			return [];
		}) as unknown as DNSQueryFunction;

		const result = await checkBIMI('example.com', queryDNS);
		expect(result.findings[0].title).toBe('No BIMI record (DMARC not enforcing)');
		// Only the BIMI TXT and the DMARC TXT lookups — no third apex TXT query.
		expect((queryDNS as unknown as ReturnType<typeof vi.fn>).mock.calls.map((c) => c[0])).toEqual([NO_BIMI, DMARC]);
	});
});
