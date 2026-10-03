// SPDX-License-Identifier: BUSL-1.1

/**
 * SQ-279 item 4 — `checkCAA` and `checkDNSSEC` must not certify absence from a SERVFAIL.
 *
 * A DoH endpoint answers HTTP 200 for SERVFAIL/REFUSED, so the `string[]` projection of
 * `queryDNS` hands a check an EMPTY answer set that is byte-identical to a name that
 * genuinely publishes nothing. Before this fix:
 *  - an inconclusive CAA lookup was filed as "No CAA records" (medium),
 *  - an inconclusive DNSKEY/DS pair was filed as "DNSSEC not enabled" (high, -40),
 *  - DS answering with a SERVFAILed DNSKEY was filed as "chain of trust incomplete"
 *    with `missingControl: true` (the slice-5 F2 shape: typical of a DNSSEC-bogus zone).
 */

import { describe, expect, it } from 'vitest';
import { checkCAA } from '../../checks/check-caa';
import { checkDNSSEC } from '../../checks/check-dnssec';
import type { DNSQueryFunction, RawDNSQueryFunction, ZoneContext } from '../../types';

const NOERROR = 0;
const SERVFAIL = 2;
const REFUSED = 5;

interface Answer {
	records?: string[];
	rcode?: number;
	throws?: boolean;
}

/** Mirror of the Worker adapter: the plain call projects to strings, `withRcode` keeps the rcode. */
function resolver(table: Record<string, Answer>): DNSQueryFunction {
	const lookup = (name: string, type: string): Answer => table[`${type} ${name}`] ?? { records: [], rcode: NOERROR };
	const queryDNS = (async (name: string, type: string) => {
		const answer = lookup(name, type);
		if (answer.throws) throw new Error('DNS query failed: timeout');
		return answer.records ?? [];
	}) as DNSQueryFunction;
	queryDNS.withRcode = async (name: string, type: string) => {
		const answer = lookup(name, type);
		if (answer.throws) throw new Error('DNS query failed: timeout');
		return { records: answer.records ?? [], rcode: answer.rcode ?? NOERROR };
	};
	return queryDNS;
}

describe('checkCAA — an unanswered lookup is not "No CAA records" (SQ-279 item 4)', () => {
	it('abstains when the CAA lookup answers SERVFAIL (plain queryDNS path)', async () => {
		const result = await checkCAA('example.com', resolver({ 'CAA example.com': { rcode: SERVFAIL } }));
		expect(result.checkStatus).toBe('error');
		expect(result.partial).toBe(true);
		expect(result.findings.some((f) => f.title === 'No CAA records')).toBe(false);
		expect(result.findings[0].metadata?.errorKind).toBe('dns_error');
		expect(result.recordPresent).toBeUndefined();
	});

	it('abstains when the raw CAA response carries SERVFAIL (rawQueryDNS path, the Worker path)', async () => {
		const rawQueryDNS: RawDNSQueryFunction = async () => ({ Status: SERVFAIL, AD: false, Answer: [] });
		const result = await checkCAA('example.com', resolver({}), { rawQueryDNS });
		expect(result.checkStatus).toBe('error');
		expect(result.findings.some((f) => f.title === 'No CAA records')).toBe(false);
	});

	it('abstains on REFUSED too', async () => {
		const rawQueryDNS: RawDNSQueryFunction = async () => ({ Status: REFUSED, AD: false, Answer: [] });
		const result = await checkCAA('example.com', resolver({}), { rawQueryDNS });
		expect(result.checkStatus).toBe('error');
	});

	it('abstains when the RFC 8659 climb meets a SERVFAIL ancestor and finds nothing else', async () => {
		const zone: ZoneContext = {
			scannedLabel: 'www.example.com',
			registrableDomain: 'example.com',
			isApex: false,
			zoneApex: 'example.com',
			apexNsRecords: ['ns1.example.com'],
			delegationStatus: 'inherited',
		};
		const result = await checkCAA(
			'www.example.com',
			resolver({
				'CAA www.example.com': { rcode: NOERROR },
				'CAA example.com': { rcode: SERVFAIL },
			}),
			{ zone },
		);
		expect(result.checkStatus).toBe('error');
		expect(result.findings.some((f) => f.title === 'No CAA records')).toBe(false);
	});

	it('still reports "No CAA records" for a measured NOERROR-empty answer (positive control)', async () => {
		const result = await checkCAA('example.com', resolver({}));
		expect(result.checkStatus).toBeUndefined();
		expect(result.findings.some((f) => f.title === 'No CAA records')).toBe(true);
		expect(result.recordPresent).toBe(false);
	});

	it('still reports "No CAA records" for NXDOMAIN-empty (a conclusion)', async () => {
		const rawQueryDNS: RawDNSQueryFunction = async () => ({ Status: 3, AD: false, Answer: [] });
		const result = await checkCAA('example.com', resolver({}), { rawQueryDNS });
		expect(result.findings.some((f) => f.title === 'No CAA records')).toBe(true);
	});
});

const DNSKEY = '257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==';
const DS = '2371 13 2 abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789';
const rawSigned: RawDNSQueryFunction = async () => ({ Status: NOERROR, AD: true, Answer: [] });

describe('checkDNSSEC — an unanswered DNSKEY/DS lookup is not a verdict (SQ-279 item 4)', () => {
	it('abstains, not "chain of trust incomplete" + missingControl, when DS answers but DNSKEY SERVFAILs', async () => {
		const result = await checkDNSSEC(
			'example.com',
			resolver({ 'DS example.com': { records: [DS] }, 'DNSKEY example.com': { rcode: SERVFAIL } }),
			{ rawQueryDNS: rawSigned },
		);
		expect(result.checkStatus).toBe('error');
		expect(result.partial).toBe(true);
		expect(result.findings.some((f) => f.title === 'DNSSEC chain of trust incomplete')).toBe(false);
		expect(result.findings.some((f) => f.metadata?.missingControl === true)).toBe(false);
	});

	it('abstains, not "DNSSEC not enabled", when DNSKEY and DS both SERVFAIL', async () => {
		const result = await checkDNSSEC(
			'example.com',
			resolver({ 'DS example.com': { rcode: SERVFAIL }, 'DNSKEY example.com': { rcode: SERVFAIL } }),
			{ rawQueryDNS: rawSigned },
		);
		expect(result.checkStatus).toBe('error');
		expect(result.findings.some((f) => f.title === 'DNSSEC not enabled')).toBe(false);
		expect(result.recordPresent).toBeUndefined();
	});

	it('abstains, not "DNSSEC not enabled", when DNSKEY is NOERROR-empty but DS SERVFAILs', async () => {
		const result = await checkDNSSEC('example.com', resolver({ 'DS example.com': { rcode: SERVFAIL } }), { rawQueryDNS: rawSigned });
		expect(result.checkStatus).toBe('error');
		expect(result.findings.some((f) => f.title === 'DNSSEC not enabled')).toBe(false);
	});

	it('abstains, not "DNSSEC not enabled", when both lookups THROW', async () => {
		const result = await checkDNSSEC(
			'example.com',
			resolver({ 'DS example.com': { throws: true }, 'DNSKEY example.com': { throws: true } }),
			{ rawQueryDNS: rawSigned },
		);
		expect(result.checkStatus).toBe('error');
		expect(result.findings.some((f) => f.title === 'DNSSEC not enabled')).toBe(false);
	});

	it('abstains, not "island of trust", when DNSKEY answers but DS SERVFAILs', async () => {
		const result = await checkDNSSEC(
			'example.com',
			resolver({ 'DNSKEY example.com': { records: [DNSKEY] }, 'DS example.com': { rcode: SERVFAIL } }),
			{ rawQueryDNS: rawSigned },
		);
		expect(result.checkStatus).toBe('error');
		expect(result.findings.some((f) => f.title === 'DNSSEC island of trust')).toBe(false);
	});

	it('still reports "DNSSEC not enabled" for measured NOERROR-empty DNSKEY and DS (positive control)', async () => {
		const result = await checkDNSSEC('example.com', resolver({}), {
			rawQueryDNS: async () => ({ Status: NOERROR, AD: false, Answer: [] }),
		});
		expect(result.checkStatus).toBeUndefined();
		const absent = result.findings.find((f) => f.title === 'DNSSEC not enabled');
		expect(absent).toBeDefined();
		expect(absent?.metadata?.penaltyOverride).toBe(40);
		expect(result.score).toBe(60);
	});

	it('still reports "chain of trust incomplete" for a MEASURED DS with NOERROR-empty DNSKEY (positive control)', async () => {
		const result = await checkDNSSEC('example.com', resolver({ 'DS example.com': { records: [DS] } }), {
			rawQueryDNS: async () => ({ Status: NOERROR, AD: false, Answer: [] }),
		});
		expect(result.findings.some((f) => f.title === 'DNSSEC chain of trust incomplete')).toBe(true);
	});
});
