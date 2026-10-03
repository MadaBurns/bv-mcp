// SPDX-License-Identifier: BUSL-1.1

/**
 * SQ-279 item 1 — `checkMX` must not turn an UNMEASURED probe into a verdict.
 *
 * A DoH endpoint answers HTTP 200 for SERVFAIL/REFUSED, so the `string[]` projection of
 * `queryDNS` renders "the resolver could not answer" as an empty answer. Before this fix:
 *  - a SERVFAIL on MX (with TXT also failing / empty) was filed as "No MX and no SPF —
 *    domain spoofable" with `missingControl: true` (score 0),
 *  - a failed TXT probe was treated as "no SPF",
 *  - a timed-out A/AAAA lookup of an MX target was filed as "Dangling MX record",
 *  - `spf.includes('-all')` matched `include:-all.example`.
 */

import { describe, expect, it } from 'vitest';
import { checkMX } from '../../checks/check-mx';
import type { DNSQueryFunction } from '../../types';

const RCODE_NOERROR = 0;
const RCODE_SERVFAIL = 2;

interface Answer {
	records?: string[];
	rcode?: number;
	throws?: boolean;
}

/**
 * Mirror of the Worker adapter (`makeQueryDNS`): the plain call projects to the answer
 * strings only (SERVFAIL looks like `[]`), `withRcode` keeps the response code.
 */
function resolver(table: Record<string, Answer>): DNSQueryFunction {
	const lookup = (name: string, type: string): Answer => table[`${type} ${name}`] ?? { records: [], rcode: RCODE_NOERROR };
	const queryDNS = (async (name: string, type: string) => {
		const answer = lookup(name, type);
		if (answer.throws) throw new Error('DNS query failed: timeout');
		return answer.records ?? [];
	}) as DNSQueryFunction;
	queryDNS.withRcode = async (name: string, type: string) => {
		const answer = lookup(name, type);
		if (answer.throws) throw new Error('DNS query failed: timeout');
		return { records: answer.records ?? [], rcode: answer.rcode ?? RCODE_NOERROR };
	};
	return queryDNS;
}

describe('checkMX — unmeasured probes abstain (SQ-279 item 1)', () => {
	it('abstains when the MX lookup is SERVFAIL, instead of "No MX and no SPF — domain spoofable"', async () => {
		const result = await checkMX(
			'example.com',
			resolver({
				'MX example.com': { rcode: RCODE_SERVFAIL },
				'TXT example.com': { rcode: RCODE_SERVFAIL },
			}),
		);
		expect(result.checkStatus).toBe('error');
		expect(result.partial).toBe(true);
		expect(result.findings.some((f) => f.title === 'No MX and no SPF — domain spoofable')).toBe(false);
		expect(result.findings.some((f) => f.metadata?.missingControl === true)).toBe(false);
		expect(result.findings[0].metadata?.errorKind).toBe('dns_error');
	});

	it('abstains when MX is a genuine NOERROR-empty but the SPF (TXT) probe SERVFAILs', async () => {
		const result = await checkMX(
			'example.com',
			resolver({
				'MX example.com': { rcode: RCODE_NOERROR },
				'TXT example.com': { rcode: RCODE_SERVFAIL },
			}),
		);
		expect(result.checkStatus).toBe('error');
		expect(result.findings.some((f) => f.metadata?.missingControl === true)).toBe(false);
	});

	it('abstains when MX is NOERROR-empty and the SPF (TXT) probe throws', async () => {
		const result = await checkMX(
			'example.com',
			resolver({
				'MX example.com': { rcode: RCODE_NOERROR },
				'TXT example.com': { throws: true },
			}),
		);
		expect(result.checkStatus).toBe('error');
		expect(result.findings.some((f) => f.metadata?.missingControl === true)).toBe(false);
	});

	it('still reports "No MX and no SPF" for a genuine NOERROR/NOERROR absence (positive control)', async () => {
		const result = await checkMX('example.com', resolver({}));
		expect(result.checkStatus).toBeUndefined();
		expect(result.findings[0].title).toBe('No MX and no SPF — domain spoofable');
		expect(result.findings[0].metadata?.missingControl).toBe(true);
	});

	it('does not file "Dangling MX record" when the A/AAAA lookups of the target time out', async () => {
		const result = await checkMX(
			'example.com',
			resolver({
				'MX example.com': { records: ['10 mx1.example.com.', '20 mx2.example.com.'] },
				'A mx1.example.com': { throws: true },
				'AAAA mx1.example.com': { throws: true },
				'A mx2.example.com': { records: ['192.0.2.2'] },
			}),
		);
		expect(result.findings.some((f) => f.title === 'Dangling MX record')).toBe(false);
	});

	it('does not file "Dangling MX record" when A and AAAA of the target SERVFAIL', async () => {
		const result = await checkMX(
			'example.com',
			resolver({
				'MX example.com': { records: ['10 mx1.example.com.', '20 mx2.example.com.'] },
				'A mx1.example.com': { rcode: RCODE_SERVFAIL },
				'AAAA mx1.example.com': { rcode: RCODE_SERVFAIL },
				'A mx2.example.com': { records: ['192.0.2.2'] },
			}),
		);
		expect(result.findings.some((f) => f.title === 'Dangling MX record')).toBe(false);
	});

	it('still files "Dangling MX record" when the target is a measured NOERROR-empty (positive control)', async () => {
		const result = await checkMX(
			'example.com',
			resolver({
				'MX example.com': { records: ['10 ghost.example.com.', '20 mx2.example.com.'] },
				'A mx2.example.com': { records: ['192.0.2.2'] },
			}),
		);
		const dangling = result.findings.find((f) => f.title === 'Dangling MX record');
		expect(dangling).toBeDefined();
		expect(dangling!.detail).toContain('ghost.example.com');
	});
});

describe('checkMX — the SPF "-all" test is anchored to the all term (SQ-279 item 1)', () => {
	it('does not treat `include:-all.example` as a hard-fail "-all"', async () => {
		const result = await checkMX(
			'example.com',
			resolver({
				'TXT example.com': { records: ['v=spf1 include:-all.example ~all'] },
			}),
		);
		expect(result.findings[0].title).toBe('Non-mail domain SPF not hard-fail');
	});

	it('still recognises a real "-all" term', async () => {
		const result = await checkMX(
			'example.com',
			resolver({
				'TXT example.com': { records: ['v=spf1 -all'] },
			}),
		);
		expect(result.findings[0].title).toBe('Correctly-configured non-mail domain');
	});

	it('recognises "-all" after other mechanisms', async () => {
		const result = await checkMX(
			'example.com',
			resolver({
				'TXT example.com': { records: ['v=spf1 ip4:192.0.2.0/24 include:_spf.example.net -all'] },
			}),
		);
		expect(result.findings[0].title).toBe('Correctly-configured non-mail domain');
	});
});
