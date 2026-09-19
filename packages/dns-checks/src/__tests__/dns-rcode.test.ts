// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import { DNS_RCODE, buildRcodeAbstentionResult, describeRcode, isConclusiveRcode, isInconclusiveRcode } from '../dns-rcode';
import { findingsIndicateMissingControl } from '../scoring/model';
import { isCheckMeasured } from '../scoring/evidence';

describe('rcode classification', () => {
	it('treats NOERROR and NXDOMAIN as conclusions', () => {
		// An empty answer set under either of these IS evidence of absence: the resolver
		// answered the question.
		expect(isConclusiveRcode(DNS_RCODE.NOERROR)).toBe(true);
		expect(isConclusiveRcode(DNS_RCODE.NXDOMAIN)).toBe(true);
		expect(isInconclusiveRcode(DNS_RCODE.NOERROR)).toBe(false);
		expect(isInconclusiveRcode(DNS_RCODE.NXDOMAIN)).toBe(false);
	});

	it('treats every other rcode as a non-conclusion', () => {
		for (const status of [DNS_RCODE.FORMERR, DNS_RCODE.SERVFAIL, DNS_RCODE.NOTIMP, DNS_RCODE.REFUSED, 9, 23]) {
			expect(isInconclusiveRcode(status), `rcode ${status}`).toBe(true);
			expect(isConclusiveRcode(status), `rcode ${status}`).toBe(false);
		}
	});

	it('treats an absent rcode as "nothing to say", not as a failure', () => {
		// Hand-built responses and adapters with no rcode channel must keep their prior
		// behaviour rather than degrade into a blanket abstention.
		expect(isInconclusiveRcode(undefined)).toBe(false);
		expect(isConclusiveRcode(undefined)).toBe(false);
	});

	it('names the known rcodes and falls back for the rest', () => {
		expect(describeRcode(DNS_RCODE.SERVFAIL)).toBe('SERVFAIL');
		expect(describeRcode(DNS_RCODE.REFUSED)).toBe('REFUSED');
		expect(describeRcode(9)).toBe('RCODE 9');
	});
});

describe('buildRcodeAbstentionResult', () => {
	const result = buildRcodeAbstentionResult('dmarc', 'DMARC', '_dmarc.example.com', 'TXT', DNS_RCODE.SERVFAIL);

	it('produces the existing abstention shape', () => {
		expect(result.category).toBe('dmarc');
		expect(result.checkStatus).toBe('error');
		expect(isCheckMeasured(result.checkStatus)).toBe(false);
		expect(result.partial).toBe(true);
		expect(result.score).toBe(0);
		expect(result.passed).toBe(false);
	});

	it('never claims the control is absent (#638 law)', () => {
		expect(findingsIndicateMissingControl(result.findings)).toBe(false);
		expect(result.findings[0].metadata?.missingControl).toBeUndefined();
		// "could not be determined", not "absent".
		expect(result.controlPresent).toBeUndefined();
	});

	it('carries the markers existing consumers filter on', () => {
		expect(result.findings[0].metadata?.errorKind).toBe('dns_error');
		expect(result.findings[0].metadata?.inconclusive).toBe(true);
		expect(result.findings[0].metadata?.dnsRcode).toBe(DNS_RCODE.SERVFAIL);
		expect(result.findings[0].title).toBe('DMARC check error');
		expect(result.findings[0].detail).toContain('SERVFAIL');
	});
});
