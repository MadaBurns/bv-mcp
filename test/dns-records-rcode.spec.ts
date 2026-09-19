// SPDX-License-Identifier: BUSL-1.1

/**
 * The DoH RCODE seam.
 *
 * `queryDnsRecords` projects a DoH response down to `string[]`, which erases the
 * difference between NOERROR-with-no-answers (this name publishes no such record — a
 * measurement) and SERVFAIL/REFUSED (the resolver could not answer — no measurement at
 * all). DoH returns HTTP 200 for both, so nothing throws and a check reading the strings
 * records a confident absence for a control it never observed.
 *
 * These cases pin the sibling projection that keeps the rcode, and pin that the legacy
 * `string[]` entry points are unchanged for the call sites still on them.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { createDohResponse, setupFetchMock } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => {
	restore();
});

const TXT = 16;

/** Mock DoH: HTTP 200 carrying `status`, with the given answers (default: none). */
function mockDoh(status: number, answers: Array<{ name: string; type: number; TTL: number; data: string }> = []): void {
	globalThis.fetch = vi.fn().mockResolvedValue(createDohResponse([{ name: '_dmarc.example.com', type: TXT }], answers, { status }));
}

const noSecondary = { retries: 0, confirmWithSecondaryOnEmpty: false } as const;

describe('queryDnsRecordsWithRcode', () => {
	it('reports NOERROR-with-no-answers as a conclusive, measured absence', async () => {
		mockDoh(0);
		const { queryDnsRecordsWithRcode } = await import('../src/lib/dns-records');

		expect(await queryDnsRecordsWithRcode('_dmarc.example.com', 'TXT', noSecondary)).toEqual({
			records: [],
			rcode: 0,
			inconclusive: false,
		});
	});

	it('reports SERVFAIL as inconclusive — the empty answer set is not evidence of absence', async () => {
		mockDoh(2);
		const { queryDnsRecordsWithRcode } = await import('../src/lib/dns-records');

		expect(await queryDnsRecordsWithRcode('_dmarc.example.com', 'TXT', noSecondary)).toEqual({
			records: [],
			rcode: 2,
			inconclusive: true,
		});
	});

	it('reports REFUSED as inconclusive', async () => {
		mockDoh(5);
		const { queryDnsRecordsWithRcode } = await import('../src/lib/dns-records');

		expect((await queryDnsRecordsWithRcode('_dmarc.example.com', 'TXT', noSecondary)).inconclusive).toBe(true);
	});

	it('treats NXDOMAIN as conclusive — "this name does not exist" IS a measurement', async () => {
		mockDoh(3);
		const { queryDnsRecordsWithRcode } = await import('../src/lib/dns-records');

		expect(await queryDnsRecordsWithRcode('_dmarc.example.com', 'TXT', noSecondary)).toEqual({
			records: [],
			rcode: 3,
			inconclusive: false,
		});
	});

	it('returns the answer data alongside the rcode on the happy path', async () => {
		mockDoh(0, [{ name: '_dmarc.example.com', type: TXT, TTL: 300, data: '"v=DMARC1; p=reject"' }]);
		const { queryDnsRecordsWithRcode } = await import('../src/lib/dns-records');

		expect(await queryDnsRecordsWithRcode('_dmarc.example.com', 'TXT', noSecondary)).toEqual({
			records: ['"v=DMARC1; p=reject"'],
			rcode: 0,
			inconclusive: false,
		});
	});
});

describe('queryTxtRecordsWithRcode', () => {
	it('carries the rcode through the TXT unescape/concatenate projection', async () => {
		mockDoh(0, [{ name: '_dmarc.example.com', type: TXT, TTL: 300, data: '"v=DMARC1\\; p=reject" "\\; rua=mailto:d@example.com"' }]);
		const { queryTxtRecordsWithRcode } = await import('../src/lib/dns-records');

		expect(await queryTxtRecordsWithRcode('_dmarc.example.com', noSecondary)).toEqual({
			records: ['v=DMARC1; p=reject; rua=mailto:d@example.com'],
			rcode: 0,
			inconclusive: false,
		});
	});

	it('flags a _dmarc SERVFAIL as inconclusive instead of an empty TXT set', async () => {
		mockDoh(2);
		const { queryTxtRecordsWithRcode } = await import('../src/lib/dns-records');

		expect(await queryTxtRecordsWithRcode('_dmarc.example.com', noSecondary)).toEqual({
			records: [],
			rcode: 2,
			inconclusive: true,
		});
	});
});

describe('legacy string[] entry points are unchanged', () => {
	it('queryDnsRecords still returns a bare empty array on SERVFAIL (no call-site break)', async () => {
		mockDoh(2);
		const { queryDnsRecords } = await import('../src/lib/dns-records');

		expect(await queryDnsRecords('_dmarc.example.com', 'TXT', noSecondary)).toEqual([]);
	});

	it('queryTxtRecords still unescapes and returns records on NOERROR', async () => {
		mockDoh(0, [{ name: '_dmarc.example.com', type: TXT, TTL: 300, data: '"v=DMARC1\\; p=none"' }]);
		const { queryTxtRecords } = await import('../src/lib/dns-records');

		expect(await queryTxtRecords('_dmarc.example.com', noSecondary)).toEqual(['v=DMARC1; p=none']);
	});
});
