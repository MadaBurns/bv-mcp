// SPDX-License-Identifier: BUSL-1.1

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { DNS_TIMEOUT_MS } from '../src/lib/config';
import type { QueryDnsOptions } from '../src/lib/dns-types';

const mockQueryDnsRecords = vi.fn(async (_domain: string, _type: string, _opts?: QueryDnsOptions): Promise<string[]> => ['A-RESULT']);
const mockQueryTxtRecords = vi.fn(async (_domain: string, _opts?: QueryDnsOptions): Promise<string[]> => ['TXT-RESULT']);

vi.mock('../src/lib/dns', async (importOriginal) => {
	const orig = await importOriginal<typeof import('../src/lib/dns')>();
	return {
		...orig,
		queryDnsRecords: (domain: string, type: string, opts?: QueryDnsOptions) => mockQueryDnsRecords(domain, type, opts),
		queryTxtRecords: (domain: string, opts?: QueryDnsOptions) => mockQueryTxtRecords(domain, opts),
	};
});

/** Options object recorded by the mocked `queryDnsRecords` / `queryTxtRecords`. */
function txtOptsArg(): QueryDnsOptions | undefined {
	return mockQueryTxtRecords.mock.calls.at(-1)?.[1];
}

function dnsOptsArg(): QueryDnsOptions | undefined {
	return mockQueryDnsRecords.mock.calls.at(-1)?.[2];
}

describe('makeQueryDNS — caller timeout is an upper bound (#674)', () => {
	beforeEach(() => {
		mockQueryDnsRecords.mockClear();
		mockQueryTxtRecords.mockClear();
	});

	afterEach(() => {
		vi.clearAllMocks();
	});

	it('returns an arity-3 function matching the DNSQueryFunction contract', async () => {
		const { makeQueryDNS } = await import('../src/lib/dns-query-adapter');
		const fn = makeQueryDNS();

		// LOAD-BEARING, not a tautology. The `: DNSQueryFunction` annotation on
		// makeQueryDNS catches a wrong option shape, a wrong return type, and an extra
		// REQUIRED parameter — but NOT a dropped one: TypeScript accepts a 2-arg
		// function wherever a 3-arg type is declared, which is exactly how #674 shipped
		// and stayed invisible. This runtime arity assertion is the only guard on that
		// direction; deleting it as "covered by the type" reopens the original bug.
		expect(fn.length).toBe(3);
		expect(typeof fn).toBe('function');

		// Structurally assignable to the published package type (compile-time assertion).
		const asContract: import('@blackveil/dns-checks').DNSQueryFunction = fn;
		expect(asContract).toBe(fn);
	});

	it('clamps a caller timeout LARGER than the Worker timeout down to the Worker value', async () => {
		const { makeQueryDNS } = await import('../src/lib/dns-query-adapter');

		// Every real caller today: `{ timeout: 5000 }` (or 4000) against the 3000 global.
		await makeQueryDNS()('example.com', 'A', { timeout: 5000 });

		// Worker value wins: no `timeoutMs` override is synthesised at all, so the
		// transport falls through to DNS_TIMEOUT_MS exactly as it does today.
		expect(dnsOptsArg()).toBeUndefined();
		expect(DNS_TIMEOUT_MS).toBeLessThan(5000);
	});

	it('clamps against an explicit Worker timeoutMs rather than the global default', async () => {
		const { makeQueryDNS } = await import('../src/lib/dns-query-adapter');
		const dnsOptions: QueryDnsOptions = { timeoutMs: 2_000 };

		await makeQueryDNS(dnsOptions)('example.com', 'A', { timeout: 5000 });

		// The Worker's own 2000 is the ceiling — the caller cannot raise it to 5000.
		expect(dnsOptsArg()).toBe(dnsOptions);
		expect(dnsOptsArg()?.timeoutMs).toBe(2_000);
	});

	it('honours a caller timeout SMALLER than the Worker timeout (may lower, never raise)', async () => {
		const { makeQueryDNS } = await import('../src/lib/dns-query-adapter');

		await makeQueryDNS()('example.com', 'A', { timeout: 1_200 });

		expect(dnsOptsArg()?.timeoutMs).toBe(1_200);
	});

	it('preserves the caller options identity fields when lowering the timeout', async () => {
		const { makeQueryDNS } = await import('../src/lib/dns-query-adapter');
		const queryCache = new Map();
		const controller = new AbortController();
		const dnsOptions: QueryDnsOptions = { queryCache, signal: controller.signal, skipSecondaryConfirmation: true };

		await makeQueryDNS(dnsOptions)('example.com', 'A', { timeout: 1_000 });

		const passed = dnsOptsArg();
		expect(passed?.timeoutMs).toBe(1_000);
		// A cloned options object must carry the scan-scoped cache/semaphore/signal
		// across, or the clamp would silently disable query dedup for that lookup.
		expect(passed?.queryCache).toBe(queryCache);
		expect(passed?.signal).toBe(controller.signal);
		expect(passed?.skipSecondaryConfirmation).toBe(true);
	});

	it('ignores a non-positive or non-finite caller timeout', async () => {
		const { makeQueryDNS } = await import('../src/lib/dns-query-adapter');
		const dnsOptions: QueryDnsOptions = { timeoutMs: 2_500 };

		for (const timeout of [0, -1, Number.NaN, Number.POSITIVE_INFINITY]) {
			await makeQueryDNS(dnsOptions)('example.com', 'A', { timeout });
			expect(dnsOptsArg()).toBe(dnsOptions);
		}
	});

	describe('no-options path is unchanged (the path every current caller takes)', () => {
		it('passes the SAME dnsOptions reference through with no options argument', async () => {
			const { makeQueryDNS } = await import('../src/lib/dns-query-adapter');
			const dnsOptions: QueryDnsOptions = { timeoutMs: 3_000, retries: 2, queryCache: new Map() };

			await makeQueryDNS(dnsOptions)('example.com', 'A');

			// Reference identity, not deep equality: no clone, no synthesised field.
			expect(dnsOptsArg()).toBe(dnsOptions);
		});

		it('passes undefined through when constructed with no dnsOptions', async () => {
			const { makeQueryDNS } = await import('../src/lib/dns-query-adapter');

			await makeQueryDNS()('example.com', 'A');
			expect(dnsOptsArg()).toBeUndefined();

			await makeQueryDNS()('example.com', 'TXT');
			expect(txtOptsArg()).toBeUndefined();
		});
	});

	describe('record-type routing', () => {
		it('routes TXT through queryTxtRecords (quote-stripping projection)', async () => {
			const { makeQueryDNS } = await import('../src/lib/dns-query-adapter');

			const result = await makeQueryDNS()('example.com', 'TXT');

			expect(result).toEqual(['TXT-RESULT']);
			expect(mockQueryTxtRecords).toHaveBeenCalledTimes(1);
			expect(mockQueryTxtRecords.mock.calls[0]?.[0]).toBe('example.com');
			expect(mockQueryDnsRecords).not.toHaveBeenCalled();
		});

		it('routes non-TXT through queryDnsRecords with the record type', async () => {
			const { makeQueryDNS } = await import('../src/lib/dns-query-adapter');

			const result = await makeQueryDNS()('example.com', 'MX');

			expect(result).toEqual(['A-RESULT']);
			expect(mockQueryDnsRecords).toHaveBeenCalledTimes(1);
			expect(mockQueryDnsRecords.mock.calls[0]?.[0]).toBe('example.com');
			expect(mockQueryDnsRecords.mock.calls[0]?.[1]).toBe('MX');
			expect(mockQueryTxtRecords).not.toHaveBeenCalled();
		});

		it('applies the clamp on the TXT branch too', async () => {
			const { makeQueryDNS } = await import('../src/lib/dns-query-adapter');

			await makeQueryDNS()('example.com', 'TXT', { timeout: 5000 });
			expect(txtOptsArg()).toBeUndefined();

			await makeQueryDNS()('example.com', 'TXT', { timeout: 900 });
			expect(txtOptsArg()?.timeoutMs).toBe(900);
		});
	});

	it('keeps the worst-case retry cost of one logical query inside PER_CHECK_TIMEOUT_MS', async () => {
		const { DNS_RETRIES, DNS_RETRY_BASE_DELAY_MS, PER_CHECK_TIMEOUT_MS } = await import('../src/lib/config');

		// One logical query = DNS_RETRIES + 1 attempts + one backoff (base + up to 50ms jitter).
		const attempts = DNS_RETRIES + 1;
		const maxBackoff = DNS_RETRIES * (DNS_RETRY_BASE_DELAY_MS + 50);

		const workerWorstCase = attempts * DNS_TIMEOUT_MS + maxBackoff;
		const honouredWorstCase = attempts * 5000 + maxBackoff;

		expect(workerWorstCase).toBeLessThan(PER_CHECK_TIMEOUT_MS);
		// This is why the caller's value is refused rather than honoured: obeying it
		// would put ONE slow lookup past safeCheck's per-check budget (#641).
		expect(honouredWorstCase).toBeGreaterThan(PER_CHECK_TIMEOUT_MS);
	});
});
