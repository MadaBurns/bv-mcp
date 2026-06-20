// SPDX-License-Identifier: BUSL-1.1

/**
 * R6: scan_domain's ~19-way DoH fan-out is bounded by a per-scan
 * outbound-concurrency semaphore (Semaphore in src/lib/semaphore.ts), threaded
 * into scanDns.dnsSemaphore and sized by SCAN_DNS_CONCURRENCY (env-overridable
 * via runtimeOptions.dnsConcurrency).
 *
 * These tests instrument the fetch mock to record the PEAK number of DoH
 * requests in flight simultaneously, then assert:
 *   1. with dnsConcurrency=N the peak never exceeds N, even though the scan
 *      issues many more than N total DoH queries;
 *   2. the cap is the binding constraint — an UNBOUNDED control run (large N)
 *      overlaps strictly more than the capped run;
 *   3. scan output/score is byte-identical whether bounded tightly or not
 *      (the semaphore only schedules connections — it must not change results).
 */

import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse, txtResponse, nsResponse, caaResponse, dnssecResponse, httpResponse } from './helpers/dns-mock';
import { IN_MEMORY_CACHE } from '../src/lib/cache';

const { restore } = setupFetchMock();

beforeEach(() => IN_MEMORY_CACHE.clear());
afterEach(() => restore());

interface ConcurrencyTracker {
	peakDoh: number;
	totalDoh: number;
}

/**
 * Installs a fetch mock that, for every DoH (cloudflare-dns.com / dns.google)
 * request, increments an in-flight counter, yields to the event loop via a real
 * setTimeout so concurrent calls actually overlap, then decrements — recording
 * the peak overlap. Non-DoH (HTTPS) requests resolve immediately and are not
 * counted, since the semaphore only guards DoH fetches.
 */
function mockWithConcurrencyTracking(): ConcurrencyTracker {
	const tracker: ConcurrencyTracker = { peakDoh: 0, totalDoh: 0 };
	let inFlight = 0;

	globalThis.fetch = vi.fn().mockImplementation(async (input: string | URL | Request) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
		const isDoh = url.includes('cloudflare-dns.com') || url.includes('dns.google');

		if (isDoh) {
			inFlight++;
			tracker.totalDoh++;
			if (inFlight > tracker.peakDoh) tracker.peakDoh = inFlight;
			// Hold the slot across a real timer tick so siblings overlap.
			await new Promise((r) => setTimeout(r, 5));
			try {
				return resolveDoh(url);
			} finally {
				inFlight--;
			}
		}

		// HTTPS (SSL / MTA-STS policy / HTTP security) — not semaphore-guarded.
		return httpResponse('OK');
	});

	return tracker;
}

/** Reasonable DoH responses keyed by record type, mirroring scan-domain.spec's mock. */
function resolveDoh(url: string): Response {
	if (url.includes('type=TXT') || url.includes('type=16')) {
		if (url.includes('_dmarc.')) return txtResponse('_dmarc.example.com', ['v=DMARC1; p=reject']);
		if (url.includes('_domainkey.')) return txtResponse('default._domainkey.example.com', ['v=DKIM1; k=rsa; p=MIGf']);
		if (url.includes('_mta-sts.')) return txtResponse('_mta-sts.example.com', ['v=STSv1; id=20240101']);
		if (url.includes('_smtp._tls.')) return txtResponse('_smtp._tls.example.com', ['v=TLSRPTv1; rua=mailto:tls@example.com']);
		if (url.includes('default._bimi.')) return txtResponse('default._bimi.example.com', ['v=BIMI1; l=https://example.com/logo.svg']);
		return txtResponse('example.com', ['v=spf1 include:_spf.google.com -all']);
	}
	if (url.includes('type=NS') || url.includes('type=2')) return nsResponse('example.com', ['ns1.example.com.', 'ns2.example.com.']);
	if (url.includes('type=CAA') || url.includes('type=257')) return caaResponse('example.com', ['0 issue "letsencrypt.org"']);
	if (url.includes('type=A') || url.includes('type=1')) return dnssecResponse('example.com', true);
	return createDohResponse([], []);
}

/**
 * Serializes the result-bearing fields, then neutralizes the one legitimately
 * per-run-random token: the subdomain-takeover wildcard probe nonce
 * (`_bv-probe-<rand>.<domain>`). That nonce is unrelated to DoH concurrency, so
 * normalizing it lets us assert true result-equality across cap settings.
 */
function stableShape(result: { score: unknown; checks: unknown[]; maturity: unknown }) {
	return JSON.stringify({ score: result.score, maturity: result.maturity, checks: result.checks }).replace(
		/_bv-probe-[a-z0-9]+\./g,
		'_bv-probe-<nonce>.',
	);
}

describe('scan_domain DoH outbound-concurrency semaphore (R6)', () => {
	it('never exceeds dnsConcurrency=N concurrent DoH fetches, despite many total queries', async () => {
		const tracker = mockWithConcurrencyTracking();
		const { scanDomain } = await import('../src/tools/scan-domain');

		const N = 3;
		const result = await scanDomain('example.com', undefined, { forceRefresh: true, dnsConcurrency: N });

		expect(result.domain).toBe('example.com');
		// Sanity: the scan really did fan out far more queries than the cap.
		expect(tracker.totalDoh).toBeGreaterThan(N);
		// The load-bearing assertion: peak in-flight DoH never exceeded the cap.
		expect(tracker.peakDoh).toBeLessThanOrEqual(N);
		expect(tracker.peakDoh).toBeGreaterThan(0);
	});

	it('cap binds: a tight cap overlaps strictly less than an unbounded run', async () => {
		const { scanDomain } = await import('../src/tools/scan-domain');

		IN_MEMORY_CACHE.clear();
		const tight = mockWithConcurrencyTracking();
		await scanDomain('example.com', undefined, { forceRefresh: true, dnsConcurrency: 2 });

		IN_MEMORY_CACHE.clear();
		const wide = mockWithConcurrencyTracking();
		await scanDomain('example.com', undefined, { forceRefresh: true, dnsConcurrency: 50 });

		expect(tight.peakDoh).toBeLessThanOrEqual(2);
		// With a wide cap the same fan-out overlaps more — proving the semaphore,
		// not some other serialization, is what bounded the tight run.
		expect(wide.peakDoh).toBeGreaterThan(tight.peakDoh);
	});

	it('produces identical scan output regardless of the concurrency cap (results unchanged)', async () => {
		const { scanDomain } = await import('../src/tools/scan-domain');

		IN_MEMORY_CACHE.clear();
		mockWithConcurrencyTracking();
		const capped = await scanDomain('example.com', undefined, { forceRefresh: true, dnsConcurrency: 1 });

		IN_MEMORY_CACHE.clear();
		mockWithConcurrencyTracking();
		const uncapped = await scanDomain('example.com', undefined, { forceRefresh: true, dnsConcurrency: 50 });

		expect(stableShape(capped)).toBe(stableShape(uncapped));
	});
});
