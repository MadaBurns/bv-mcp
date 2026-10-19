// SPDX-License-Identifier: BUSL-1.1

/**
 * Covers two module-private helpers of discover-subdomains through their exported callers:
 *  - `parseRetryAfterSeconds` via `fetchCertspotterEntries` on a first-page 429 (`retryAfterSeconds`)
 *  - `cachedBanner` via `formatSubdomainDiscovery` for a fresh-window cache hit (`cached: true`)
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import type { SubdomainDiscoveryResult } from '../src/tools/discover-subdomains';

afterEach(() => {
	vi.useRealTimers();
});

async function retryAfterFor(headerValue: string | null): Promise<number | undefined> {
	const { fetchCertspotterEntries } = await import('../src/tools/discover-subdomains');
	const headers: Record<string, string> = headerValue === null ? {} : { 'Retry-After': headerValue };
	const fetchFn = vi.fn(async () => new Response('{"code":"rate_limited"}', { status: 429, headers }));
	const result = await fetchCertspotterEntries('example.com', new AbortController().signal, { fetchFn: fetchFn as unknown as typeof fetch });
	expect(fetchFn).toHaveBeenCalledTimes(1);
	expect(result.entries).toEqual([]);
	return result.retryAfterSeconds;
}

describe('Certspotter 429 Retry-After parsing', () => {
	it('reports no delay when the header is absent', async () => {
		expect(await retryAfterFor(null)).toBeUndefined();
	});

	it('reads a numeric header as seconds, rounding fractions up', async () => {
		expect(await retryAfterFor('120')).toBe(120);
		expect(await retryAfterFor('1.2')).toBe(2);
	});

	it('converts an HTTP-date header into whole seconds from now', async () => {
		vi.useFakeTimers();
		vi.setSystemTime(new Date('2026-10-19T00:00:00Z'));
		expect(await retryAfterFor('Mon, 19 Oct 2026 00:01:30 GMT')).toBe(90);
	});

	it('clamps an HTTP-date that is already in the past to one second', async () => {
		vi.useFakeTimers();
		vi.setSystemTime(new Date('2026-10-19T00:00:00Z'));
		expect(await retryAfterFor('Sun, 18 Oct 2026 00:00:00 GMT')).toBe(1);
	});

	it('ignores an unparseable header value', async () => {
		expect(await retryAfterFor('soon')).toBeUndefined();
	});
});

describe('formatSubdomainDiscovery fresh-cache notice', () => {
	function cachedResult(overrides: Partial<SubdomainDiscoveryResult>): SubdomainDiscoveryResult {
		return {
			domain: 'example.com',
			totalSubdomains: 1,
			totalCertificates: 1,
			subdomains: [{ subdomain: 'api.example.com', firstSeen: '', lastSeen: '', issuer: '', certCount: 1, isWildcard: false, isExpired: false }],
			wildcardCerts: 0,
			expiredCerts: 0,
			uniqueIssuers: [],
			issues: [],
			cached: true,
			...overrides,
		};
	}

	it.each([
		[undefined, 'CACHED (less than a minute old)'],
		[0, 'CACHED (less than a minute old)'],
		[1, 'CACHED (1 minute old)'],
		[7, 'CACHED (7 minutes old)'],
	])('renders age %s as "%s" without implying an outage', async (cacheAgeMinutes, expected) => {
		const { formatSubdomainDiscovery } = await import('../src/tools/discover-subdomains');
		const text = formatSubdomainDiscovery(cachedResult({ cacheAgeMinutes }), 'compact');
		expect(text).toContain(expected);
		expect(text).toContain('`force_refresh`');
		expect(text).not.toContain('STALE');
		expect(text).toContain('api.example.com');
	});

	it('does not show the fresh-cache notice for a live result', async () => {
		const { formatSubdomainDiscovery } = await import('../src/tools/discover-subdomains');
		const text = formatSubdomainDiscovery(cachedResult({ cached: false }), 'compact');
		expect(text).not.toContain('CACHED');
	});
});
