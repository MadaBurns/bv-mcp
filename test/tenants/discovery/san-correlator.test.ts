// SPDX-License-Identifier: BUSL-1.1

/**
 * Unit tests for the SAN-cert correlator (Phase-4 brand-discovery, tier-1 signal).
 *
 * The correlator queries crt.sh for a seed domain, extracts every Subject
 * Alternative Name from the returned certificates, and filters to sibling
 * co-owned domains (not the seed itself, not subdomains, not invalid hosts).
 *
 * Tests inject a `fetchFn` rather than spying on `safeFetch` — the implementation
 * exposes the dependency for exactly this reason.
 */

import { describe, it, expect, vi } from 'vitest';
import { correlateSans } from '../../../src/tenants/discovery/san-correlator';

interface CrtShFixtureEntry {
	id?: number;
	name_value: string;
	entry_timestamp?: string;
}

function jsonResponse(body: unknown, init?: ResponseInit): Response {
	const text = JSON.stringify(body);
	return new Response(text, {
		status: 200,
		headers: { 'content-type': 'application/json', 'content-length': String(text.length) },
		...init,
	});
}

function mockFetchOk(entries: CrtShFixtureEntry[]): typeof fetch {
	return vi.fn().mockResolvedValue(jsonResponse(entries)) as unknown as typeof fetch;
}

describe('correlateSans', () => {
	it('returns sibling SANs from a single cert (happy path)', async () => {
		const fetchFn = mockFetchOk([
			{ id: 1, name_value: 'foo.com\nbar.com\nbaz.com' },
		]);
		const result = await correlateSans('foo.com', { fetchFn });
		expect(result.queryStatus).toBe('ok');
		expect(result.coOwnedDomains).toEqual(['bar.com', 'baz.com']);
		expect(result.seedDomain).toBe('foo.com');
	});

	it('drops wildcards and subdomains of the seed', async () => {
		const fetchFn = mockFetchOk([
			{ id: 1, name_value: '*.example.com\nexample.com\nshop.example.com' },
		]);
		const result = await correlateSans('example.com', { fetchFn });
		expect(result.queryStatus).toBe('ok');
		expect(result.coOwnedDomains).toEqual([]);
	});

	it('deduplicates SANs across multiple certs and sorts the result', async () => {
		const fetchFn = mockFetchOk([
			{ id: 1, name_value: 'foo.com\nbar.com\ncharlie.com' },
			{ id: 2, name_value: 'foo.com\nbar.com\nalpha.com' },
		]);
		const result = await correlateSans('foo.com', { fetchFn });
		expect(result.queryStatus).toBe('ok');
		expect(result.coOwnedDomains).toEqual(['alpha.com', 'bar.com', 'charlie.com']);
	});

	it('caps the cert count via maxCertsPerDomain', async () => {
		const entries: CrtShFixtureEntry[] = [];
		for (let i = 0; i < 100; i++) {
			entries.push({
				id: i,
				name_value: `foo.com\nsibling${i}.com`,
				entry_timestamp: new Date(2026, 0, 1, 0, 0, i).toISOString(),
			});
		}
		const fetchFn = mockFetchOk(entries);
		const result = await correlateSans('foo.com', { fetchFn, maxCertsPerDomain: 10 });
		expect(result.queryStatus).toBe('ok');
		// Most-recent first ⇒ siblings 90..99 (10 items)
		expect(result.coOwnedDomains.length).toBe(10);
		const sortedExpected = Array.from({ length: 10 }, (_, k) => `sibling${90 + k}.com`).sort();
		expect(result.coOwnedDomains).toEqual(sortedExpected);
	});

	it('throws on invalid seed input with the expected error prefix', async () => {
		await expect(correlateSans('not a domain')).rejects.toThrow(/^Domain validation failed:/);
	});

	it('returns rate_limited status on 429 without throwing', async () => {
		const fetchFn = vi.fn().mockResolvedValue(new Response('rate', { status: 429 })) as unknown as typeof fetch;
		const result = await correlateSans('foo.com', { fetchFn });
		expect(result.queryStatus).toBe('rate_limited');
		expect(result.coOwnedDomains).toEqual([]);
	});

	it('returns timeout status when fetch throws an AbortError', async () => {
		const abortErr = new Error('aborted');
		abortErr.name = 'AbortError';
		const fetchFn = vi.fn().mockRejectedValue(abortErr) as unknown as typeof fetch;
		const result = await correlateSans('foo.com', { fetchFn });
		expect(result.queryStatus).toBe('timeout');
		expect(result.coOwnedDomains).toEqual([]);
	});

	it('returns error status on a generic network failure without throwing', async () => {
		const fetchFn = vi.fn().mockRejectedValue(new TypeError('network down')) as unknown as typeof fetch;
		const result = await correlateSans('foo.com', { fetchFn });
		expect(result.queryStatus).toBe('error');
		expect(result.coOwnedDomains).toEqual([]);
	});

	it('silently drops invalid SAN entries while keeping valid ones', async () => {
		const fetchFn = mockFetchOk([
			{ id: 1, name_value: 'valid.com\nnot a domain\nfoo.com' },
		]);
		const result = await correlateSans('foo.com', { fetchFn });
		expect(result.queryStatus).toBe('ok');
		expect(result.coOwnedDomains).toEqual(['valid.com']);
	});

	it('drops the seed itself even when present in SAN list', async () => {
		const fetchFn = mockFetchOk([
			{ id: 1, name_value: 'foo.com\nFoo.com\nbar.com' },
		]);
		const result = await correlateSans('foo.com', { fetchFn });
		expect(result.queryStatus).toBe('ok');
		expect(result.coOwnedDomains).toEqual(['bar.com']);
	});
});
