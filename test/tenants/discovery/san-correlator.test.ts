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
	const encoder = new TextEncoder();
	const uint8 = encoder.encode(text);
	return new Response(uint8, {
		status: 200,
		headers: { 'content-type': 'application/json', 'content-length': String(uint8.length) },
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
				name_value: `foo.com\nsibling${String(i).padStart(3, '0')}.com`,
			});
		}
		const fetchFn = mockFetchOk(entries);
		const result = await correlateSans('foo.com', { fetchFn, maxCertsPerDomain: 10 });
		expect(result.queryStatus).toBe('ok');
		// Streaming processes first 10 entries from the "server" response.
		expect(result.coOwnedDomains.length).toBe(10);
		const expected = Array.from({ length: 10 }, (_, k) => `sibling${String(k).padStart(3, '0')}.com`).sort();
		expect(result.coOwnedDomains).toEqual(expected);
	});

	it('aborts early on signal saturation', async () => {
		const entries: CrtShFixtureEntry[] = [];
		// 1. Initial discovery
		entries.push({ id: 1, name_value: 'foo.com\nsibling.com' });
		// 2. 101 redundant entries (saturation threshold is 100)
		for (let i = 0; i < 101; i++) {
			entries.push({ id: i + 2, name_value: 'foo.com\nsibling.com' });
		}
		// 3. This one should NOT be reached
		entries.push({ id: 999, name_value: 'foo.com\nnever-found.com' });

		const fetchFn = mockFetchOk(entries);
		const result = await correlateSans('foo.com', { fetchFn, maxCertsPerDomain: 500 });
		expect(result.queryStatus).toBe('ok');
		expect(result.coOwnedDomains).toEqual(['sibling.com']);
		expect(result.coOwnedDomains).not.toContain('never-found.com');
	});

	it('throws on invalid seed input with the expected error prefix', async () => {
		await expect(correlateSans('not a domain')).rejects.toThrow(/^Domain validation failed:/);
	});

	it('returns rate_limited status on 429 without throwing', async () => {
		const fetchFn = vi.fn().mockResolvedValue(new Response('rate', { status: 429 })) as unknown as typeof fetch;
		const result = await correlateSans('foo.com', { fetchFn, maxRetries: 0 });
		expect(result.queryStatus).toBe('rate_limited');
		expect(result.coOwnedDomains).toEqual([]);
	});

	it('returns timeout status when fetch throws an AbortError', async () => {
		const abortErr = new Error('aborted');
		abortErr.name = 'AbortError';
		const fetchFn = vi.fn().mockRejectedValue(abortErr) as unknown as typeof fetch;
		const result = await correlateSans('foo.com', { fetchFn, maxRetries: 0 });
		expect(result.queryStatus).toBe('timeout');
		expect(result.coOwnedDomains).toEqual([]);
	});

	it('returns error status on a generic network failure without throwing', async () => {
		const fetchFn = vi.fn().mockRejectedValue(new TypeError('network down')) as unknown as typeof fetch;
		const result = await correlateSans('foo.com', { fetchFn, maxRetries: 0 });
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

	it('retries on transient error and surfaces eventual success', async () => {
		const okResponse = jsonResponse([{ id: 1, name_value: 'foo.com\nbar.com' }]);
		const fetchFn = vi
			.fn<typeof fetch>()
			.mockRejectedValueOnce(new TypeError('network down'))
			.mockResolvedValueOnce(new Response('boom', { status: 503 }))
			.mockResolvedValueOnce(okResponse);
		const sleepFn = vi.fn<(ms: number) => Promise<void>>().mockResolvedValue(undefined);
		const result = await correlateSans('foo.com', { fetchFn, sleepFn, maxRetries: 2, initialBackoffMs: 1 });
		expect(result.queryStatus).toBe('ok');
		expect(result.coOwnedDomains).toEqual(['bar.com']);
		expect(fetchFn).toHaveBeenCalledTimes(3);
		expect(sleepFn).toHaveBeenCalledTimes(2);
	});

	it('retries on rate_limited (429) before giving up', async () => {
		const fetchFn = vi
			.fn<typeof fetch>()
			.mockResolvedValue(new Response('rate', { status: 429 }));
		const sleepFn = vi.fn<(ms: number) => Promise<void>>().mockResolvedValue(undefined);
		const result = await correlateSans('foo.com', { fetchFn, sleepFn, maxRetries: 2, initialBackoffMs: 1 });
		expect(result.queryStatus).toBe('rate_limited');
		expect(fetchFn).toHaveBeenCalledTimes(3);
		expect(sleepFn).toHaveBeenCalledTimes(2);
	});

	it('returns last attempt status after exhausting retries', async () => {
		const fetchFn = vi
			.fn<typeof fetch>()
			.mockRejectedValueOnce(new TypeError('first'))
			.mockResolvedValueOnce(new Response('rate', { status: 429 }))
			.mockRejectedValueOnce(new TypeError('third'));
		const sleepFn = vi.fn<(ms: number) => Promise<void>>().mockResolvedValue(undefined);
		const result = await correlateSans('foo.com', { fetchFn, sleepFn, maxRetries: 2, initialBackoffMs: 1 });
		// Last attempt rejected → 'error' status
		expect(result.queryStatus).toBe('error');
		expect(fetchFn).toHaveBeenCalledTimes(3);
	});

	it('uses bv-certstream service binding when provided and returns siblings', async () => {
		const csFetch = vi.fn<typeof fetch>().mockResolvedValue(
			Response.json({
				domain: 'foo.com',
				names: ['bar.com', 'baz.com', '*.foo.com', 'foo.com', 'shop.foo.com', 'not a domain', 'alpha.com'],
				certificateCount: 5,
				timedOut: false,
				cached: true,
			}),
		);
		const directFetch = vi.fn() as unknown as typeof fetch;
		const result = await correlateSans('foo.com', {
			certstream: { fetch: csFetch },
			fetchFn: directFetch,
			maxRetries: 0,
		});
		expect(result.queryStatus).toBe('ok');
		expect(result.coOwnedDomains).toEqual(['alpha.com', 'bar.com', 'baz.com']);
		expect(csFetch).toHaveBeenCalledTimes(1);
		const callUrl = (csFetch.mock.calls[0][0] as string);
		expect(callUrl).toContain('/sans?domain=foo.com');
		// Direct crt.sh fallback must not have been invoked.
		expect(directFetch).not.toHaveBeenCalled();
	});

	it('falls back to direct crt.sh when certstream binding fails', async () => {
		const csFetch = vi.fn<typeof fetch>().mockResolvedValue(new Response('boom', { status: 503 }));
		const directFetch = mockFetchOk([{ id: 7, name_value: 'foo.com\nfallback-sibling.com' }]);
		const sleepFn = vi.fn<(ms: number) => Promise<void>>().mockResolvedValue(undefined);
		const result = await correlateSans('foo.com', {
			certstream: { fetch: csFetch },
			fetchFn: directFetch,
			sleepFn,
			maxRetries: 0,
		});
		expect(result.queryStatus).toBe('ok');
		expect(result.coOwnedDomains).toEqual(['fallback-sibling.com']);
		expect(csFetch).toHaveBeenCalledTimes(1);
		expect(directFetch).toHaveBeenCalledTimes(1);
	});

	it('falls back when certstream response sets error or timedOut', async () => {
		const csFetch = vi.fn<typeof fetch>().mockResolvedValue(
			Response.json({ domain: 'foo.com', names: [], certificateCount: 0, timedOut: true, cached: false }),
		);
		const directFetch = mockFetchOk([{ id: 1, name_value: 'foo.com\nrecovered.com' }]);
		const result = await correlateSans('foo.com', {
			certstream: { fetch: csFetch },
			fetchFn: directFetch,
			maxRetries: 0,
		});
		expect(result.queryStatus).toBe('ok');
		expect(result.coOwnedDomains).toEqual(['recovered.com']);
		expect(directFetch).toHaveBeenCalledTimes(1);
	});

	it('returns partial certstream SAN names when the service times out after collecting data', async () => {
		const csFetch = vi.fn<typeof fetch>().mockResolvedValue(
			Response.json({
				domain: 'foo.com',
				names: ['partial-one.com', 'partial-two.com', 'shop.foo.com'],
				certificateCount: 50,
				timedOut: true,
				cached: false,
			}),
		);
		const directFetch = vi.fn() as unknown as typeof fetch;
		const result = await correlateSans('foo.com', {
			certstream: { fetch: csFetch },
			fetchFn: directFetch,
			maxRetries: 0,
		});

		expect(result.queryStatus).toBe('partial');
		expect(result.coOwnedDomains).toEqual(['partial-one.com', 'partial-two.com']);
		expect(directFetch).not.toHaveBeenCalled();
	});
});
