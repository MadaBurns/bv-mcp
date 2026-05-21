// SPDX-License-Identifier: BUSL-1.1
/**
 * Unit tests for the HTTP-redirect ownership detector.
 *
 * Signal: for each caller-asserted candidate, follow up to N redirects and
 * check whether the chain terminates at the seed's apex (or a subdomain of
 * the seed). Near-deterministic ownership evidence for defensive ccTLD
 * registrations.
 */

import { describe, it, expect, vi } from 'vitest';
import { detectHttpRedirect } from '../../../src/tenants/discovery/http-redirect-detector';

function mockFetch(responses: Array<{ status: number; location?: string; finalUrl?: string }>): typeof fetch {
	let i = 0;
	return vi.fn(async (input: RequestInfo | URL): Promise<Response> => {
		const r = responses[i++] ?? { status: 404 };
		const url = r.finalUrl ?? (typeof input === 'string' ? input : input instanceof URL ? input.href : input.url);
		const headers: HeadersInit = r.location ? { Location: r.location } : {};
		return new Response('', { status: r.status, headers, ...(({ url } as unknown) as ResponseInit) });
	}) as unknown as typeof fetch;
}

describe('detectHttpRedirect', () => {
	it('redirect to seed apex → consolidated, conf >= 0.9', async () => {
		// brand-zeta-de.example.net → 301 → https://www.brand-zeta.example.com/de
		const fetchFn = mockFetch([
			{ status: 301, location: 'https://www.brand-zeta.example.com/de' },
			{ status: 200, finalUrl: 'https://www.brand-zeta.example.com/de' },
		]);
		const result = await detectHttpRedirect('brand-zeta.example.com', {
			candidateDomains: ['brand-zeta-de.example.net'],
			fetchFn,
		});
		expect(result.queryStatus).toBe('ok');
		expect(result.coOwnedDomains).toHaveLength(1);
		expect(result.coOwnedDomains[0].domain).toBe('brand-zeta-de.example.net');
		expect(result.coOwnedDomains[0].confidence).toBeGreaterThanOrEqual(0.9);
		expect(result.coOwnedDomains[0].evidence.finalUrl).toMatch(/brand-zeta\.example\.com/);
	});

	it('redirect to subdomain of seed → consolidated', async () => {
		const fetchFn = mockFetch([
			{ status: 302, location: 'https://shop.apple.com/es' },
			{ status: 200, finalUrl: 'https://shop.apple.com/es' },
		]);
		const result = await detectHttpRedirect('apple.com', {
			candidateDomains: ['apple.es'],
			fetchFn,
		});
		expect(result.coOwnedDomains[0].domain).toBe('apple.es');
		expect(result.coOwnedDomains[0].confidence).toBeGreaterThanOrEqual(0.9);
	});

	it('redirect to unrelated domain → no signal', async () => {
		const fetchFn = mockFetch([
			{ status: 301, location: 'https://parked.godaddy.com/nike-de' },
			{ status: 200, finalUrl: 'https://parked.godaddy.com/nike-de' },
		]);
		const result = await detectHttpRedirect('brand-zeta.example.com', {
			candidateDomains: ['brand-zeta-de.example.net'],
			fetchFn,
		});
		expect(result.coOwnedDomains).toHaveLength(0);
		expect(result.queryStatus).toBe('ok');
	});

	it('200 OK with no redirect → no signal', async () => {
		const fetchFn = mockFetch([{ status: 200, finalUrl: 'https://brand-zeta-de.example.net' }]);
		const result = await detectHttpRedirect('brand-zeta.example.com', {
			candidateDomains: ['brand-zeta-de.example.net'],
			fetchFn,
		});
		expect(result.coOwnedDomains).toHaveLength(0);
	});

	it('4xx/5xx → status remains ok; no signal for that candidate', async () => {
		const fetchFn = mockFetch([{ status: 503, finalUrl: 'https://brand-zeta-de.example.net' }]);
		const result = await detectHttpRedirect('brand-zeta.example.com', {
			candidateDomains: ['brand-zeta-de.example.net'],
			fetchFn,
		});
		expect(result.coOwnedDomains).toHaveLength(0);
		expect(result.queryStatus).toBe('ok');
	});

	it('fetch throw → status records the failure per-candidate, but overall query is ok', async () => {
		const fetchFn = vi.fn().mockRejectedValue(new TypeError('network down')) as unknown as typeof fetch;
		const result = await detectHttpRedirect('brand-zeta.example.com', {
			candidateDomains: ['brand-zeta-de.example.net'],
			fetchFn,
		});
		expect(result.coOwnedDomains).toHaveLength(0);
		expect(result.queryStatus).toBe('ok');
	});

	it('redirect loop is bounded at maxHops', async () => {
		// 5 redirects in a chain, none reaching seed
		const fetchFn = mockFetch([
			{ status: 301, location: 'https://a.example/' },
			{ status: 301, location: 'https://b.example/' },
			{ status: 301, location: 'https://c.example/' },
			{ status: 301, location: 'https://d.example/' },
			{ status: 301, location: 'https://e.example/' },
		]);
		const result = await detectHttpRedirect('brand-zeta.example.com', {
			candidateDomains: ['brand-zeta-variant.example.net'],
			fetchFn,
			maxHops: 3,
		});
		expect(result.coOwnedDomains).toHaveLength(0);
		// Should have stopped after 3 hops max
		expect((fetchFn as unknown as { mock: { calls: unknown[] } }).mock.calls.length).toBeLessThanOrEqual(3);
	});

	it('processes multiple candidates with parallelism', async () => {
		// Three candidates, mock returns redirect-to-seed for all
		const fetchFn = vi.fn(async (input: RequestInfo | URL): Promise<Response> => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('brand-zeta-de.example.net')) {
				return new Response('', { status: 301, headers: { Location: 'https://brand-zeta.example.com/de' } });
			}
			if (url.includes('brand-zeta-fr.example.net')) {
				return new Response('', { status: 301, headers: { Location: 'https://brand-zeta.example.com/fr' } });
			}
			if (url.includes('brand-zeta-uk.example.net')) {
				return new Response('', { status: 301, headers: { Location: 'https://parked.com' } });
			}
			return new Response('', { status: 200 });
		}) as unknown as typeof fetch;
		const result = await detectHttpRedirect('brand-zeta.example.com', {
			candidateDomains: ['brand-zeta-de.example.net', 'brand-zeta-fr.example.net', 'brand-zeta-uk.example.net'],
			fetchFn,
		});
		expect(result.coOwnedDomains.map((d) => d.domain).sort()).toEqual(['brand-zeta-de.example.net', 'brand-zeta-fr.example.net']);
	});

	it('rejects invalid seed', async () => {
		await expect(detectHttpRedirect('not a domain', { candidateDomains: [] })).rejects.toThrow(/^Domain validation failed:/);
	});

	it('returns empty for empty candidate list', async () => {
		const result = await detectHttpRedirect('brand-zeta.example.com', { candidateDomains: [] });
		expect(result.coOwnedDomains).toEqual([]);
		expect(result.queryStatus).toBe('ok');
	});
});
