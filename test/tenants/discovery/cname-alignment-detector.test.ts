// SPDX-License-Identifier: BUSL-1.1
/**
 * Unit tests for the CNAME-alignment ownership detector.
 *
 * Signal: candidate's apex or `www.candidate` CNAME chain terminates at the
 * seed's apex or a subdomain of the seed. Catches Cloudflare/Akamai-fronted
 * defensive registrations that serve content from the seed's CDN tenant.
 */

import { describe, it, expect, vi } from 'vitest';
import { detectCnameAlignment } from '../../../src/tenants/discovery/cname-alignment-detector';

/** Mock DoH returning CNAME chains keyed by qname. */
function mockDohCname(byDomain: Record<string, string>): typeof fetch {
	return vi.fn(async (input: RequestInfo | URL): Promise<Response> => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
		const u = new URL(url);
		const name = (u.searchParams.get('name') ?? '').toLowerCase().replace(/\.$/, '');
		const type = u.searchParams.get('type');
		if (type !== '5' && type !== 'CNAME') return new Response(JSON.stringify({ Status: 3, Answer: [] }));
		const cname = byDomain[name];
		if (!cname) return new Response(JSON.stringify({ Status: 0, Answer: [] }), { status: 200 });
		return new Response(
			JSON.stringify({ Status: 0, Answer: [{ name, type: 5, TTL: 300, data: cname }] }),
			{ status: 200 },
		);
	}) as unknown as typeof fetch;
}

describe('detectCnameAlignment', () => {
	it('candidate apex CNAMEs to seed apex → consolidated, conf >= 0.9', async () => {
		const dohFn = mockDohCname({
			'brand-zeta-de.example.net': 'brand-zeta.example.com.',
		});
		const result = await detectCnameAlignment('brand-zeta.example.com', {
			candidateDomains: ['brand-zeta-de.example.net'],
			dohFn,
		});
		expect(result.queryStatus).toBe('ok');
		expect(result.coOwnedDomains).toHaveLength(1);
		expect(result.coOwnedDomains[0].domain).toBe('brand-zeta-de.example.net');
		expect(result.coOwnedDomains[0].confidence).toBeGreaterThanOrEqual(0.9);
	});

	it('candidate CNAMEs to subdomain of seed → consolidated', async () => {
		const dohFn = mockDohCname({
			'apple.fr': 'www.apple.com.',
		});
		const result = await detectCnameAlignment('apple.com', {
			candidateDomains: ['apple.fr'],
			dohFn,
		});
		expect(result.coOwnedDomains).toHaveLength(1);
	});

	it('candidate CNAMEs through CDN to seed → consolidated (transitive)', async () => {
		// brand-zeta-de.example.net → brand-zeta.example.com.edgesuite.net → brand-zeta.example.com (resolves via edge)
		const dohFn = mockDohCname({
			'brand-zeta-de.example.net': 'brand-zeta.example.com.edgesuite.net.',
			'brand-zeta.example.com.edgesuite.net': 'brand-zeta.example.com.',
		});
		const result = await detectCnameAlignment('brand-zeta.example.com', {
			candidateDomains: ['brand-zeta-de.example.net'],
			dohFn,
		});
		expect(result.coOwnedDomains).toHaveLength(1);
	});

	it('candidate CNAMEs to unrelated host → no signal', async () => {
		const dohFn = mockDohCname({
			'brand-zeta-variant.example.net': 'parked.godaddy.com.',
		});
		const result = await detectCnameAlignment('brand-zeta.example.com', {
			candidateDomains: ['brand-zeta-variant.example.net'],
			dohFn,
		});
		expect(result.coOwnedDomains).toHaveLength(0);
	});

	it('no CNAME on candidate → no signal', async () => {
		const dohFn = mockDohCname({});
		const result = await detectCnameAlignment('brand-zeta.example.com', {
			candidateDomains: ['brand-zeta-de.example.net'],
			dohFn,
		});
		expect(result.coOwnedDomains).toHaveLength(0);
	});

	it('chain length bounded (no infinite recursion on CNAME loop)', async () => {
		const dohFn = mockDohCname({
			'a.com': 'b.com.',
			'b.com': 'a.com.',
		});
		const result = await detectCnameAlignment('brand-zeta.example.com', {
			candidateDomains: ['a.com'],
			dohFn,
		});
		expect(result.queryStatus).toBe('ok');
		expect(result.coOwnedDomains).toHaveLength(0);
	});

	it('CNAME to CDN edge with seed-rooted pattern (e.g. brand-zeta.example.com.akadns.net) → consolidated with medium conf', async () => {
		// Direct edge alias matching seed name — strong heuristic
		const dohFn = mockDohCname({
			'brand-zeta-de.example.net': 'brand-zeta.example.com.akadns.net.',
		});
		const result = await detectCnameAlignment('brand-zeta.example.com', {
			candidateDomains: ['brand-zeta-de.example.net'],
			dohFn,
		});
		expect(result.coOwnedDomains).toHaveLength(1);
		// 0.6 < conf < 0.95 because the edge alias is not the seed itself
		expect(result.coOwnedDomains[0].confidence).toBeGreaterThanOrEqual(0.6);
	});

	it('rejects invalid seed', async () => {
		await expect(detectCnameAlignment('not a domain', { candidateDomains: [] })).rejects.toThrow(/^Domain validation failed:/);
	});
});
