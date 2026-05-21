// SPDX-License-Identifier: BUSL-1.1
/**
 * Unit tests for the MX-overlap ownership detector.
 *
 * Signal: candidates whose MX hosts overlap with the seed's MX hosts share
 * mail-delivery infrastructure. Confidence is downgraded when both endpoints
 * are on shared multi-tenant SaaS (Outlook/Google/Proofpoint) since that
 * indicates tenant co-residence, not ownership.
 */

import { describe, it, expect, vi } from 'vitest';
import { detectMxOverlap } from '../../../src/tenants/discovery/mx-overlap-detector';

/** Mock DoH function — returns canned MX RRsets keyed by domain. */
function mockDoh(byDomain: Record<string, string[]>): typeof fetch {
	return vi.fn(async (input: RequestInfo | URL): Promise<Response> => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
		const u = new URL(url);
		const name = (u.searchParams.get('name') ?? '').toLowerCase().replace(/\.$/, '');
		const type = u.searchParams.get('type');
		const mx = (byDomain[name] ?? []).map((host) => ({ name, type: 15, TTL: 300, data: `10 ${host}` }));
		if (type !== '15' && type !== 'MX') return new Response(JSON.stringify({ Status: 3, Answer: [] }));
		return new Response(JSON.stringify({ Status: 0, Answer: mx }), { status: 200 });
	}) as unknown as typeof fetch;
}

describe('detectMxOverlap', () => {
	it('exact MX hostname match → confidence ~ 0.7', async () => {
		const dohFn = mockDoh({
			'apple.com': ['mx-in-smtp.apple.com.'],
			'apple.fr': ['mx-in-smtp.apple.com.'],
		});
		const result = await detectMxOverlap('apple.com', {
			candidateDomains: ['apple.fr'],
			dohFn,
		});
		expect(result.queryStatus).toBe('ok');
		expect(result.coOwnedDomains).toHaveLength(1);
		expect(result.coOwnedDomains[0].domain).toBe('apple.fr');
		expect(result.coOwnedDomains[0].confidence).toBeGreaterThanOrEqual(0.7);
	});

	it('both MX hosts under seed apex → bumped to >= 0.9', async () => {
		const dohFn = mockDoh({
			'brand-zeta.example.com': ['mx1.brand-zeta.example.com.', 'mx2.brand-zeta.example.com.'],
			'brand-zeta-de.example.net': ['mx1.brand-zeta.example.com.', 'mx2.brand-zeta.example.com.'],
		});
		const result = await detectMxOverlap('brand-zeta.example.com', {
			candidateDomains: ['brand-zeta-de.example.net'],
			dohFn,
		});
		expect(result.coOwnedDomains[0].confidence).toBeGreaterThanOrEqual(0.9);
	});

	it('shared multi-tenant SaaS (e.g. outlook.com) → downgraded below 0.7', async () => {
		const dohFn = mockDoh({
			'foo.com': ['acme-com.mail.protection.outlook.com.'],
			'bar.com': ['acme-com.mail.protection.outlook.com.'],
		});
		const result = await detectMxOverlap('foo.com', {
			candidateDomains: ['bar.com'],
			dohFn,
		});
		// Same tenant string → same tenant — bump back up to medium
		expect(result.coOwnedDomains[0].confidence).toBeGreaterThanOrEqual(0.5);

		// Different tenants on same provider — should NOT yield ownership.
		const dohFn2 = mockDoh({
			'foo.com': ['foo-com.mail.protection.outlook.com.'],
			'bar.com': ['bar-com.mail.protection.outlook.com.'],
		});
		const result2 = await detectMxOverlap('foo.com', {
			candidateDomains: ['bar.com'],
			dohFn: dohFn2,
		});
		expect(result2.coOwnedDomains).toHaveLength(0);
	});

	it('partial MX overlap (1 of 3 matches) → conf ~ 0.5', async () => {
		const dohFn = mockDoh({
			'apple.com': ['mx-in-smtp.apple.com.', 'fallback.apple.com.', 'mx2.icloud.com.'],
			'apple.it': ['mx-in-smtp.apple.com.', 'something-else.com.'],
		});
		const result = await detectMxOverlap('apple.com', {
			candidateDomains: ['apple.it'],
			dohFn,
		});
		expect(result.coOwnedDomains[0].confidence).toBeGreaterThanOrEqual(0.4);
		expect(result.coOwnedDomains[0].confidence).toBeLessThan(0.8);
	});

	it('no MX on candidate → no signal', async () => {
		const dohFn = mockDoh({
			'brand-zeta.example.com': ['mx.brand-zeta.example.com.'],
			'brand-zeta-variant.example.net': [],
		});
		const result = await detectMxOverlap('brand-zeta.example.com', {
			candidateDomains: ['brand-zeta-variant.example.net'],
			dohFn,
		});
		expect(result.coOwnedDomains).toHaveLength(0);
	});

	it('no MX on seed → no signal for any candidate', async () => {
		const dohFn = mockDoh({
			'brand-zeta.example.com': [],
			'brand-zeta-de.example.net': ['mx.brand-zeta.example.com.'],
		});
		const result = await detectMxOverlap('brand-zeta.example.com', {
			candidateDomains: ['brand-zeta-de.example.net'],
			dohFn,
		});
		expect(result.coOwnedDomains).toHaveLength(0);
	});

	it('rejects invalid seed', async () => {
		await expect(detectMxOverlap('not a domain', { candidateDomains: [] })).rejects.toThrow(/^Domain validation failed:/);
	});
});
