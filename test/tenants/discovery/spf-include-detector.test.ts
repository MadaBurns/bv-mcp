// SPDX-License-Identifier: BUSL-1.1
/**
 * Unit tests for the SPF-include ownership detector.
 *
 * Signal: candidate's SPF record includes `_spf.SEED.com` (or any subdomain
 * of the seed) → seed's operator controls the candidate's mail authentication
 * policy, near-deterministic ownership evidence.
 */

import { describe, it, expect, vi } from 'vitest';
import { detectSpfInclude } from '../../../src/tenants/discovery/spf-include-detector';

/** Mock DoH returning TXT records keyed by domain. Values are SPF strings. */
function mockDohTxt(byDomain: Record<string, string[]>): typeof fetch {
	return vi.fn(async (input: RequestInfo | URL): Promise<Response> => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
		const u = new URL(url);
		const name = (u.searchParams.get('name') ?? '').toLowerCase().replace(/\.$/, '');
		const type = u.searchParams.get('type');
		if (type !== '16' && type !== 'TXT') return new Response(JSON.stringify({ Status: 3, Answer: [] }));
		const txts = (byDomain[name] ?? []).map((data) => ({ name, type: 16, TTL: 300, data: `"${data}"` }));
		return new Response(JSON.stringify({ Status: 0, Answer: txts }), { status: 200 });
	}) as unknown as typeof fetch;
}

describe('detectSpfInclude', () => {
	it('candidate SPF includes _spf.seed.com → consolidated, conf >= 0.85', async () => {
		const dohFn = mockDohTxt({
			'apple.fr': ['v=spf1 include:_spf.apple.com ~all'],
		});
		const result = await detectSpfInclude('apple.com', {
			candidateDomains: ['apple.fr'],
			dohFn,
		});
		expect(result.queryStatus).toBe('ok');
		expect(result.coOwnedDomains).toHaveLength(1);
		expect(result.coOwnedDomains[0].domain).toBe('apple.fr');
		expect(result.coOwnedDomains[0].confidence).toBeGreaterThanOrEqual(0.85);
		expect((result.coOwnedDomains[0].evidence as { include: string }).include).toBe('_spf.apple.com');
	});

	it('candidate SPF includes seed.com directly → consolidated', async () => {
		const dohFn = mockDohTxt({
			'brand-zeta-de.example.net': ['v=spf1 include:brand-zeta.example.com -all'],
		});
		const result = await detectSpfInclude('brand-zeta.example.com', {
			candidateDomains: ['brand-zeta-de.example.net'],
			dohFn,
		});
		expect(result.coOwnedDomains).toHaveLength(1);
	});

	it('candidate SPF includes shared provider (google.com) → no signal', async () => {
		const dohFn = mockDohTxt({
			'foo.com': ['v=spf1 include:_spf.google.com ~all'],
		});
		const result = await detectSpfInclude('google.com', {
			candidateDomains: ['foo.com'],
			dohFn,
		});
		// google.com is its own seed — but foo.com including google.com's SPF is just SaaS usage, not ownership.
		// Detector should treat shared SPF providers as non-evidence.
		expect(result.coOwnedDomains).toHaveLength(0);
	});

	it('recursive include reaching seed → consolidated (bounded depth)', async () => {
		const dohFn = mockDohTxt({
			'brand-zeta-fr.example.net': ['v=spf1 include:_outbound.brand-zeta-fr.example.net -all'],
			'_outbound.brand-zeta-fr.example.net': ['v=spf1 include:_spf.brand-zeta.example.com ~all'],
		});
		const result = await detectSpfInclude('brand-zeta.example.com', {
			candidateDomains: ['brand-zeta-fr.example.net'],
			dohFn,
		});
		expect(result.coOwnedDomains).toHaveLength(1);
		expect(result.coOwnedDomains[0].domain).toBe('brand-zeta-fr.example.net');
	});

	it('SPF lookup limit respected (RFC 7208 max 10) — does not infinite-loop on cyclic includes', async () => {
		const dohFn = mockDohTxt({
			'a.com': ['v=spf1 include:b.com'],
			'b.com': ['v=spf1 include:a.com'],
		});
		const result = await detectSpfInclude('brand-zeta.example.com', {
			candidateDomains: ['a.com'],
			dohFn,
		});
		expect(result.queryStatus).toBe('ok');
		expect(result.coOwnedDomains).toHaveLength(0);
	});

	it('no SPF record on candidate → no signal', async () => {
		const dohFn = mockDohTxt({ 'foo.com': [] });
		const result = await detectSpfInclude('brand-zeta.example.com', {
			candidateDomains: ['foo.com'],
			dohFn,
		});
		expect(result.coOwnedDomains).toHaveLength(0);
	});

	it('multiple TXT records, only one is SPF', async () => {
		const dohFn = mockDohTxt({
			'apple.fr': ['google-site-verification=abc123', 'v=spf1 include:_spf.apple.com ~all'],
		});
		const result = await detectSpfInclude('apple.com', {
			candidateDomains: ['apple.fr'],
			dohFn,
		});
		expect(result.coOwnedDomains).toHaveLength(1);
	});

	it('rejects invalid seed', async () => {
		await expect(detectSpfInclude('not a domain', { candidateDomains: [] })).rejects.toThrow(/^Domain validation failed:/);
	});
});
