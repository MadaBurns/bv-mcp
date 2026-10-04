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

	describe('per-provider tenant extraction (Proofpoint)', () => {
		const run = async (byDomain: Record<string, string[]>) =>
			detectMxOverlap('foo.com', { candidateDomains: ['bar.com'], dohFn: mockDoh(byDomain) });

		it('same id behind different mxa-/mxb- rotation labels matches at the isolated-tenant weight', async () => {
			const result = await run({
				'foo.com': ['mxa-00162b01.gslb.pphosted.com.', 'mxb-00162b01.gslb.pphosted.com.'],
				'bar.com': ['mxb-00162b01.gslb.pphosted.com.'],
			});
			expect(result.coOwnedDomains).toHaveLength(1);
			expect(result.coOwnedDomains[0].confidence).toBe(0.65);
			expect(result.coOwnedDomains[0].evidence.sharedSaas).toBe(true);
			expect(result.coOwnedDomains[0].evidence.sharedTenant).toBe('pphosted.com:00162b01');
		});

		it('matches when seed and candidate list only different rotation labels or host families', async () => {
			const result = await run({
				'foo.com': ['mxa-00162b01.gslb.pphosted.com.'],
				'bar.com': ['mx0b-00162b01.pphosted.com.'],
			});
			expect(result.coOwnedDomains).toHaveLength(1);
			expect(result.coOwnedDomains[0].evidence.sharedTenant).toBe('pphosted.com:00162b01');
		});

		it('different per-customer ids on Proofpoint → no signal', async () => {
			const result = await run({
				'foo.com': ['mxa-00162b01.gslb.pphosted.com.', 'mxb-00162b01.gslb.pphosted.com.'],
				'bar.com': ['mxa-00190b01.gslb.pphosted.com.', 'mxb-00190b01.gslb.pphosted.com.'],
			});
			expect(result.coOwnedDomains).toHaveLength(0);
		});

		it('bare pphosted.com host with no extractable id keeps the shared-platform weight', async () => {
			const result = await run({
				'foo.com': ['mx.pphosted.com.'],
				'bar.com': ['mx.pphosted.com.'],
			});
			expect(result.coOwnedDomains).toHaveLength(1);
			expect(result.coOwnedDomains[0].confidence).toBe(0.5);
			expect(result.coOwnedDomains[0].evidence.sharedSaas).toBe(true);
			expect(result.coOwnedDomains[0].evidence.sharedTenant).toBeUndefined();
		});

		it('an id-shaped label that is not a verified Proofpoint format is not treated as isolated', async () => {
			const result = await run({
				'foo.com': ['mxa-notanid.gslb.pphosted.com.'],
				'bar.com': ['mxb-notanid.gslb.pphosted.com.'],
			});
			expect(result.coOwnedDomains).toHaveLength(0);
		});

		it('M365 same-tenant match is unchanged: 0.5, no sharedTenant label', async () => {
			const result = await run({
				'foo.com': ['acme-com.mail.protection.outlook.com.'],
				'bar.com': ['acme-com.mail.protection.outlook.com.'],
			});
			expect(result.coOwnedDomains).toHaveLength(1);
			expect(result.coOwnedDomains[0].confidence).toBe(0.5);
			expect(result.coOwnedDomains[0].evidence.sharedTenant).toBeUndefined();
		});
	});

	describe('per-provider tenant extraction (Forcepoint mailcontrol)', () => {
		const run = async (byDomain: Record<string, string[]>) =>
			detectMxOverlap('foo.com', { candidateDomains: ['bar.com'], dohFn: mockDoh(byDomain) });

		it('same cust id behind different -1/-2 rotation labels matches at the isolated-tenant weight', async () => {
			const result = await run({
				'foo.com': ['cust78413-1.in.mailcontrol.com.'],
				'bar.com': ['cust78413-2.in.mailcontrol.com.'],
			});
			expect(result.coOwnedDomains).toHaveLength(1);
			expect(result.coOwnedDomains[0].confidence).toBe(0.65);
			expect(result.coOwnedDomains[0].evidence.sharedSaas).toBe(true);
			expect(result.coOwnedDomains[0].evidence.sharedTenant).toBe('mailcontrol.com:78413');
		});

		it('different cust ids → no signal', async () => {
			const result = await run({
				'foo.com': ['cust78413-1.in.mailcontrol.com.', 'cust78413-2.in.mailcontrol.com.'],
				'bar.com': ['cust12345-1.in.mailcontrol.com.', 'cust12345-2.in.mailcontrol.com.'],
			});
			expect(result.coOwnedDomains).toHaveLength(0);
		});

		it('non-cust mailcontrol host (shared cluster) is not promoted: 0.5, no label', async () => {
			const result = await run({
				'foo.com': ['cluster-a.mailcontrol.com.'],
				'bar.com': ['cluster-a.mailcontrol.com.'],
			});
			expect(result.coOwnedDomains).toHaveLength(1);
			expect(result.coOwnedDomains[0].confidence).toBe(0.5);
			expect(result.coOwnedDomains[0].evidence.sharedSaas).toBe(true);
			expect(result.coOwnedDomains[0].evidence.sharedTenant).toBeUndefined();
		});
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

	it('keeps the timeout active while a response body stalls after headers', async () => {
		let requestSignal: AbortSignal | null | undefined;
		const dohFn = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
			requestSignal = init?.signal;
			let bodyController: ReadableStreamDefaultController<Uint8Array>;
			const body = new ReadableStream<Uint8Array>({ start: (controller) => (bodyController = controller) });
			init?.signal?.addEventListener('abort', () => bodyController.error(init.signal?.reason), { once: true });
			return new Response(body, { status: 200 });
		}) as unknown as typeof fetch;

		const result = await detectMxOverlap('example.com', {
			candidateDomains: ['example.net'],
			dohFn,
			timeoutMs: 5,
		});

		expect(result.coOwnedDomains).toEqual([]);
		expect(requestSignal?.aborted).toBe(true);
	});

	it('cancels an unread non-2xx DoH response body', async () => {
		const cancelled = vi.fn();
		const dohFn = vi.fn().mockResolvedValue(
			new Response(new ReadableStream<Uint8Array>({ cancel: cancelled }), { status: 502 }),
		) as unknown as typeof fetch;

		await detectMxOverlap('example.com', { candidateDomains: ['example.net'], dohFn });

		expect(cancelled).toHaveBeenCalledOnce();
	});

	it('rejects invalid seed', async () => {
		await expect(detectMxOverlap('not a domain', { candidateDomains: [] })).rejects.toThrow(/^Domain validation failed:/);
	});
});
