// SPDX-License-Identifier: BUSL-1.1

/**
 * Unit tests for forward SPF-chain extraction (`extractSeedSpfIncludes`).
 *
 * Signal: walk the seed's own SPF `include:` / `redirect=` chain and emit
 * every different registrable apex as a same-organization candidate
 * (confidence 0.85). Closes the discovery gap that left Nike-style brands
 * — whose regional ccTLD apexes appear ONLY in the seed's authoritative
 * mail-policy chain — invisible to the corroboration-only `spf_include`
 * detector.
 */

import { describe, it, expect, vi } from 'vitest';
import { extractSeedSpfIncludes } from '../../../src/tenants/discovery/spf-include-detector';

/** DoH stub returning TXT records keyed by domain. Values are SPF strings (no surrounding quotes). */
function mockDohTxt(byDomain: Record<string, string[]>): typeof fetch {
	return vi.fn(async (input: RequestInfo | URL): Promise<Response> => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
		const u = new URL(url);
		const name = (u.searchParams.get('name') ?? '').toLowerCase().replace(/\.$/, '');
		const type = u.searchParams.get('type');
		if (type !== '16' && type !== 'TXT') {
			return new Response(JSON.stringify({ Status: 3, Answer: [] }));
		}
		const recs = byDomain[name];
		if (!recs || recs.length === 0) {
			return new Response(JSON.stringify({ Status: 0, Answer: [] }));
		}
		const txts = recs.map((data) => ({ name, type: 16, TTL: 300, data: `"${data}"` }));
		return new Response(JSON.stringify({ Status: 0, Answer: txts }), { status: 200 });
	}) as unknown as typeof fetch;
}

describe('extractSeedSpfIncludes', () => {
	it('Nike-style: surfaces ccTLD sibling apex, dedups self-apex', async () => {
		const dohFn = mockDohTxt({
			'brand-zeta.example.com': ['v=spf1 include:_spf.brand-zeta.example.com include:spf.brand-zeta-eu.example.net -all'],
			'_spf.brand-zeta.example.com': ['v=spf1 include:_spf.google.com -all'],
			'spf.brand-zeta-eu.example.net': ['v=spf1 ip4:192.0.2.1 -all'],
		});
		const result = await extractSeedSpfIncludes('brand-zeta.example.com', { dohFn });
		expect(result.queryStatus).toBe('ok');
		// brand-zeta.example.com is the seed apex → dedup'd. _spf.google.com is shared infra → skipped.
		// Only the different registered apex should surface.
		const apexes = result.candidates.map((c) => c.apex).sort();
		expect(apexes).toEqual(['example.net']);
		expect(result.candidates[0].confidence).toBe(0.85);
		expect(result.candidates[0].depth).toBe(1);
	});

	it('skips Microsoft 365 shared-provider include', async () => {
		const dohFn = mockDohTxt({
			'acme.com': ['v=spf1 include:spf.protection.outlook.com -all'],
			'spf.protection.outlook.com': ['v=spf1 ip4:192.0.2.1 -all'],
		});
		const result = await extractSeedSpfIncludes('acme.com', { dohFn });
		expect(result.queryStatus).toBe('ok');
		expect(result.candidates).toHaveLength(0);
	});

	it('skips Google, Amazon SES, SendGrid, Mailchimp shared providers', async () => {
		const dohFn = mockDohTxt({
			'acme.com': [
				'v=spf1 include:_spf.google.com include:amazonses.com include:sendgrid.net include:servers.mcsv.net -all',
			],
		});
		const result = await extractSeedSpfIncludes('acme.com', { dohFn });
		expect(result.candidates).toHaveLength(0);
	});

	it('recurses into seed-apex includes and emits a different apex at depth 2', async () => {
		const dohFn = mockDohTxt({
			'acme.com': ['v=spf1 include:l1.acme.com -all'],
			'l1.acme.com': ['v=spf1 include:l2.someotherbrand.com -all'],
			'l2.someotherbrand.com': ['v=spf1 ip4:192.0.2.1 -all'],
		});
		const result = await extractSeedSpfIncludes('acme.com', { dohFn });
		expect(result.queryStatus).toBe('ok');
		const apexes = result.candidates.map((c) => c.apex);
		expect(apexes).toEqual(['someotherbrand.com']);
		expect(result.candidates[0].depth).toBe(2);
	});

	it('depth cap: chain of 6 distinct apexes emits 5, truncates the 6th', async () => {
		const dohFn = mockDohTxt({
			'seed.com': ['v=spf1 include:a1.com -all'],
			'a1.com': ['v=spf1 include:a2.com -all'],
			'a2.com': ['v=spf1 include:a3.com -all'],
			'a3.com': ['v=spf1 include:a4.com -all'],
			'a4.com': ['v=spf1 include:a5.com -all'],
			'a5.com': ['v=spf1 include:a6.com -all'],
			'a6.com': ['v=spf1 ip4:192.0.2.1 -all'],
		});
		const result = await extractSeedSpfIncludes('seed.com', { dohFn });
		const apexes = result.candidates.map((c) => c.apex).sort();
		expect(apexes).toEqual(['a1.com', 'a2.com', 'a3.com', 'a4.com', 'a5.com']);
		expect(apexes).not.toContain('a6.com');
	});

	it('handles cycles without hanging', async () => {
		const dohFn = mockDohTxt({
			'seed.com': ['v=spf1 include:a.com -all'],
			'a.com': ['v=spf1 include:b.com -all'],
			'b.com': ['v=spf1 include:a.com -all'],
		});
		const result = await extractSeedSpfIncludes('seed.com', { dohFn });
		expect(result.queryStatus).toBe('ok');
		// Each apex emitted once (not infinitely).
		const apexes = result.candidates.map((c) => c.apex).sort();
		expect(apexes).toEqual(['a.com', 'b.com']);
	});

	it('handles seed with no SPF record at all', async () => {
		const dohFn = mockDohTxt({ 'seed.com': [] });
		const result = await extractSeedSpfIncludes('seed.com', { dohFn });
		expect(result.queryStatus).toBe('no_spf');
		expect(result.candidates).toHaveLength(0);
	});

	it('handles seed SPF with no includes (ip-only)', async () => {
		const dohFn = mockDohTxt({
			'seed.com': ['v=spf1 ip4:192.0.2.1 -all'],
		});
		const result = await extractSeedSpfIncludes('seed.com', { dohFn });
		expect(result.queryStatus).toBe('ok');
		expect(result.candidates).toHaveLength(0);
	});

	it('respects `redirect=` mechanism (RFC 7208) as a chain target', async () => {
		const dohFn = mockDohTxt({
			'seed.com': ['v=spf1 redirect=spf.otherbrand.com'],
			'spf.otherbrand.com': ['v=spf1 ip4:192.0.2.1 -all'],
		});
		const result = await extractSeedSpfIncludes('seed.com', { dohFn });
		expect(result.candidates.map((c) => c.apex)).toEqual(['otherbrand.com']);
	});

	it('ignores macro-bearing include tokens (cannot resolve to a stable apex)', async () => {
		// SPF sender-IP macro `%{ir}.spf.example.com` cannot resolve to a
		// stable apex without a real sender — skip cleanly.
		const macroToken = ['v=spf1 include:%{ir}.spf.example.com -all'];
		const dohFn = mockDohTxt({ 'seed.com': macroToken });
		const result = await extractSeedSpfIncludes('seed.com', { dohFn });
		expect(result.candidates).toHaveLength(0);
	});

	it('rejects invalid seed (programmer error)', async () => {
		await expect(extractSeedSpfIncludes('not a domain')).rejects.toThrow(/^Domain validation failed:/);
	});

	it('budget exhaustion returns partial results with budget_exceeded status', async () => {
		// DoH that takes longer than the budget on every call.
		const slowFn: typeof fetch = vi.fn(async (input: RequestInfo | URL) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			const u = new URL(url);
			const name = (u.searchParams.get('name') ?? '').toLowerCase().replace(/\.$/, '');
			await new Promise((r) => setTimeout(r, 80));
			if (name === 'seed.com') {
				return new Response(
					JSON.stringify({
						Status: 0,
						Answer: [{ name, type: 16, TTL: 300, data: '"v=spf1 include:nextbrand.com -all"' }],
					}),
				);
			}
			return new Response(JSON.stringify({ Status: 0, Answer: [] }));
		}) as unknown as typeof fetch;

		const result = await extractSeedSpfIncludes('seed.com', { dohFn: slowFn, budgetMs: 50 });
		expect(result.queryStatus).toBe('budget_exceeded');
	});

	it('handles two-label PSL TLD (co.uk): seed sub.example.co.uk → sibling.co.uk emitted as full apex', async () => {
		const dohFn = mockDohTxt({
			'example.co.uk': ['v=spf1 include:_spf.sibling.co.uk -all'],
			'_spf.sibling.co.uk': ['v=spf1 ip4:192.0.2.1 -all'],
		});
		const result = await extractSeedSpfIncludes('example.co.uk', { dohFn });
		expect(result.candidates.map((c) => c.apex)).toEqual(['sibling.co.uk']);
	});
});
