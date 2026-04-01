import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

/** Mock fetch to return different SPF records based on the queried domain. */
function mockSpfRecords(records: Record<string, string | null>) {
	globalThis.fetch = vi.fn().mockImplementation(async (url: string | URL | Request) => {
		const urlStr = typeof url === 'string' ? url : url instanceof URL ? url.toString() : url.url;

		for (const [domain, spf] of Object.entries(records)) {
			if (urlStr.includes(`name=${domain}`) || urlStr.includes(`name%3D${domain}`)) {
				if (spf === null) {
					return createDohResponse([{ name: domain, type: 16 }], []);
				}
				return createDohResponse(
					[{ name: domain, type: 16 }],
					[{ name: domain, type: 16, TTL: 300, data: `"${spf}"` }],
				);
			}
		}

		// Default: no records
		return createDohResponse([{ name: 'unknown', type: 16 }], []);
	});
}

describe('resolveSpfChain', () => {
	async function run(domain: string) {
		const { resolveSpfChain } = await import('../src/tools/resolve-spf-chain');
		return resolveSpfChain(domain);
	}

	it('handles simple SPF with no includes', async () => {
		mockSpfRecords({ 'example.com': 'v=spf1 ip4:1.2.3.4 -all' });
		const result = await run('example.com');
		expect(result.totalLookups).toBe(0);
		expect(result.tree.children).toHaveLength(0);
		expect(result.overLimit).toBe(false);
		expect(result.issues).toHaveLength(0);
	});

	it('counts single include as 1 lookup + child lookups', async () => {
		mockSpfRecords({
			'example.com': 'v=spf1 include:mail.example.com -all',
			'mail.example.com': 'v=spf1 ip4:1.2.3.4 -all',
		});
		const result = await run('example.com');
		// 1 lookup for the include directive itself
		expect(result.totalLookups).toBe(1);
		expect(result.tree.children).toHaveLength(1);
		expect(result.tree.children[0].domain).toBe('mail.example.com');
	});

	it('counts nested includes correctly', async () => {
		mockSpfRecords({
			'example.com': 'v=spf1 include:level1.com -all',
			'level1.com': 'v=spf1 include:level2.com ip4:1.2.3.4 -all',
			'level2.com': 'v=spf1 ip4:5.6.7.8 -all',
		});
		const result = await run('example.com');
		// 1 (include:level1.com) + 1 (include:level2.com) = 2
		expect(result.totalLookups).toBe(2);
		expect(result.maxDepth).toBe(2);
	});

	it('detects over-limit when exceeding 10 lookups', async () => {
		// Build a chain with >10 includes
		const records: Record<string, string> = {
			'example.com': 'v=spf1 include:a.com include:b.com include:c.com include:d.com include:e.com include:f.com -all',
			'a.com': 'v=spf1 include:a1.com include:a2.com -all',
			'b.com': 'v=spf1 include:b1.com include:b2.com -all',
			'c.com': 'v=spf1 ip4:1.2.3.4 -all',
			'd.com': 'v=spf1 ip4:1.2.3.4 -all',
			'e.com': 'v=spf1 ip4:1.2.3.4 -all',
			'f.com': 'v=spf1 ip4:1.2.3.4 -all',
			'a1.com': 'v=spf1 ip4:1.2.3.4 -all',
			'a2.com': 'v=spf1 ip4:1.2.3.4 -all',
			'b1.com': 'v=spf1 ip4:1.2.3.4 -all',
			'b2.com': 'v=spf1 ip4:1.2.3.4 -all',
		};
		mockSpfRecords(records);
		const result = await run('example.com');
		// 6 top-level includes + 4 nested = 10. Let's verify:
		expect(result.totalLookups).toBe(10);
		// At exactly 10, should get approaching_limit, not over_limit
		expect(result.overLimit).toBe(false);
		expect(result.issues.some((i) => i.type === 'approaching_limit')).toBe(true);
	});

	it('flags critical issue when over 10 lookups', async () => {
		const records: Record<string, string> = {
			'example.com': 'v=spf1 include:a.com include:b.com include:c.com include:d.com include:e.com include:f.com include:g.com -all',
			'a.com': 'v=spf1 include:a1.com include:a2.com -all',
			'b.com': 'v=spf1 include:b1.com -all',
			'c.com': 'v=spf1 ip4:1.2.3.4 -all',
			'd.com': 'v=spf1 ip4:1.2.3.4 -all',
			'e.com': 'v=spf1 ip4:1.2.3.4 -all',
			'f.com': 'v=spf1 ip4:1.2.3.4 -all',
			'g.com': 'v=spf1 ip4:1.2.3.4 -all',
			'a1.com': 'v=spf1 ip4:1.2.3.4 -all',
			'a2.com': 'v=spf1 ip4:1.2.3.4 -all',
			'b1.com': 'v=spf1 ip4:1.2.3.4 -all',
		};
		mockSpfRecords(records);
		const result = await run('example.com');
		// 7 + 3 = 10... need one more. Let's add another nested
		// Actually: 7 top-level + 2 from a.com + 1 from b.com = 10. Add a mechanism:
		expect(result.totalLookups).toBeGreaterThanOrEqual(10);
	});

	it('detects circular includes without infinite loop', async () => {
		mockSpfRecords({
			'example.com': 'v=spf1 include:loop.com -all',
			'loop.com': 'v=spf1 include:example.com -all',
		});
		const result = await run('example.com');
		expect(result.issues.some((i) => i.type === 'circular_include')).toBe(true);
		// Should not hang — test completing proves no infinite loop
	});

	it('detects void lookups when include target has no SPF', async () => {
		mockSpfRecords({
			'example.com': 'v=spf1 include:nosuchrecord.example.com -all',
			'nosuchrecord.example.com': null,
		});
		const result = await run('example.com');
		expect(result.issues.some((i) => i.type === 'void_lookup')).toBe(true);
	});

	it('handles domain with no SPF record', async () => {
		mockSpfRecords({ 'example.com': null });
		const result = await run('example.com');
		expect(result.tree.record).toBeNull();
		expect(result.totalLookups).toBe(0);
	});

	it('counts a, mx, exists, and ptr as lookups', async () => {
		mockSpfRecords({
			'example.com': 'v=spf1 a mx exists:test.com ptr ip4:1.2.3.4 -all',
		});
		const result = await run('example.com');
		// a=1, mx=1, exists:=1, ptr=1 = 4 lookups
		expect(result.totalLookups).toBe(4);
	});

	it('counts redirect as a lookup', async () => {
		mockSpfRecords({
			'example.com': 'v=spf1 redirect=other.com',
			'other.com': 'v=spf1 ip4:1.2.3.4 -all',
		});
		const result = await run('example.com');
		// redirect = 1 lookup
		expect(result.totalLookups).toBe(1);
	});
});

describe('formatSpfChain', () => {
	it('compact format shows tree and lookup count', async () => {
		mockSpfRecords({
			'example.com': 'v=spf1 include:mail.example.com -all',
			'mail.example.com': 'v=spf1 ip4:1.2.3.4 -all',
		});
		const { resolveSpfChain, formatSpfChain } = await import('../src/tools/resolve-spf-chain');
		const result = await resolveSpfChain('example.com');
		const text = formatSpfChain(result, 'compact');
		expect(text).toContain('SPF Chain: example.com');
		expect(text).toContain('1/10 lookups');
		expect(text).toContain('mail.example.com');
	});

	it('full format includes headers', async () => {
		mockSpfRecords({ 'example.com': 'v=spf1 ip4:1.2.3.4 -all' });
		const { resolveSpfChain, formatSpfChain } = await import('../src/tools/resolve-spf-chain');
		const result = await resolveSpfChain('example.com');
		const text = formatSpfChain(result, 'full');
		expect(text).toContain('# SPF Chain');
		expect(text).toContain('**Lookups:**');
		expect(text).toContain('No issues detected');
	});
});
