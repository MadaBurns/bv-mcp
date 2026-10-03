import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

/**
 * Per-domain TXT mock. A string is an SPF record, `null` is NOERROR/NODATA (measured
 * absence), a number is a DoH RCODE (2 = SERVFAIL). Matches the queried name exactly so
 * `c.test` never answers for `ac.test`.
 */
function mockSpf(records: Record<string, string | null | number>, queried?: string[]) {
	globalThis.fetch = vi.fn().mockImplementation(async (url: string | URL | Request) => {
		const urlStr = typeof url === 'string' ? url : url instanceof URL ? url.toString() : url.url;
		const name = new URL(urlStr).searchParams.get('name') ?? '';
		queried?.push(name);
		const spf = records[name];
		if (typeof spf === 'number') {
			return createDohResponse([{ name, type: 16 }], [], { status: spf });
		}
		if (typeof spf === 'string') {
			return createDohResponse([{ name, type: 16 }], [{ name, type: 16, TTL: 300, data: `"${spf}"` }]);
		}
		return createDohResponse([{ name, type: 16 }], []);
	});
}

async function run(domain: string) {
	const { resolveSpfChain } = await import('../src/tools/resolve-spf-chain');
	return resolveSpfChain(domain);
}

describe('resolveSpfChain — RFC 7208 conformance', () => {
	describe('item 1: diamond includes', () => {
		const diamond = {
			'root.test': 'v=spf1 include:a.test include:b.test -all',
			'a.test': 'v=spf1 include:c.test -all',
			'b.test': 'v=spf1 include:c.test -all',
			'c.test': 'v=spf1 a ip4:192.0.2.1 -all',
		};

		it('does not flag a shared include reached via two paths as circular', async () => {
			mockSpf(diamond);
			const result = await run('root.test');
			expect(result.issues.some((i) => i.type === 'circular_include')).toBe(false);
		});

		it('flags the second path as redundant_include and counts each evaluation toward the limit', async () => {
			mockSpf(diamond);
			const result = await run('root.test');
			expect(result.issues.filter((i) => i.type === 'redundant_include')).toHaveLength(1);
			// root: 2 includes. a: include:c (1) + c's `a` (1). b: the same 2 again.
			expect(result.totalLookups).toBe(6);
			// c is expanded under both a and b
			expect(result.tree.children[1].children[0].record).toBe('v=spf1 a ip4:192.0.2.1 -all');
		});

		it('still flags a true cycle on the current recursion path', async () => {
			mockSpf({
				'root.test': 'v=spf1 include:a.test -all',
				'a.test': 'v=spf1 include:b.test -all',
				'b.test': 'v=spf1 include:a.test -all',
			});
			const result = await run('root.test');
			expect(result.issues.filter((i) => i.type === 'circular_include')).toHaveLength(1);
			expect(result.issues.some((i) => i.type === 'redundant_include')).toBe(false);
		});
	});

	describe('item 2: qualifier-prefixed mechanisms', () => {
		it.each(['+a', '-a', '~a', '?a', '+mx', '-mx:mail.example.net', '~exists:%{i}.x.example.net', '?ptr', '+a:other.example.net/24'])(
			'counts %s as one DNS lookup',
			async (mech) => {
				mockSpf({ 'root.test': `v=spf1 ${mech} -all` });
				const result = await run('root.test');
				expect(result.totalLookups).toBe(1);
				// the qualifier is preserved in the output
				expect(result.tree.mechanisms).toContain(mech);
			},
		);

		it.each(['+include:inc.test', '~include:inc.test', '-include:inc.test', '?include:inc.test'])('follows %s', async (mech) => {
			mockSpf({
				'root.test': `v=spf1 ${mech} -all`,
				'inc.test': 'v=spf1 mx -all',
			});
			const result = await run('root.test');
			expect(result.tree.children).toHaveLength(1);
			expect(result.tree.children[0].domain).toBe('inc.test');
			// include (1) + the child's mx (1)
			expect(result.totalLookups).toBe(2);
			expect(result.tree.mechanisms).toContain(mech);
		});
	});

	describe('item 3a: SERVFAIL is inconclusive, not a void lookup', () => {
		it('reports a SERVFAIL on an include as inconclusive, not void_lookup', async () => {
			mockSpf({ 'root.test': 'v=spf1 include:broken.test -all', 'broken.test': 2 });
			const result = await run('root.test');
			expect(result.issues.some((i) => i.type === 'void_lookup')).toBe(false);
			const issue = result.issues.find((i) => i.type === 'lookup_inconclusive');
			expect(issue).toBeDefined();
			expect(issue!.inconclusive).toBe(true);
			expect(issue!.errorKind).toBe('dns_error');
			expect(result.inconclusive).toBe(true);
		});

		it('does not report "No issues detected" when the root lookup SERVFAILs', async () => {
			mockSpf({ 'root.test': 2 });
			const result = await run('root.test');
			expect(result.inconclusive).toBe(true);
			expect(result.issues.some((i) => i.type === 'lookup_inconclusive' && i.errorKind === 'dns_error')).toBe(true);
			const { formatSpfChain } = await import('../src/tools/resolve-spf-chain');
			expect(formatSpfChain(result, 'full')).not.toContain('No issues detected');
			expect(formatSpfChain(result, 'full')).toContain('INCONCLUSIVE');
		});

		it('still reports NOERROR/NODATA on an include as a void_lookup (measured absence)', async () => {
			mockSpf({ 'root.test': 'v=spf1 include:empty.test -all', 'empty.test': null });
			const result = await run('root.test');
			expect(result.issues.some((i) => i.type === 'void_lookup')).toBe(true);
			expect(result.inconclusive).toBeFalsy();
		});
	});

	describe('item 3b: lookup cutoff', () => {
		it('stops expanding after the 10th lookup and emits lookup_limit_exceeded', async () => {
			const queried: string[] = [];
			const records: Record<string, string> = {};
			const includes: string[] = [];
			for (let i = 0; i < 40; i++) {
				includes.push(`include:i${i}.test`);
				records[`i${i}.test`] = 'v=spf1 ip4:192.0.2.1 -all';
			}
			records['root.test'] = `v=spf1 ${includes.join(' ')} -all`;
			mockSpf(records, queried);
			const result = await run('root.test');
			expect(result.overLimit).toBe(true);
			expect(result.issues.some((i) => i.type === 'lookup_limit_exceeded')).toBe(true);
			// root + 10 expanded includes, never the other 30 (also bounds the node count)
			expect(queried.length).toBeLessThanOrEqual(11);
			expect(result.tree.children.length).toBeLessThanOrEqual(10);
		});

		it('does not emit lookup_limit_exceeded at exactly 10 lookups', async () => {
			const records: Record<string, string> = {};
			const includes: string[] = [];
			for (let i = 0; i < 10; i++) {
				includes.push(`include:i${i}.test`);
				records[`i${i}.test`] = 'v=spf1 ip4:192.0.2.1 -all';
			}
			records['root.test'] = `v=spf1 ${includes.join(' ')} -all`;
			mockSpf(records);
			const result = await run('root.test');
			expect(result.totalLookups).toBe(10);
			expect(result.issues.some((i) => i.type === 'lookup_limit_exceeded')).toBe(false);
		});
	});

	describe('item 3c: redirect is ignored when all is present (RFC 7208 section 6.1)', () => {
		it('does not follow or count redirect= when an all mechanism is present', async () => {
			const queried: string[] = [];
			mockSpf({ 'root.test': 'v=spf1 ip4:192.0.2.1 redirect=other.test -all', 'other.test': 'v=spf1 mx -all' }, queried);
			const result = await run('root.test');
			expect(queried).not.toContain('other.test');
			expect(result.tree.children).toHaveLength(0);
			expect(result.totalLookups).toBe(0);
			expect(result.issues.some((i) => i.type === 'redirect_ignored')).toBe(true);
		});

		it('follows redirect= when there is no all mechanism', async () => {
			mockSpf({ 'root.test': 'v=spf1 ip4:192.0.2.1 redirect=other.test', 'other.test': 'v=spf1 mx -all' });
			const result = await run('root.test');
			expect(result.tree.children).toHaveLength(1);
			expect(result.totalLookups).toBe(2);
			expect(result.issues.some((i) => i.type === 'redirect_ignored')).toBe(false);
		});

		it('treats a qualified all (~all) as present', async () => {
			mockSpf({ 'root.test': 'v=spf1 redirect=other.test ~all', 'other.test': 'v=spf1 mx -all' });
			const result = await run('root.test');
			expect(result.tree.children).toHaveLength(0);
		});
	});
});
