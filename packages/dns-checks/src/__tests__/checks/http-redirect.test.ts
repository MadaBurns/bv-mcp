// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it, vi } from 'vitest';
import { checkHttpRedirect } from '../../checks/check-http-redirect';
import { analyzeHttpRedirects, nothingMeasured } from '../../checks/http-redirect-analysis';
import type { HostWalk, RedirectChain } from '../../checks/http-redirect-analysis';
import type { CheckResult, FetchFunction } from '../../types';

const DOMAIN = 'example.com';

/** One URL's answer: `[status, location?]`. Any URL not in the table throws like an unreachable host. */
type Answer = [number, string?];

function site(table: Record<string, Answer>): FetchFunction & ReturnType<typeof vi.fn> {
	return vi.fn(async (url: string) => {
		const answer = table[url];
		if (!answer) throw new TypeError(`unreachable ${url}`);
		const [status, location] = answer;
		return new Response(null, { status, headers: location ? { location } : {} });
	}) as FetchFunction & ReturnType<typeof vi.fn>;
}

/** Clean site: both hosts upgrade with a 301 and settle on https://example.com/. */
const CLEAN: Record<string, Answer> = {
	'http://example.com/': [301, 'https://example.com/'],
	'https://example.com/': [200],
	'http://www.example.com/': [301, 'https://www.example.com/'],
	'https://www.example.com/': [301, 'https://example.com/'],
};

const run = (table: Record<string, Answer>): Promise<CheckResult> => checkHttpRedirect(DOMAIN, site(table));
const titles = (result: CheckResult): string[] => result.findings.map((f) => f.title);
const find = (result: CheckResult, title: string) => result.findings.find((f) => f.title === title);

describe('checkHttpRedirect', () => {
	it('positive control: a clean 301 upgrade on both hosts that settle on one origin has no findings', async () => {
		const result = await run(CLEAN);
		expect(result.category).toBe('http_redirect');
		expect(result.findings).toEqual([]);
		expect(result.passed).toBe(true);
		expect(result.checkStatus).toBeUndefined();
	});

	it('records each chain in the result metadata', async () => {
		const result = await run(CLEAN);
		expect(result.metadata).toMatchObject({
			apex: {
				http: { end: 'final', steps: [{ url: 'http://example.com/', status: 301 }, { url: 'https://example.com/', status: 200 }] },
			},
			www: { https: { end: 'final' } },
		});
	});

	it('walks every hop by hand with GET and redirect: manual', async () => {
		const fetchFn = site(CLEAN);
		await checkHttpRedirect(DOMAIN, fetchFn);
		// apex: http (2 requests) + https (1); www: http (3: http, https www, https apex) + https (2).
		expect(fetchFn).toHaveBeenCalledTimes(8);
		for (const call of fetchFn.mock.calls) {
			expect(call[1]).toMatchObject({ method: 'GET', redirect: 'manual' });
		}
	});

	it('resolves a relative Location against the requested URL', async () => {
		const result = await run({ ...CLEAN, 'http://example.com/': [301, '/landing'], 'http://example.com/landing': [301, 'https://example.com/'] });
		expect(result.metadata).toMatchObject({ apex: { http: { steps: [{ url: 'http://example.com/' }, { url: 'http://example.com/landing' }, { url: 'https://example.com/' }] } } });
		expect(result.findings).toEqual([]);
	});

	describe('http does not redirect to https', () => {
		it('is high on the apex and medium on www', async () => {
			const result = await run({ ...CLEAN, 'http://example.com/': [200], 'http://www.example.com/': [200] });
			expect(find(result, 'HTTP does not redirect to HTTPS (apex)')).toMatchObject({ severity: 'high', metadata: { finalStatus: 200, host: 'apex' } });
			expect(find(result, 'HTTP does not redirect to HTTPS (www)')?.severity).toBe('medium');
		});

		it('reads a 403 on plain HTTP as not assessed, not as a missing redirect', async () => {
			const result = await run({ ...CLEAN, 'http://example.com/': [403] });
			expect(titles(result)).not.toContain('HTTP does not redirect to HTTPS (apex)');
			expect(find(result, 'HTTP redirect not assessed (apex)')).toMatchObject({ severity: 'info', metadata: { inconclusive: true } });
			expect(result.findings.some((f) => f.metadata?.missingControl === true)).toBe(false);
		});

		it('is still reported when the chain redirects http to http and ends on an error page', async () => {
			const result = await run({ ...CLEAN, 'http://example.com/': [301, 'http://example.com/home'], 'http://example.com/home': [404] });
			expect(find(result, 'HTTP does not redirect to HTTPS (apex)')?.severity).toBe('high');
		});
	});

	describe('cross-host first hop', () => {
		const crossHost = { ...CLEAN, 'http://example.com/': [301, 'http://www.example.com/'], 'https://example.com/': [301, 'https://www.example.com/'], 'https://www.example.com/': [200] } satisfies Record<string, Answer>;

		it('flags http://a -> http://b -> https://b as medium', async () => {
			const result = await run(crossHost);
			expect(find(result, 'HTTP redirects to another host before HTTPS (apex)')).toMatchObject({
				severity: 'medium',
				metadata: { firstHop: 'http://www.example.com/' },
			});
		});

		it('does not flag a same-host first hop that upgrades before changing host', async () => {
			const result = await run({ ...CLEAN, 'https://example.com/': [301, 'https://www.example.com/'], 'https://www.example.com/': [200] });
			expect(titles(result)).not.toContain('HTTP redirects to another host before HTTPS (apex)');
		});

		it('does not flag a first hop that goes cross-host straight to https', async () => {
			const result = await run({ ...CLEAN, 'http://example.com/': [301, 'https://www.example.com/'], 'https://example.com/': [301, 'https://www.example.com/'], 'https://www.example.com/': [200] });
			expect(titles(result)).not.toContain('HTTP redirects to another host before HTTPS (apex)');
		});
	});

	describe('https to http downgrade', () => {
		it('is high when an https URL redirects to http', async () => {
			const result = await run({ ...CLEAN, 'https://example.com/': [302, 'http://legacy.example.net/'], 'http://legacy.example.net/': [200] });
			expect(find(result, 'HTTPS redirects down to HTTP (apex)')).toMatchObject({
				severity: 'high',
				metadata: { from: 'https://example.com/', to: 'http://legacy.example.net/' },
			});
		});

		it('is found from an https start that no http walk covers', async () => {
			const result = await run({ ...CLEAN, 'http://example.com/': [200], 'https://example.com/': [302, 'http://legacy.example.net/'], 'http://legacy.example.net/': [200] });
			expect(find(result, 'HTTPS redirects down to HTTP (apex)')).toMatchObject({ metadata: { scheme: 'https' } });
		});

		it('is found in the middle of an http-started chain', async () => {
			const result = await run({
				...CLEAN,
				'http://example.com/': [301, 'https://example.com/'],
				'https://example.com/': [301, 'http://example.com/final'],
				'http://example.com/final': [200],
			});
			expect(find(result, 'HTTPS redirects down to HTTP (apex)')?.severity).toBe('high');
		});
	});

	describe('loops and long chains', () => {
		it('flags a redirect loop as medium', async () => {
			const result = await run({ ...CLEAN, 'https://example.com/': [301, 'https://example.com/a'], 'https://example.com/a': [301, 'https://example.com/'] });
			expect(find(result, 'Redirect loop (apex)')).toMatchObject({ severity: 'medium', metadata: { scheme: 'http' } });
		});

		it('reports a loop on an https start that no http walk covers once, under the https scheme', async () => {
			const result = await run({
				...CLEAN,
				'http://example.com/': [200],
				'https://example.com/': [301, 'https://example.com/a'],
				'https://example.com/a': [301, 'https://example.com/'],
			});
			const loops = result.findings.filter((f) => f.title === 'Redirect loop (apex)');
			expect(loops).toHaveLength(1);
			expect(loops[0].metadata).toMatchObject({ scheme: 'https' });
		});

		it('does not report a loop twice when the http walk already ran through the https tail', async () => {
			const result = await run({ ...CLEAN, 'https://example.com/': [301, 'https://example.com/a'], 'https://example.com/a': [301, 'https://example.com/'] });
			expect(result.findings.filter((f) => f.title === 'Redirect loop (apex)')).toHaveLength(1);
		});

		it('flags more than 5 redirects as medium, and exactly 5 as fine', async () => {
			// The http walk adds one upgrade redirect in front of the https tail, so a tail of N hops is N + 1 redirects.
			const chain = (tailHops: number): Record<string, Answer> => {
				const table: Record<string, Answer> = { ...CLEAN, 'https://example.com/': [301, 'https://example.com/h1'] };
				for (let i = 1; i < tailHops; i++) table[`https://example.com/h${i}`] = [301, `https://example.com/h${i + 1}`];
				table[`https://example.com/h${tailHops}`] = [200];
				return table;
			};
			const five = await run(chain(4));
			expect(titles(five)).not.toContain('Long redirect chain (apex)');
			const six = await run(chain(5));
			expect(find(six, 'Long redirect chain (apex)')).toMatchObject({ severity: 'medium', metadata: { redirects: 6 } });
		});

		it('stops an endless chain after the hop limit and says it did not settle', async () => {
			const fetchFn = vi.fn(async (url: string) => {
				if (url.startsWith('https://example.com/')) {
					const n = Number(url.split('/n')[1] ?? 0) + 1;
					return new Response(null, { status: 301, headers: { location: `https://example.com/n${n}` } });
				}
				throw new TypeError('unreachable');
			}) as FetchFunction & ReturnType<typeof vi.fn>;
			const result = await checkHttpRedirect(DOMAIN, fetchFn);
			const long = find(result, 'Long redirect chain (apex)');
			expect(long?.detail).toContain('still had not settled after 6 redirects');
			// The walker follows 6 redirects, then stops after the 7th response.
			expect(fetchFn.mock.calls.filter(([url]) => (url as string).startsWith('https://example.com/')).length).toBe(7);
		});
	});

	describe('temporary redirect used for the upgrade', () => {
		it.each([302, 307])('reports HTTP %i as info', async (status) => {
			const result = await run({ ...CLEAN, 'http://example.com/': [status, 'https://example.com/'] });
			expect(find(result, 'HTTP upgrade uses a temporary redirect (apex)')).toMatchObject({ severity: 'info', metadata: { status } });
		});

		it.each([301, 308])('does not report HTTP %i', async (status) => {
			const result = await run({ ...CLEAN, 'http://example.com/': [status, 'https://example.com/'] });
			expect(titles(result)).not.toContain('HTTP upgrade uses a temporary redirect (apex)');
		});

		it('ignores a 302 that is not the http-to-https step', async () => {
			const result = await run({ ...CLEAN, 'https://www.example.com/': [302, 'https://example.com/'] });
			expect(result.findings).toEqual([]);
		});
	});

	describe('apex and www parity', () => {
		it('flags two hosts that each serve on their own origin as low', async () => {
			const result = await run({ ...CLEAN, 'http://www.example.com/': [301, 'https://www.example.com/'], 'https://www.example.com/': [200] });
			expect(find(result, 'Apex and www end on different origins')).toMatchObject({
				severity: 'low',
				metadata: { apexLanding: 'https://example.com/', wwwLanding: 'https://www.example.com/' },
			});
		});

		it('flags one host serving while the other errors as low', async () => {
			const result = await run({ ...CLEAN, 'https://www.example.com/': [404] });
			expect(find(result, 'Apex and www disagree: one serves, one errors')).toMatchObject({ severity: 'low', metadata: { wwwStatus: 404 } });
		});

		it('names the apex when the apex is the one that errors', async () => {
			const result = await run({ ...CLEAN, 'https://example.com/': [500], 'https://www.example.com/': [200] });
			expect(find(result, 'Apex and www disagree: one serves, one errors')?.detail).toContain('Make apex serve');
		});

		it('does not read an auth wall or rate limit on one host as a parity failure', async () => {
			const result = await run({ ...CLEAN, 'https://www.example.com/': [403] });
			expect(titles(result)).not.toContain('Apex and www disagree: one serves, one errors');
		});

		it('is silent when both hosts error', async () => {
			const result = await run({ ...CLEAN, 'https://example.com/': [500], 'https://www.example.com/': [404] });
			expect(titles(result).filter((t) => t.startsWith('Apex and www'))).toEqual([]);
		});
	});

	describe('hosts that cannot be fetched', () => {
		const wwwDown: Record<string, Answer> = {
			'http://example.com/': [301, 'https://example.com/'],
			'https://example.com/': [200],
		};

		it('reports an unresolvable www as info, not a failure, and does not touch parity', async () => {
			const result = await run(wwwDown);
			expect(result.findings).toHaveLength(1);
			expect(find(result, 'www host not resolvable or not served')).toMatchObject({ severity: 'info', metadata: { inconclusive: true } });
			expect(result.checkStatus).toBeUndefined();
		});

		it('reports an unreachable apex as not assessed while still judging www', async () => {
			const result = await run({ 'http://www.example.com/': [200], 'https://www.example.com/': [200] });
			expect(find(result, 'Apex host not assessed')).toMatchObject({ severity: 'info', metadata: { inconclusive: true } });
			expect(find(result, 'HTTP does not redirect to HTTPS (www)')?.severity).toBe('medium');
		});

		it('reports one failed start URL as not assessed for that scheme only', async () => {
			const { 'http://example.com/': _dropped, ...httpDown } = CLEAN;
			const result = await run(httpDown);
			expect(titles(result)).toEqual(['HTTP redirects not assessed (apex)']);
			expect(result.findings[0].metadata?.missingControl).toBeUndefined();
		});

		it('keeps what it saw when a later request in the chain fails', async () => {
			const result = await run({ ...CLEAN, 'http://example.com/': [301, 'https://example.com/lost'] });
			expect(find(result, 'Redirect chain not fully assessed (apex)')).toMatchObject({ severity: 'info', metadata: { inconclusive: true } });
			expect(titles(result)).not.toContain('HTTP does not redirect to HTTPS (apex)');
			expect(result.metadata).toMatchObject({ apex: { http: { end: 'interrupted' } } });
		});

		it('abstains with the not-assessed shape when nothing could be fetched', async () => {
			const result = await run({});
			expect(result).toMatchObject({ category: 'http_redirect', score: 0, passed: false, partial: true, checkStatus: 'error' });
			expect(result.findings[0].metadata).toMatchObject({ inconclusive: true });
			expect(result.findings[0].metadata?.missingControl).toBeUndefined();
		});
	});
});

describe('analyzeHttpRedirects (pure)', () => {
	const chain = (startUrl: string, steps: [string, number, string | null][], end: RedirectChain['end'] = 'final'): RedirectChain => ({
		startUrl,
		steps: steps.map(([url, status, next]) => ({ url, status, next })),
		end,
	});
	const walk = (label: 'apex' | 'www', hostname: string, http: RedirectChain | null, https: RedirectChain | null): HostWalk => ({ label, hostname, http, https });

	it('nothingMeasured is true only when all four chains are null', () => {
		const empty = walk('apex', 'a', null, null);
		expect(nothingMeasured(empty, walk('www', 'www.a', null, null))).toBe(true);
		expect(nothingMeasured(empty, walk('www', 'www.a', chain('https://www.a/', [['https://www.a/', 200, null]]), null))).toBe(false);
	});

	it('names a status 0 opaque answer on plain http as not assessed', () => {
		const apex = walk('apex', 'a', chain('http://a/', [['http://a/', 0, null]]), chain('https://a/', [['https://a/', 200, null]]));
		const www = walk('www', 'www.a', null, null);
		const titles = analyzeHttpRedirects(apex, www).map((f) => f.title);
		expect(titles).toContain('HTTP redirect not assessed (apex)');
	});
});
