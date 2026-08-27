// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, vi } from 'vitest';
import {
	SCANNER_USER_AGENT,
	RobotsDisallowedError,
	withRobotsGate,
	parseRobotsGroups,
	isPathDisallowed,
	createRobotsGroupCache,
	getRobotsGroupCacheStats,
	ROBOTS_CACHE_MAX_BYTES,
	ROBOTS_MAX_BODY_BYTES,
} from '../robots-gate';
import type { RobotsResolutionRecord } from '../robots-gate';

function textResponse(body: string, ok = true): Response {
	return new Response(body, { status: ok ? 200 : 404 });
}

describe('parseRobotsGroups', () => {
	it('parses a single wildcard group', () => {
		const groups = parseRobotsGroups('User-agent: *\nDisallow: /private\n');
		expect(groups).toEqual([{ agents: ['*'], rules: [{ path: '/private', allow: false }] }]);
	});

	it('parses a named group separately from the wildcard group', () => {
		const groups = parseRobotsGroups('User-agent: BlackVeil-Security-Scanner\nDisallow: /\n\nUser-agent: *\nDisallow: /admin\n');
		expect(groups).toEqual([
			{ agents: ['blackveil-security-scanner'], rules: [{ path: '/', allow: false }] },
			{ agents: ['*'], rules: [{ path: '/admin', allow: false }] },
		]);
	});

	it('ignores comments and blank lines', () => {
		const groups = parseRobotsGroups('# comment\n\nUser-agent: *\n# another comment\nDisallow: /x\n');
		expect(groups).toEqual([{ agents: ['*'], rules: [{ path: '/x', allow: false }] }]);
	});

	it('groups consecutive User-agent lines into one group', () => {
		const groups = parseRobotsGroups('User-agent: a\nUser-agent: b\nDisallow: /x\n');
		expect(groups).toEqual([{ agents: ['a', 'b'], rules: [{ path: '/x', allow: false }] }]);
	});
});

describe('isPathDisallowed', () => {
	it('returns false for a null group (no matching group at all)', () => {
		expect(isPathDisallowed(null, '/anything')).toBe(false);
	});

	it('disallows an exact-prefix match', () => {
		const group = { agents: ['*'], rules: [{ path: '/private', allow: false }] };
		expect(isPathDisallowed(group, '/private/x')).toBe(true);
		expect(isPathDisallowed(group, '/public')).toBe(false);
	});

	it('an empty Disallow value means allow everything', () => {
		const group = { agents: ['*'], rules: [{ path: '', allow: false }] };
		expect(isPathDisallowed(group, '/anything')).toBe(false);
	});

	it('longest match wins', () => {
		const group = {
			agents: ['*'],
			rules: [
				{ path: '/', allow: false },
				{ path: '/public', allow: true },
			],
		};
		expect(isPathDisallowed(group, '/public/page')).toBe(false);
		expect(isPathDisallowed(group, '/private')).toBe(true);
	});

	it('ties favor Allow regardless of encounter order', () => {
		const allowFirst = {
			agents: ['*'],
			rules: [
				{ path: '/x', allow: true },
				{ path: '/x', allow: false },
			],
		};
		const disallowFirst = {
			agents: ['*'],
			rules: [
				{ path: '/x', allow: false },
				{ path: '/x', allow: true },
			],
		};
		expect(isPathDisallowed(allowFirst, '/x')).toBe(false);
		expect(isPathDisallowed(disallowFirst, '/x')).toBe(false);
	});

	it('supports * wildcard and $ end-anchor', () => {
		const group = { agents: ['*'], rules: [{ path: '/*.pdf$', allow: false }] };
		expect(isPathDisallowed(group, '/docs/report.pdf')).toBe(true);
		expect(isPathDisallowed(group, '/docs/report.pdf.html')).toBe(false);
	});

	it('preserves prefix anchoring, empty/repeated wildcards, and terminal-only $ semantics', () => {
		const group = {
			agents: ['*'],
			rules: [
				{ path: '/prefix**middle*end', allow: false },
				{ path: '/exact$', allow: false },
			],
		};
		expect(isPathDisallowed(group, '/prefixmiddle/end-and-more')).toBe(true);
		expect(isPathDisallowed(group, 'x/prefixmiddle/end')).toBe(false);
		expect(isPathDisallowed(group, '/exact')).toBe(true);
		expect(isPathDisallowed(group, '/exact/more')).toBe(false);
	});

	it('treats regex metacharacters and non-terminal $ as literal path characters', () => {
		const group = {
			agents: ['*'],
			rules: [{ path: '/literal[1].(pdf)?+$value', allow: false }],
		};
		expect(isPathDisallowed(group, '/literal[1].(pdf)?+$value/child')).toBe(true);
		expect(isPathDisallowed(group, '/literal1Xpdfvalue')).toBe(false);
	});

	it('rejects the adversarial wildcard nonmatch in bounded time', () => {
		const n = 500;
		const group = {
			agents: ['*'],
			rules: [{ path: '*a'.repeat(n) + 'b', allow: false }],
		};
		const startedAt = performance.now();
		expect(isPathDisallowed(group, 'a'.repeat(n))).toBe(false);
		// The former dynamic RegExp exceeded ten seconds for this exact input.
		expect(performance.now() - startedAt).toBeLessThan(100);
	});
});

describe('withRobotsGate', () => {
	it('stamps the User-Agent header when the caller did not set one', async () => {
		const inner = vi.fn(async (_url: string, _init?: RequestInit) => textResponse('', false));
		const gated = withRobotsGate(inner);
		await gated('https://example.com/robots.txt');
		expect(inner).toHaveBeenCalledWith(
			'https://example.com/robots.txt',
			expect.objectContaining({
				headers: expect.any(Headers),
			}),
		);
		const sentHeaders = inner.mock.calls[0]![1]!.headers as Headers;
		expect(sentHeaders.get('User-Agent')).toBe(SCANNER_USER_AGENT);
	});

	it('does not overwrite a caller-supplied User-Agent', async () => {
		const inner = vi.fn(async (_url: string, _init?: RequestInit) => textResponse('', false));
		const gated = withRobotsGate(inner);
		await gated('https://example.com/robots.txt', { headers: { 'User-Agent': 'Custom/1.0' } });
		const sentHeaders = inner.mock.calls[0]![1]!.headers as Headers;
		expect(sentHeaders.get('User-Agent')).toBe('Custom/1.0');
	});

	it('allows a path with no robots.txt (fetch failure = fail-open)', async () => {
		const inner = vi.fn(async (url: string, _init?: RequestInit) => {
			if (url.endsWith('/robots.txt')) throw new Error('network error');
			return textResponse('ok');
		});
		const gated = withRobotsGate(inner);
		const res = await gated('https://example.com/');
		expect(await res.text()).toBe('ok');
	});

	it('allows a path when robots.txt has no matching Disallow', async () => {
		const inner = vi.fn(async (url: string) => {
			if (url.endsWith('/robots.txt')) return textResponse('User-agent: *\nDisallow: /private\n');
			return textResponse('ok');
		});
		const gated = withRobotsGate(inner);
		const res = await gated('https://example.com/');
		expect(await res.text()).toBe('ok');
	});

	it('uses manual redirect mode for robots.txt and never follows a redirect target', async () => {
		const inner = vi.fn(async (url: string) => {
			if (url === 'https://example.com/robots.txt') {
				return new Response(null, {
					status: 302,
					headers: { Location: 'https://169.254.169.254/latest/meta-data/' },
				});
			}
			return textResponse('ok');
		});
		const gated = withRobotsGate(inner);

		const response = await gated('https://example.com/');

		expect(await response.text()).toBe('ok');
		expect(inner).toHaveBeenCalledTimes(2);
		expect(inner.mock.calls[0]![0]).toBe('https://example.com/robots.txt');
		expect(inner.mock.calls[0]![1]).toEqual(expect.objectContaining({ redirect: 'manual' }));
		expect(inner.mock.calls.some(([url]) => String(url).includes('169.254.169.254'))).toBe(false);
	});

	it('rejects with RobotsDisallowedError for a disallowed path', async () => {
		const inner = vi.fn(async (url: string) => {
			if (url.endsWith('/robots.txt')) return textResponse('User-agent: *\nDisallow: /\n');
			return textResponse('should not be reached');
		});
		const gated = withRobotsGate(inner);
		await expect(gated('https://example.com/')).rejects.toBeInstanceOf(RobotsDisallowedError);
	});

	it('fetches robots.txt at most once per hostname across repeated calls', async () => {
		const robotsFetches = vi.fn();
		const inner = vi.fn(async (url: string) => {
			if (url.endsWith('/robots.txt')) {
				robotsFetches();
				return textResponse('User-agent: *\nDisallow: /private\n');
			}
			return textResponse('ok');
		});
		const gated = withRobotsGate(inner);
		await gated('https://example.com/a');
		await gated('https://example.com/b');
		await gated('https://example.com/c');
		expect(robotsFetches).toHaveBeenCalledTimes(1);
	});

	it('fails open and cancels an oversized robots.txt stream', async () => {
		const cancelled = vi.fn();
		const records: RobotsResolutionRecord[] = [];
		const inner = vi.fn(async (url: string) => {
			if (!url.endsWith('/robots.txt')) return textResponse('ok');
			let pull = 0;
			return new Response(
				new ReadableStream<Uint8Array>({
					pull(controller) {
						if (pull++ === 0) controller.enqueue(new Uint8Array(ROBOTS_MAX_BODY_BYTES));
						else if (pull === 2) controller.enqueue(new Uint8Array([1]));
						else if (pull === 3) controller.enqueue(new Uint8Array([2]));
						else controller.close();
					},
					cancel: cancelled,
				}),
			);
		});
		const gated = withRobotsGate(inner, { onRobotsResolution: (record) => records.push(record) });

		const response = await gated('https://example.com/');
		expect(await response.text()).toBe('ok');
		expect(cancelled).toHaveBeenCalledOnce();
		expect(records).toEqual([
			{
				host: 'example.com',
				path: '/',
				resolution: 'unreachable',
				failOpen: true,
				status: 200,
				errorName: 'RobotsBodyTooLargeError',
			},
		]);
	});

	it('evicts the least-recently-used host at the configured bound', async () => {
		const robotsByHost = new Map<string, number>();
		const inner = async (url: string) => {
			const parsed = new URL(url);
			if (parsed.pathname === '/robots.txt') {
				robotsByHost.set(parsed.hostname, (robotsByHost.get(parsed.hostname) ?? 0) + 1);
				return textResponse('User-agent: *\nDisallow: /private\n');
			}
			return textResponse('ok');
		};
		const cache = createRobotsGroupCache({ maxEntries: 2 });
		const gated = withRobotsGate(inner, { groupCache: cache });

		await gated('https://a.example.com/');
		await gated('https://b.example.com/');
		await gated('https://a.example.com/again'); // touch a; b is now LRU
		await gated('https://c.example.com/');
		await gated('https://b.example.com/again');

		expect(robotsByHost).toEqual(
			new Map([
				['a.example.com', 1],
				['b.example.com', 2],
				['c.example.com', 1],
			]),
		);
		expect(cache.entries.size).toBe(2);
	});

	it('strictly byte-bounds max-sized cached policies and evicts before admitting another', async () => {
		const prefix = 'User-agent: *\nDisallow: /';
		const maxBody = prefix + 'x'.repeat(ROBOTS_MAX_BODY_BYTES - prefix.length);
		expect(new TextEncoder().encode(maxBody)).toHaveLength(ROBOTS_MAX_BODY_BYTES);
		const robotsFetches = new Map<string, number>();
		const inner = async (url: string) => {
			const parsed = new URL(url);
			if (parsed.pathname === '/robots.txt') {
				robotsFetches.set(parsed.hostname, (robotsFetches.get(parsed.hostname) ?? 0) + 1);
				return textResponse(maxBody);
			}
			return textResponse('ok');
		};
		const cache = createRobotsGroupCache();
		const gated = withRobotsGate(inner, { groupCache: cache });

		await gated('https://a.example.com/');
		const afterFirst = getRobotsGroupCacheStats(cache);
		expect(afterFirst).toMatchObject({ entries: 1, maxBytes: ROBOTS_CACHE_MAX_BYTES });
		expect(afterFirst.retainedBytes).toBeGreaterThan(ROBOTS_MAX_BODY_BYTES);
		expect(afterFirst.retainedBytes).toBeLessThanOrEqual(ROBOTS_CACHE_MAX_BYTES);

		await gated('https://b.example.com/');
		const afterSecond = getRobotsGroupCacheStats(cache);
		expect(afterSecond.entries).toBe(1);
		expect(afterSecond.retainedBytes).toBeLessThanOrEqual(ROBOTS_CACHE_MAX_BYTES);

		await gated('https://a.example.com/again');
		expect(robotsFetches).toEqual(
			new Map([
				['a.example.com', 2],
				['b.example.com', 1],
			]),
		);
		expect(getRobotsGroupCacheStats(cache).retainedBytes).toBeLessThanOrEqual(ROBOTS_CACHE_MAX_BYTES);
	});

	it('expires a cached host after its TTL', async () => {
		let now = 1_000;
		const robotsFetches = vi.fn();
		const inner = async (url: string) => {
			if (url.endsWith('/robots.txt')) robotsFetches();
			return url.endsWith('/robots.txt') ? textResponse('User-agent: *\nDisallow: /private\n') : textResponse('ok');
		};
		const cache = createRobotsGroupCache({ ttlMs: 100, now: () => now });
		const gated = withRobotsGate(inner, { groupCache: cache });

		await gated('https://example.com/a');
		expect(getRobotsGroupCacheStats(cache).retainedBytes).toBeGreaterThan(0);
		now = 1_099;
		await gated('https://example.com/b');
		now = 1_100;
		expect(getRobotsGroupCacheStats(cache)).toMatchObject({ entries: 0, retainedBytes: 0 });
		await gated('https://example.com/c');

		expect(robotsFetches).toHaveBeenCalledTimes(2);
	});

	it('does not let an expired in-flight settlement overwrite replacement accounting', async () => {
		let now = 1_000;
		const robotsResolvers: Array<(response: Response) => void> = [];
		let robotsFetches = 0;
		const inner = async (url: string): Promise<Response> => {
			if (!url.endsWith('/robots.txt')) return textResponse('ok');
			robotsFetches += 1;
			return new Promise<Response>((resolve) => robotsResolvers.push(resolve));
		};
		const cache = createRobotsGroupCache({ ttlMs: 10, now: () => now });
		const gated = withRobotsGate(inner, { groupCache: cache });

		const oldRequest = gated('https://example.com/first');
		await vi.waitFor(() => expect(robotsResolvers).toHaveLength(1));
		now = 1_010;
		const replacementRequest = gated('https://example.com/second');
		await vi.waitFor(() => expect(robotsResolvers).toHaveLength(2));

		robotsResolvers[0]!(textResponse('User-agent: *\nDisallow: /old\n'));
		await oldRequest;
		const whileReplacementPending = getRobotsGroupCacheStats(cache);
		expect(whileReplacementPending.entries).toBe(1);
		expect(whileReplacementPending.retainedBytes).toBeGreaterThan(0);
		expect(whileReplacementPending.retainedBytes).toBeLessThanOrEqual(ROBOTS_CACHE_MAX_BYTES);

		robotsResolvers[1]!(textResponse('User-agent: *\nDisallow: /new\n'));
		await replacementRequest;
		const afterReplacement = getRobotsGroupCacheStats(cache);
		expect(afterReplacement.entries).toBe(1);
		expect(afterReplacement.retainedBytes).toBeLessThan(whileReplacementPending.retainedBytes);
		await expect(gated('https://example.com/old')).resolves.toBeInstanceOf(Response);
		await expect(gated('https://example.com/new')).rejects.toBeInstanceOf(RobotsDisallowedError);
		expect(robotsFetches).toBe(2);
	});

	it('shares one byte budget across isolated cache namespaces', async () => {
		const robotsFetches = vi.fn();
		const inner = async (url: string) => {
			if (url.endsWith('/robots.txt')) robotsFetches();
			return url.endsWith('/robots.txt') ? textResponse('User-agent: *\nDisallow: /private\n') : textResponse('ok');
		};
		const cache = createRobotsGroupCache();
		const plain = withRobotsGate(inner, { groupCache: cache, cacheNamespace: 'plain' });
		const safe = withRobotsGate(inner, { groupCache: cache, cacheNamespace: 'safe' });

		await plain('https://example.com/');
		await safe('https://example.com/');
		await plain('https://example.com/again');

		expect(robotsFetches).toHaveBeenCalledTimes(2);
		expect(getRobotsGroupCacheStats(cache)).toMatchObject({ entries: 2, maxBytes: ROBOTS_CACHE_MAX_BYTES });
		expect(getRobotsGroupCacheStats(cache).retainedBytes).toBeLessThanOrEqual(ROBOTS_CACHE_MAX_BYTES);
	});

	it('never routes a /robots.txt request itself through the gate', async () => {
		const inner = vi.fn(async () => textResponse('User-agent: *\nDisallow: /\n'));
		const gated = withRobotsGate(inner);
		// Would throw RobotsDisallowedError if the gate applied to itself (Disallow: /).
		await expect(gated('https://example.com/robots.txt')).resolves.toBeInstanceOf(Response);
	});

	it('attributes a blanket `User-agent: *` disallow to all crawlers, not to us by name', async () => {
		const inner = vi.fn(async (url: string) => {
			// The real crt.sh robots.txt: blocks every crawler, names nobody.
			if (url.endsWith('/robots.txt')) return textResponse('User-agent: *\nDisallow: /\n');
			return textResponse('should not be reached');
		});
		const gated = withRobotsGate(inner);
		const err = await gated('https://crt.sh/').catch((e: unknown) => e);
		expect(err).toBeInstanceOf(RobotsDisallowedError);
		expect((err as RobotsDisallowedError).scope).toBe('blanket');
		expect((err as RobotsDisallowedError).message).not.toContain('BlackVeil-Security-Scanner');
	});

	it('attributes a disallow in a group naming our UA as a named block', async () => {
		const inner = vi.fn(async (url: string) => {
			if (url.endsWith('/robots.txt')) {
				return textResponse('User-agent: BlackVeil-Security-Scanner\nDisallow: /\n');
			}
			return textResponse('should not be reached');
		});
		const gated = withRobotsGate(inner);
		const err = await gated('https://example.com/').catch((e: unknown) => e);
		expect(err).toBeInstanceOf(RobotsDisallowedError);
		expect((err as RobotsDisallowedError).scope).toBe('named');
		expect((err as RobotsDisallowedError).message).toContain('BlackVeil-Security-Scanner');
	});

	it('defaults to the non-accusatory `blanket` scope when the caller supplies none', () => {
		// Conservative default: never claim a site singled us out without evidence it did.
		expect(new RobotsDisallowedError('https://example.com/').scope).toBe('blanket');
	});

	describe('resolution provenance (issue #745)', () => {
		/** Run one gated request against a robots.txt the caller describes, capturing every reported record. */
		async function gatedWithRecords(
			robots: () => Promise<Response>,
			url = 'https://example.com/',
		): Promise<{ records: RobotsResolutionRecord[]; error: unknown }> {
			const records: RobotsResolutionRecord[] = [];
			const inner = async (target: string) => (target.endsWith('/robots.txt') ? robots() : textResponse('ok'));
			const gated = withRobotsGate(inner, { onRobotsResolution: (r) => records.push(r) });
			const error = await gated(url).then(
				() => undefined,
				(e: unknown) => e,
			);
			return { records, error };
		}

		it('records `allowed` with the matched scope when robots.txt permits the path', async () => {
			const { records, error } = await gatedWithRecords(async () => textResponse('User-agent: *\nDisallow: /private\n'));
			expect(error).toBeUndefined();
			expect(records).toEqual([{ host: 'example.com', path: '/', resolution: 'allowed', failOpen: false, status: 200, scope: 'blanket' }]);
		});

		it('records `allowed` with no scope when no group in robots.txt applies to us', async () => {
			const { records } = await gatedWithRecords(async () => textResponse('User-agent: Googlebot\nDisallow: /\n'));
			expect(records[0]).toMatchObject({ resolution: 'allowed', failOpen: false });
			expect(records[0]!.scope).toBeUndefined();
		});

		it('records `disallowed` on the branch that aborts the request', async () => {
			const { records, error } = await gatedWithRecords(async () => textResponse('User-agent: *\nDisallow: /\n'));
			expect(error).toBeInstanceOf(RobotsDisallowedError);
			expect(records[0]).toEqual({
				host: 'example.com',
				path: '/',
				resolution: 'disallowed',
				failOpen: false,
				status: 200,
				scope: 'blanket',
			});
		});

		it('records `no_policy` — not a fail-open guess — for a 404 robots.txt', async () => {
			// A 404 is a MEASUREMENT: this origin published no policy, and will say so
			// again tomorrow. It must not be conflated with "we could not find out".
			const { records } = await gatedWithRecords(async () => new Response('', { status: 404 }));
			expect(records[0]).toEqual({ host: 'example.com', path: '/', resolution: 'no_policy', failOpen: false, status: 404 });
		});

		it('records `unreachable` + failOpen for the crt.sh 502 case, and still proceeds', async () => {
			const { records, error } = await gatedWithRecords(async () => new Response('', { status: 502 }), 'https://crt.sh/');
			// Policy UNCHANGED: an unreadable robots.txt still does not block the scan.
			expect(error).toBeUndefined();
			expect(records[0]).toEqual({ host: 'crt.sh', path: '/', resolution: 'unreachable', failOpen: true, status: 502 });
		});

		it('records `unreachable` + the error name when the robots.txt fetch throws', async () => {
			const { records, error } = await gatedWithRecords(async () => {
				throw new TypeError('network error');
			});
			expect(error).toBeUndefined();
			expect(records[0]).toEqual({
				host: 'example.com',
				path: '/',
				resolution: 'unreachable',
				failOpen: true,
				errorName: 'TypeError',
			});
		});

		it('distinguishes a timeout from an unreachable origin', async () => {
			const { records, error } = await gatedWithRecords(async () => {
				const err = new Error('The operation was aborted due to timeout');
				err.name = 'TimeoutError';
				throw err;
			});
			expect(error).toBeUndefined();
			expect(records[0]).toEqual({
				host: 'example.com',
				path: '/',
				resolution: 'timeout',
				failOpen: true,
				errorName: 'TimeoutError',
			});
		});

		it('reports every gated request, including ones served from the per-host memo', async () => {
			// The record describes the DECISION applied to a request, not the network
			// fetch — otherwise only the first request of a check would be explainable.
			const records: RobotsResolutionRecord[] = [];
			const inner = async (url: string) =>
				url.endsWith('/robots.txt') ? textResponse('User-agent: *\nDisallow: /private\n') : textResponse('ok');
			const gated = withRobotsGate(inner, { onRobotsResolution: (r) => records.push(r) });
			await gated('https://example.com/a');
			await gated('https://example.com/b');
			expect(records.map((r) => r.path)).toEqual(['/a', '/b']);
			expect(records.every((r) => r.resolution === 'allowed')).toBe(true);
		});

		it("never reports the gate's own /robots.txt fetch", async () => {
			const records: RobotsResolutionRecord[] = [];
			const gated = withRobotsGate(async () => textResponse('User-agent: *\nDisallow: /private\n'), {
				onRobotsResolution: (r) => records.push(r),
			});
			await gated('https://example.com/robots.txt');
			expect(records).toEqual([]);
		});

		it('swallows a throwing callback — instrumentation can never break a scan', async () => {
			const gated = withRobotsGate(async () => textResponse('ok'), {
				onRobotsResolution: () => {
					throw new Error('observer blew up');
				},
			});
			await expect(gated('https://example.com/')).resolves.toBeInstanceOf(Response);
		});

		it('shares robots.txt decisions across gates through a caller-owned cache', async () => {
			// What makes per-invocation provenance affordable: a fresh gate per call
			// (needed for attribution) without re-fetching robots.txt per call.
			const robotsFetches = vi.fn();
			const inner = async (url: string) => {
				if (url.endsWith('/robots.txt')) {
					robotsFetches();
					return textResponse('User-agent: *\nDisallow: /private\n');
				}
				return textResponse('ok');
			};
			const groupCache = createRobotsGroupCache();
			const first: RobotsResolutionRecord[] = [];
			const second: RobotsResolutionRecord[] = [];
			await withRobotsGate(inner, { groupCache, onRobotsResolution: (r) => first.push(r) })('https://example.com/a');
			await withRobotsGate(inner, { groupCache, onRobotsResolution: (r) => second.push(r) })('https://example.com/b');
			expect(robotsFetches).toHaveBeenCalledTimes(1);
			expect(first).toHaveLength(1);
			expect(second).toHaveLength(1);
			expect(second[0]!.resolution).toBe('allowed');
		});
	});

	it('selects the named UA group over the wildcard group', async () => {
		const inner = vi.fn(async (url: string) => {
			if (url.endsWith('/robots.txt')) {
				return textResponse('User-agent: *\nDisallow: /\n\nUser-agent: BlackVeil-Security-Scanner\nAllow: /\n');
			}
			return textResponse('ok');
		});
		const gated = withRobotsGate(inner);
		const res = await gated('https://example.com/');
		expect(await res.text()).toBe('ok');
	});
});
