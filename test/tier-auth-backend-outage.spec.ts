// SPDX-License-Identifier: BUSL-1.1
//
// SQ-565: an opaque API key whose entitlement lookup (BV_WEB validate-key) could not be answered must be a
// retryable 503, never a 401 — and never a tier, never a stale positive, never a cached negative.
import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { afterEach, describe, expect, it, vi } from 'vitest';
import worker from '../src/index';

const KEY = 'opaque-outage-key';
const BASE_ENV = { BV_WEB_INTERNAL_KEY: 'internal-key' };

/** In-memory KV that records every write so cache poisoning is observable. */
function memoryKv() {
	const store = new Map<string, string>();
	const put = vi.fn(async (key: string, value: string) => {
		store.set(key, value);
	});
	const kv = {
		get: vi.fn(async (key: string) => store.get(key) ?? null),
		put,
		delete: vi.fn(async (key: string) => {
			store.delete(key);
		}),
		list: vi.fn(async () => ({ keys: [], list_complete: true })),
	} as unknown as KVNamespace;
	return { kv, put, store };
}

function bvWeb(fetch: (request: Request) => Promise<Response>): Fetcher {
	return { fetch: vi.fn(fetch) } as unknown as Fetcher;
}

async function tierFor(key: string, web: Fetcher, kv: KVNamespace) {
	const { resolveTier } = await import('../src/lib/tier-auth');
	return resolveTier(key, { ...BASE_ENV, RATE_LIMIT: kv, BV_WEB: web }, undefined, 'https://example.com/mcp');
}

/** Entitlement-cache writes only (the auth-resolution rate limiter also writes `rl:` keys to the same KV). */
function tierWrites(put: { mock: { calls: unknown[][] } }): unknown[][] {
	return put.mock.calls.filter(([key]) => String(key).startsWith('tier:'));
}

const UNAVAILABLE = { authenticated: false, storageUnavailable: true };

afterEach(() => {
	vi.useRealTimers();
});

describe('resolveTier: BV_WEB validate-key backend outage (SQ-565)', () => {
	it('backend throws -> storageUnavailable, no tier, nothing cached', async () => {
		const { kv, put } = memoryKv();
		const result = await tierFor(
			KEY,
			bvWeb(() => Promise.reject(new Error('connection refused'))),
			kv,
		);
		expect(result).toEqual(UNAVAILABLE);
		expect(tierWrites(put)).toEqual([]);
	});

	it('backend times out -> storageUnavailable, no tier, nothing cached', async () => {
		vi.useFakeTimers();
		const { kv, put } = memoryKv();
		const hang = bvWeb(
			(request) =>
				new Promise<Response>((_, reject) => {
					request.signal.addEventListener('abort', () => reject(request.signal.reason));
				}),
		);
		const pending = tierFor(KEY, hang, kv);
		await vi.advanceTimersByTimeAsync(5_001);
		expect(await pending).toEqual(UNAVAILABLE);
		expect(tierWrites(put)).toEqual([]);
	});

	it.each([500, 502, 503, 504])('backend %i -> storageUnavailable, nothing cached', async (status) => {
		const { kv, put } = memoryKv();
		const result = await tierFor(
			KEY,
			bvWeb(async () => new Response('down', { status })),
			kv,
		);
		expect(result).toEqual(UNAVAILABLE);
		expect(tierWrites(put)).toEqual([]);
	});

	it.each([
		['non-JSON body', () => new Response('<html>oops</html>', { status: 200 })],
		['wrong shape', () => Response.json({ unexpected: true })],
		['unknown tier value', () => Response.json({ tier: 'superuser' })],
		['empty JSON null', () => Response.json(null)],
	])('backend 200 with malformed body (%s) -> storageUnavailable, nothing cached', async (_label, respond) => {
		const { kv, put } = memoryKv();
		const result = await tierFor(
			KEY,
			bvWeb(async () => respond()),
			kv,
		);
		expect(result).toEqual(UNAVAILABLE);
		expect(tierWrites(put)).toEqual([]);
	});

	it('backend says the key is unknown (null tier) -> plain unauthenticated, negative cached as before', async () => {
		const { kv, put } = memoryKv();
		const result = await tierFor(
			KEY,
			bvWeb(async () => Response.json({ tier: null })),
			kv,
		);
		expect(result).toEqual({ authenticated: false });
		expect(tierWrites(put)).toHaveLength(1);
		expect(JSON.parse(String(tierWrites(put)[0][1]))).toMatchObject({ tier: 'free', revokedAt: expect.any(Number) });
	});

	// SQ-578: these describe the backend / internal channel (our bearer rejected, route absent, timeout, throttle),
	// never the customer key, so they are an outage, not a definitive negative.
	it.each([401, 403, 404, 408, 429])(
		'backend %i (about the backend, not the key) -> storageUnavailable, nothing cached',
		async (status) => {
			const { kv, put } = memoryKv();
			const result = await tierFor(
				KEY,
				bvWeb(async () => new Response('nope', { status })),
				kv,
			);
			expect(result).toEqual(UNAVAILABLE);
			expect(tierWrites(put)).toEqual([]);
		},
	);

	it.each([400, 410, 422])('any other non-2xx (%i) keeps the plain unauthenticated result, nothing cached', async (status) => {
		const { kv, put } = memoryKv();
		const result = await tierFor(
			KEY,
			bvWeb(async () => new Response('rejected', { status })),
			kv,
		);
		expect(result).toEqual({ authenticated: false });
		expect(tierWrites(put)).toEqual([]);
	});

	it('a backend 401 followed by a healthy answer for the same key authenticates (not negative-cached)', async () => {
		const { kv } = memoryKv();
		let status = 401;
		const web = bvWeb(async () => (status === 200 ? Response.json({ tier: 'developer' }) : new Response('nope', { status })));
		expect(await tierFor(KEY, web, kv)).toEqual(UNAVAILABLE);
		status = 200;
		expect(await tierFor(KEY, web, kv)).toMatchObject({ authenticated: true, tier: 'developer' });
	});

	it('backend says valid -> authenticated at the validated tier, positive cached', async () => {
		const { kv, put } = memoryKv();
		const result = await tierFor(
			KEY,
			bvWeb(async () => Response.json({ tier: 'enterprise' })),
			kv,
		);
		expect(result).toMatchObject({ authenticated: true, tier: 'enterprise' });
		expect(result.storageUnavailable).toBeUndefined();
		expect(JSON.parse(String(tierWrites(put)[0][1]))).toEqual({ tier: 'enterprise', revokedAt: null });
	});

	it('backend says valid with no KV binding -> authenticated (cache is only an accelerator)', async () => {
		const { resolveTier } = await import('../src/lib/tier-auth');
		const web = bvWeb(async () => Response.json({ tier: 'developer' }));
		const result = await resolveTier(KEY, { ...BASE_ENV, BV_WEB: web }, undefined, 'https://example.com/mcp');
		expect(result).toMatchObject({ authenticated: true, tier: 'developer' });
	});

	it('entitlement cache write failing after a definitive answer stays a plain unauthenticated result (unchanged)', async () => {
		const { kv, put } = memoryKv();
		put.mockImplementation(async (key: string) => {
			if (key.startsWith('tier:')) throw new Error('KV put failed');
		});
		const result = await tierFor(
			KEY,
			bvWeb(async () => Response.json({ tier: 'developer' })),
			kv,
		);
		expect(result).toEqual({ authenticated: false });
	});

	it('outage then healthy validation of the same key authenticates (outage was not negative-cached)', async () => {
		const { kv, store } = memoryKv();
		let healthy = false;
		const web = bvWeb(async () => (healthy ? Response.json({ tier: 'developer' }) : new Response('down', { status: 503 })));

		expect(await tierFor(KEY, web, kv)).toEqual(UNAVAILABLE);
		expect([...store.keys()].filter((k) => k.startsWith('tier:'))).toEqual([]);

		healthy = true;
		const recovered = await tierFor(KEY, web, kv);
		expect(recovered).toMatchObject({ authenticated: true, tier: 'developer' });
	});

	it('repeated outages never write any entitlement cache entry (no stale positive, no negative)', async () => {
		const { kv } = memoryKv();
		const down = bvWeb(async () => new Response('down', { status: 503 }));
		expect(await tierFor(KEY, down, kv)).toEqual(UNAVAILABLE);
		expect(await tierFor(KEY, down, kv)).toEqual(UNAVAILABLE);
		expect(tierWrites(vi.mocked(kv.put))).toEqual([]);
	});
});

describe('resolveTier: validate-key outage is logged without key material (SQ-578)', () => {
	async function loggedOutage(web: Fetcher): Promise<Record<string, unknown>[]> {
		const log = vi.spyOn(console, 'log').mockImplementation(() => undefined);
		try {
			expect(await tierFor(KEY, web, memoryKv().kv)).toEqual(UNAVAILABLE);
			return log.mock.calls
				.map(([line]) => JSON.parse(String(line)) as Record<string, unknown>)
				.filter((e) => e.result === 'validate_key_unavailable');
		} finally {
			log.mockRestore();
		}
	}

	it.each([
		['status_401', () => new Response('nope', { status: 401 })],
		['status_429', () => new Response('slow down', { status: 429 })],
		['status_5xx', () => new Response('down', { status: 503 })],
		['malformed_body', () => Response.json({ tier: 'superuser' })],
	])('logs one warn event with reason %s and nothing sensitive', async (reason, respond) => {
		const events = await loggedOutage(bvWeb(async () => respond()));
		expect(events).toHaveLength(1);
		expect(events[0]).toMatchObject({ severity: 'warn', category: 'auth', details: { reason } });
		const line = JSON.stringify(events[0]);
		expect(line).not.toContain(KEY);
		expect(line).not.toContain('internal-key');
		expect(line).not.toContain('https://internal');
	});

	it('logs a fetch_error for a thrown backend call', async () => {
		const events = await loggedOutage(bvWeb(() => Promise.reject(new Error('connection refused'))));
		expect(events).toHaveLength(1);
		expect(events[0]).toMatchObject({ details: { reason: 'fetch_error' } });
	});

	it('logs a timeout for a stalled backend call', async () => {
		vi.useFakeTimers();
		const hang = bvWeb(
			(request) =>
				new Promise<Response>((_, reject) => {
					request.signal.addEventListener('abort', () => reject(request.signal.reason));
				}),
		);
		const pending = loggedOutage(hang);
		await vi.advanceTimersByTimeAsync(5_001);
		const events = await pending;
		expect(events).toHaveLength(1);
		expect(events[0]).toMatchObject({ details: { reason: 'timeout' } });
	});

	it('does not log for a definitive answer', async () => {
		const log = vi.spyOn(console, 'log').mockImplementation(() => undefined);
		await tierFor(
			KEY,
			bvWeb(async () => Response.json({ tier: null })),
			memoryKv().kv,
		);
		await tierFor(
			KEY,
			bvWeb(async () => new Response('bad', { status: 400 })),
			memoryKv().kv,
		);
		const outageLogs = log.mock.calls.filter(([line]) => String(line).includes('validate_key_unavailable'));
		log.mockRestore();
		expect(outageLogs).toEqual([]);
	});
});

describe('/mcp: BV_WEB validate-key outage maps to 503 + Retry-After (SQ-565)', () => {
	async function post(web: Fetcher, kv: KVNamespace, key = KEY) {
		const ctx = createExecutionContext();
		const response = await worker.fetch(
			new Request('http://example.com/mcp', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${key}` },
				body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
			}),
			{ ...env, ...BASE_ENV, RATE_LIMIT: kv, BV_WEB: web } as unknown as Parameters<typeof worker.fetch>[1],
			ctx,
		);
		await waitOnExecutionContext(ctx);
		return response;
	}

	it('backend throws -> 503 with Retry-After, no challenge, no internals in the body', async () => {
		const { kv } = memoryKv();
		const response = await post(
			bvWeb(() => Promise.reject(new Error('connect ECONNREFUSED bv-web-prod.internal'))),
			kv,
		);
		expect(response.status).toBe(503);
		expect(response.headers.get('retry-after')).toBe('5');
		expect(response.headers.get('www-authenticate')).toBeNull();
		const text = await response.text();
		expect(JSON.parse(text)).toEqual({ error: 'temporarily_unavailable', error_description: 'Authorization state is unavailable' });
		expect(text).not.toMatch(/bv-web|ECONNREFUSED|internal/i);
	});

	it('backend 5xx -> 503 with Retry-After', async () => {
		const { kv } = memoryKv();
		const response = await post(
			bvWeb(async () => new Response('boom', { status: 502 })),
			kv,
		);
		expect(response.status).toBe(503);
		expect(response.headers.get('retry-after')).toBe('5');
	});

	it.each([401, 403, 404, 408, 429])('backend %i -> 503 with Retry-After, never a 401 (SQ-578)', async (status) => {
		const { kv } = memoryKv();
		const response = await post(
			bvWeb(async () => new Response('nope', { status })),
			kv,
		);
		expect(response.status).toBe(503);
		expect(response.headers.get('retry-after')).toBe('5');
		expect(response.headers.get('www-authenticate')).toBeNull();
	});

	it('backend malformed body -> 503 with Retry-After', async () => {
		const { kv } = memoryKv();
		const response = await post(
			bvWeb(async () => new Response('not json', { status: 200 })),
			kv,
		);
		expect(response.status).toBe(503);
		expect(response.headers.get('retry-after')).toBe('5');
	});

	it('backend says invalid -> 401 with WWW-Authenticate (unchanged)', async () => {
		const { kv } = memoryKv();
		const response = await post(
			bvWeb(async () => Response.json({ tier: null })),
			kv,
		);
		expect(response.status).toBe(401);
		expect(response.headers.get('www-authenticate')).toMatch(/^Bearer/);
		expect(response.headers.get('retry-after')).toBeNull();
	});

	it('outage response followed by healthy validation of the same key is served (200), not locked out', async () => {
		const { kv } = memoryKv();
		let healthy = false;
		const web = bvWeb(async () => (healthy ? Response.json({ tier: 'developer' }) : new Response('down', { status: 503 })));

		expect((await post(web, kv)).status).toBe(503);
		healthy = true;
		const recovered = await post(web, kv);
		expect(recovered.status).toBe(200);
	});
});
