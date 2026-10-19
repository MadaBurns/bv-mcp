// SPDX-License-Identifier: BUSL-1.1

/**
 * Decision table for `consumeOAuthRateLimit` (src/oauth/rate-limit.ts). Every row states
 * input -> verdict ({exceeded, retryAfterSeconds, unavailable?}) plus the KV / coordinator
 * side effects. The invariant under test: once a coordinator is bound its failure NEVER falls
 * through to racy KV, and a principal that has spent nothing is never told it is over budget.
 *
 * A fake coordinator namespace scripts the Durable Object answers, so no real DO is involved
 * and every window is pinned (`nowMs` for attempt 0, a `Date.now` spy for the retry).
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { consumeOAuthRateLimit } from '../../src/oauth/rate-limit';
import type { QuotaCoordinator } from '../../src/lib/quota-coordinator';

const WINDOW_S = 60;
const WINDOW_MS = WINDOW_S * 1000;
/** Mid-window instant: the window starts at 1_020_000 and ends at 1_080_000. */
const NOW = 1_050_000;
const WINDOW_START = Math.floor(NOW / WINDOW_MS) * WINDOW_MS;
const EXPIRES_AT = WINDOW_START + WINDOW_MS;
/** What the denied/allowed answers report as `retryAfterSeconds` at NOW. */
const RETRY_AFTER = Math.ceil((EXPIRES_AT - NOW) / 1000);

afterEach(() => vi.restoreAllMocks());

function createKv(opts: { failGet?: boolean; failPut?: boolean } = {}) {
	const store = new Map<string, string>();
	const get = vi.fn(async (key: string) => {
		if (opts.failGet) throw new Error('kv get failed');
		return store.get(key) ?? null;
	});
	const put = vi.fn(async (key: string, value: string, options?: unknown) => {
		void options;
		if (opts.failPut) throw new Error('kv put failed');
		store.set(key, value);
	});
	return { store, get, put, kv: { get, put, delete: vi.fn(), list: vi.fn() } as unknown as KVNamespace };
}

type Answer = unknown | Error;

/** Coordinator whose Nth dispatch answers `answers[N]` (the last answer repeats). */
function createCoordinator(answers: Answer[]) {
	const payloads: Array<Record<string, unknown>> = [];
	const dispatch = vi.fn(async (payload: Record<string, unknown>) => {
		payloads.push(payload);
		const answer = answers[Math.min(payloads.length - 1, answers.length - 1)];
		if (answer instanceof Error) throw answer;
		return answer;
	});
	const namespace = { getByName: vi.fn(() => ({ dispatch })) } as unknown as DurableObjectNamespace<QuotaCoordinator>;
	return { namespace, dispatch, payloads };
}

const allowed = (used: number, limit = 5) => ({ allowed: true, limit, used, remaining: limit - used });
const denied = (limit = 5) => ({ allowed: false, limit, used: limit, remaining: 0 });
const expiredWindowRefusal = (limit = 5) => ({ allowed: false, limit, used: 0, remaining: 0 });

function baseOptions(over: Record<string, unknown> = {}) {
	return {
		coordinationScope: 'register:min',
		kvKey: 'oauth:test-rate',
		principal: '198.51.100.20',
		limit: 5,
		windowSeconds: WINDOW_S,
		nowMs: NOW,
		...over,
	};
}

describe('consumeOAuthRateLimit — configuration is validated before any I/O', () => {
	it.each([
		['limit 0', { limit: 0 }],
		['limit -1', { limit: -1 }],
		['limit 1.5', { limit: 1.5 }],
		['limit NaN', { limit: Number.NaN }],
		['limit Infinity', { limit: Number.POSITIVE_INFINITY }],
		['windowSeconds 0', { windowSeconds: 0 }],
		['windowSeconds -1', { windowSeconds: -1 }],
		['windowSeconds NaN', { windowSeconds: Number.NaN }],
		['windowSeconds too large for a safe integer', { windowSeconds: 1e300 }],
		['windowSeconds below one millisecond', { windowSeconds: 0.0001 }],
	])('%s rejects with a RangeError (KV and coordinator untouched)', async (_label, over) => {
		const k = createKv();
		const c = createCoordinator([allowed(1)]);
		await expect(consumeOAuthRateLimit({ ...baseOptions(over), kv: k.kv })).rejects.toThrow(RangeError);
		await expect(consumeOAuthRateLimit({ ...baseOptions(over), kv: k.kv, quotaCoordinator: c.namespace })).rejects.toThrow(
			'Invalid OAuth rate-limit configuration',
		);
		expect(k.get).not.toHaveBeenCalled();
		expect(k.put).not.toHaveBeenCalled();
		expect(c.dispatch).not.toHaveBeenCalled();
	});

	it('accepts the smallest legal window (1 ms) and a fractional-second window', async () => {
		const k = createKv();
		await expect(consumeOAuthRateLimit({ ...baseOptions({ windowSeconds: 0.001 }), kv: k.kv })).resolves.toEqual({
			exceeded: false,
			retryAfterSeconds: 0,
		});
		await expect(consumeOAuthRateLimit({ ...baseOptions({ windowSeconds: 1.5, kvKey: 'other' }), kv: k.kv })).resolves.toEqual({
			exceeded: false,
			retryAfterSeconds: 0,
		});
	});
});

describe('consumeOAuthRateLimit — KV fixed window (no coordinator bound)', () => {
	it('first request opens a window pinned to the first request and is admitted', async () => {
		const k = createKv();
		const result = await consumeOAuthRateLimit({ ...baseOptions(), kv: k.kv });
		expect(result).toEqual({ exceeded: false, retryAfterSeconds: 0 });
		expect(JSON.parse(k.store.get('oauth:test-rate') as string)).toEqual({ count: 1, expiresAt: NOW + WINDOW_MS });
		expect(k.put.mock.calls[0][2]).toEqual({ expirationTtl: 60 });
	});

	it('a request under the limit increments the count and keeps the original expiry', async () => {
		const k = createKv();
		k.store.set('oauth:test-rate', JSON.stringify({ count: 3, expiresAt: NOW + 10_000 }));
		expect(await consumeOAuthRateLimit({ ...baseOptions(), kv: k.kv })).toEqual({ exceeded: false, retryAfterSeconds: 0 });
		expect(JSON.parse(k.store.get('oauth:test-rate') as string)).toEqual({ count: 4, expiresAt: NOW + 10_000 });
	});

	it('a request at the limit is denied with the remaining window as retry-after and writes nothing', async () => {
		const k = createKv();
		k.store.set('oauth:test-rate', JSON.stringify({ count: 5, expiresAt: NOW + 12_345 }));
		expect(await consumeOAuthRateLimit({ ...baseOptions(), kv: k.kv })).toEqual({ exceeded: true, retryAfterSeconds: 13 });
		expect(k.put).not.toHaveBeenCalled();
	});

	it('retry-after is never below one second', async () => {
		const k = createKv();
		k.store.set('oauth:test-rate', JSON.stringify({ count: 5, expiresAt: NOW + 1 }));
		expect(await consumeOAuthRateLimit({ ...baseOptions(), kv: k.kv })).toEqual({ exceeded: true, retryAfterSeconds: 1 });
	});

	it.each([
		['an expired window', JSON.stringify({ count: 99, expiresAt: NOW })],
		['malformed JSON', '{not json'],
		['a negative count', JSON.stringify({ count: -1, expiresAt: NOW + 5000 })],
		['a fractional count', JSON.stringify({ count: 1.5, expiresAt: NOW + 5000 })],
		['a non-numeric expiry', JSON.stringify({ count: 1, expiresAt: 'soon' })],
		['an unsafe-integer expiry', JSON.stringify({ count: 1, expiresAt: 1e300 })],
		['an empty value', ''],
	])('%s is ignored and a fresh window starts', async (_label, raw) => {
		const k = createKv();
		k.store.set('oauth:test-rate', raw);
		expect(await consumeOAuthRateLimit({ ...baseOptions(), kv: k.kv })).toEqual({ exceeded: false, retryAfterSeconds: 0 });
		expect(JSON.parse(k.store.get('oauth:test-rate') as string)).toEqual({ count: 1, expiresAt: NOW + WINDOW_MS });
	});

	it('the KV TTL tracks the window once it exceeds the 60 s floor', async () => {
		const k = createKv();
		await consumeOAuthRateLimit({ ...baseOptions({ windowSeconds: 300 }), kv: k.kv });
		expect(k.put.mock.calls[0][2]).toEqual({ expirationTtl: 300 });
	});

	it('a KV read failure propagates (the self-host path has no coordinator to defer to)', async () => {
		const k = createKv({ failGet: true });
		await expect(consumeOAuthRateLimit({ ...baseOptions(), kv: k.kv })).rejects.toThrow('kv get failed');
	});

	it('a KV write failure propagates', async () => {
		const k = createKv({ failPut: true });
		await expect(consumeOAuthRateLimit({ ...baseOptions(), kv: k.kv })).rejects.toThrow('kv put failed');
	});
});

describe('consumeOAuthRateLimit — coordinator path', () => {
	it('asks the coordinator for one unit of the aligned window under the documented key', async () => {
		const k = createKv();
		const c = createCoordinator([allowed(1)]);
		await consumeOAuthRateLimit({ ...baseOptions(), kv: k.kv, quotaCoordinator: c.namespace });
		expect(c.payloads).toHaveLength(1);
		expect(c.payloads[0]).toEqual({
			kind: 'reserve-budget',
			coordinationKey: `oauth-rate:register:min:198.51.100.20:${WINDOW_START}`,
			amount: 1,
			limit: 5,
			expiresAt: EXPIRES_AT,
			initialUsed: 0,
		});
	});

	it('an allowed reservation admits, mirrors the count into KV, and reports no retry-after', async () => {
		const k = createKv();
		const c = createCoordinator([allowed(2)]);
		const result = await consumeOAuthRateLimit({ ...baseOptions(), kv: k.kv, quotaCoordinator: c.namespace });
		expect(result).toEqual({ exceeded: false, retryAfterSeconds: 0 });
		expect(JSON.parse(k.store.get('oauth:test-rate') as string)).toEqual({ count: 2, expiresAt: EXPIRES_AT });
		expect(k.put.mock.calls[0][2]).toEqual({ expirationTtl: 60 });
	});

	it('a denied reservation answers exceeded with the window remainder and is not "unavailable"', async () => {
		const k = createKv();
		const c = createCoordinator([denied()]);
		const result = await consumeOAuthRateLimit({ ...baseOptions(), kv: k.kv, quotaCoordinator: c.namespace });
		expect(result).toEqual({ exceeded: true, retryAfterSeconds: RETRY_AFTER });
		expect(result.unavailable).toBeUndefined();
		expect(JSON.parse(k.store.get('oauth:test-rate') as string)).toEqual({ count: 5, expiresAt: EXPIRES_AT });
	});

	it.each([
		['undefined (unbound stub)', undefined],
		['a non-object', 'nope'],
		['null', null],
		['a missing field', { allowed: true }],
		['a limit that disagrees with the request', { allowed: true, limit: 9, used: 1, remaining: 8 }],
		['used above the limit', { allowed: true, limit: 5, used: 6, remaining: 0 }],
		['a negative used', { allowed: false, limit: 5, used: -1, remaining: 5 }],
		['a fractional used', { allowed: true, limit: 5, used: 1.5, remaining: 3 }],
		['remaining above the limit', { allowed: true, limit: 5, used: 1, remaining: 6 }],
		['an allowed answer that consumed nothing', { allowed: true, limit: 5, used: 0, remaining: 5 }],
		['a non-boolean allowed', { allowed: 'yes', limit: 5, used: 1, remaining: 4 }],
	])('%s fails closed as unavailable and never touches KV', async (_label, answer) => {
		const k = createKv();
		const c = createCoordinator([answer]);
		const result = await consumeOAuthRateLimit({ ...baseOptions(), kv: k.kv, quotaCoordinator: c.namespace });
		expect(result).toEqual({ exceeded: true, retryAfterSeconds: RETRY_AFTER, unavailable: true });
		expect(k.put).not.toHaveBeenCalled();
		expect(c.dispatch).toHaveBeenCalledTimes(1);
	});

	it('a coordinator that throws fails closed as unavailable (no fall-through to KV) with exactly one attempt', async () => {
		const k = createKv();
		const c = createCoordinator([new Error('coordinator unavailable')]);
		const result = await consumeOAuthRateLimit({ ...baseOptions(), kv: k.kv, quotaCoordinator: c.namespace });
		expect(result).toEqual({ exceeded: true, retryAfterSeconds: RETRY_AFTER, unavailable: true });
		expect(k.put).not.toHaveBeenCalled();
		expect(c.dispatch).toHaveBeenCalledTimes(1);
	});

	it('seeds the coordinator from the KV mirror count, clamped to the limit', async () => {
		const k = createKv();
		k.store.set('oauth:test-rate', JSON.stringify({ count: 3, expiresAt: NOW + 5000 }));
		const c = createCoordinator([allowed(4)]);
		await consumeOAuthRateLimit({ ...baseOptions(), kv: k.kv, quotaCoordinator: c.namespace });
		expect(c.payloads[0].initialUsed).toBe(3);

		k.store.set('oauth:test-rate', JSON.stringify({ count: 500, expiresAt: NOW + 5000 }));
		const c2 = createCoordinator([denied()]);
		await consumeOAuthRateLimit({ ...baseOptions(), kv: k.kv, quotaCoordinator: c2.namespace });
		expect(c2.payloads[0].initialUsed).toBe(5);
	});

	it('ignores an expired or malformed KV mirror when seeding', async () => {
		const k = createKv();
		k.store.set('oauth:test-rate', JSON.stringify({ count: 4, expiresAt: NOW }));
		const c = createCoordinator([allowed(1)]);
		await consumeOAuthRateLimit({ ...baseOptions(), kv: k.kv, quotaCoordinator: c.namespace });
		expect(c.payloads[0].initialUsed).toBe(0);
	});

	it('an unreadable KV mirror does not become an outage: the coordinator is still consulted from zero', async () => {
		const k = createKv({ failGet: true });
		const c = createCoordinator([allowed(1)]);
		const result = await consumeOAuthRateLimit({ ...baseOptions(), kv: k.kv, quotaCoordinator: c.namespace });
		expect(result).toEqual({ exceeded: false, retryAfterSeconds: 0 });
		expect(c.payloads[0].initialUsed).toBe(0);
	});

	it('a failing mirror write does not change the coordinator verdict', async () => {
		const k = createKv({ failPut: true });
		const admitted = createCoordinator([allowed(1)]);
		expect(await consumeOAuthRateLimit({ ...baseOptions(), kv: k.kv, quotaCoordinator: admitted.namespace })).toEqual({
			exceeded: false,
			retryAfterSeconds: 0,
		});
		const refused = createCoordinator([denied()]);
		expect(await consumeOAuthRateLimit({ ...baseOptions(), kv: k.kv, quotaCoordinator: refused.namespace })).toEqual({
			exceeded: true,
			retryAfterSeconds: RETRY_AFTER,
		});
	});

	it('the mirror TTL follows a long window rather than the 60 s floor', async () => {
		const k = createKv();
		const c = createCoordinator([allowed(1)]);
		await consumeOAuthRateLimit({ ...baseOptions({ windowSeconds: 600 }), kv: k.kv, quotaCoordinator: c.namespace });
		const ttl = (k.put.mock.calls[0][2] as { expirationTtl: number }).expirationTtl;
		expect(ttl).toBeGreaterThan(60);
		expect(ttl).toBeLessThanOrEqual(600);
	});
});

describe('consumeOAuthRateLimit — expired-window boundary race (#985): one bounded retry', () => {
	/** The retry reads the live clock; pin it into the NEXT window so its key differs. */
	function pinRetryClock() {
		const retryNow = NOW + WINDOW_MS;
		vi.spyOn(Date, 'now').mockReturnValue(retryNow);
		return { retryNow, retryStart: Math.floor(retryNow / WINDOW_MS) * WINDOW_MS };
	}

	it('retries ONCE on a different, freshly aligned window and admits when the retry succeeds', async () => {
		const { retryStart } = pinRetryClock();
		const k = createKv();
		const c = createCoordinator([expiredWindowRefusal(), allowed(1)]);
		const result = await consumeOAuthRateLimit({ ...baseOptions(), kv: k.kv, quotaCoordinator: c.namespace });
		expect(result).toEqual({ exceeded: false, retryAfterSeconds: 0 });
		expect(c.dispatch).toHaveBeenCalledTimes(2);
		expect(c.payloads[0].coordinationKey).toBe(`oauth-rate:register:min:198.51.100.20:${WINDOW_START}`);
		expect(c.payloads[1].coordinationKey).toBe(`oauth-rate:register:min:198.51.100.20:${retryStart}`);
		expect(c.payloads[1].expiresAt).toBe(retryStart + WINDOW_MS);
		expect(JSON.parse(k.store.get('oauth:test-rate') as string)).toEqual({ count: 1, expiresAt: retryStart + WINDOW_MS });
	});

	it('a retry that is denied for real reports exceeded, with retry-after from the retry window', async () => {
		const { retryNow, retryStart } = pinRetryClock();
		const k = createKv();
		const c = createCoordinator([expiredWindowRefusal(), denied()]);
		const result = await consumeOAuthRateLimit({ ...baseOptions(), kv: k.kv, quotaCoordinator: c.namespace });
		expect(result).toEqual({ exceeded: true, retryAfterSeconds: Math.ceil((retryStart + WINDOW_MS - retryNow) / 1000) });
		expect(c.dispatch).toHaveBeenCalledTimes(2);
	});

	it('a SECOND expired-window refusal is unavailable (never a 429 for a principal that used nothing) and is not retried again', async () => {
		pinRetryClock();
		const k = createKv();
		const c = createCoordinator([expiredWindowRefusal(), expiredWindowRefusal()]);
		const result = await consumeOAuthRateLimit({ ...baseOptions(), kv: k.kv, quotaCoordinator: c.namespace });
		expect(result.exceeded).toBe(true);
		expect(result.unavailable).toBe(true);
		expect(c.dispatch).toHaveBeenCalledTimes(2);
		expect(k.put).not.toHaveBeenCalled();
	});

	it('a retry that throws or answers malformed fails closed as unavailable', async () => {
		pinRetryClock();
		for (const second of [new Error('boom'), { allowed: true }, undefined]) {
			const k = createKv();
			const c = createCoordinator([expiredWindowRefusal(), second]);
			const result = await consumeOAuthRateLimit({ ...baseOptions(), kv: k.kv, quotaCoordinator: c.namespace });
			expect(result.exceeded).toBe(true);
			expect(result.unavailable).toBe(true);
			expect(c.dispatch).toHaveBeenCalledTimes(2);
		}
	});

	it('does not treat an ordinary denial (used === limit) as the boundary race', async () => {
		const k = createKv();
		const c = createCoordinator([denied()]);
		const result = await consumeOAuthRateLimit({ ...baseOptions(), kv: k.kv, quotaCoordinator: c.namespace });
		expect(result.exceeded).toBe(true);
		expect(result.unavailable).toBeUndefined();
		expect(c.dispatch).toHaveBeenCalledTimes(1);
	});

	it('the first attempt honours the pinned nowMs while the retry ignores it', async () => {
		const { retryStart } = pinRetryClock();
		const k = createKv();
		const c = createCoordinator([expiredWindowRefusal(), allowed(1)]);
		await consumeOAuthRateLimit({ ...baseOptions({ nowMs: NOW }), kv: k.kv, quotaCoordinator: c.namespace });
		expect(c.payloads[0].expiresAt).toBe(EXPIRES_AT);
		expect(c.payloads[1].expiresAt).toBe(retryStart + WINDOW_MS);
	});
});
