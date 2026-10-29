// SPDX-License-Identifier: BUSL-1.1

/**
 * SQ-450: the coordinator path's KV mirror write leaves the response path when the caller hands
 * over its `waitUntil`. Each OAuth limiter call was three serial platform round trips (mirror
 * read, coordinator RPC, mirror write); the write's result is never read by the request and never
 * changes the verdict, so it runs after the response. The KV-only fallback keeps the write awaited:
 * there it is the authoritative count and its failure must still fail the request.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { consumeOAuthRateLimit, requestWaitUntil } from '../../src/oauth/rate-limit';
import type { QuotaCoordinator } from '../../src/lib/quota-coordinator';

afterEach(() => vi.restoreAllMocks());

/** KV whose put stays pending until `release()` (or rejects when `failPut`). */
function gatedKv(opts: { failPut?: boolean } = {}) {
	const store = new Map<string, string>();
	let release!: () => void;
	const gate = new Promise<void>((resolve) => (release = resolve));
	const put = vi.fn(async (key: string, value: string) => {
		await gate;
		if (opts.failPut) throw new Error('kv put failed');
		store.set(key, value);
	});
	const kv = { get: vi.fn(async (key: string) => store.get(key) ?? null), put } as unknown as KVNamespace;
	return { kv, put, store, release };
}

function coordinator(answer: unknown) {
	const dispatch = vi.fn(async () => answer);
	return { getByName: vi.fn(() => ({ dispatch })) } as unknown as DurableObjectNamespace<QuotaCoordinator>;
}

const options = {
	coordinationScope: 'token',
	kvKey: 'oauth:token-rl:198.51.100.7',
	principal: '198.51.100.7',
	limit: 30,
	windowSeconds: 60,
	nowMs: 1_050_000,
};

/** Races `promise` against a macrotask: true when it settled without waiting on anything still gated. */
async function settlesPromptly(promise: Promise<unknown>): Promise<boolean> {
	let settled = false;
	const mark = () => (settled = true);
	void promise.then(mark, mark);
	await new Promise((resolve) => setTimeout(resolve, 0));
	return settled;
}

describe('consumeOAuthRateLimit — deferred KV mirror write (SQ-450)', () => {
	it('answers an allowed request before the mirror write lands, and hands the write to waitUntil', async () => {
		const k = gatedKv();
		const deferred: Promise<unknown>[] = [];
		const verdict = consumeOAuthRateLimit({
			...options,
			kv: k.kv,
			quotaCoordinator: coordinator({ allowed: true, limit: 30, used: 4, remaining: 26 }),
			waitUntil: (p) => void deferred.push(p),
		});

		expect(await settlesPromptly(verdict)).toBe(true);
		expect(await verdict).toEqual({ exceeded: false, retryAfterSeconds: 0 });
		expect(deferred).toHaveLength(1);
		expect(k.store.size).toBe(0);

		k.release();
		await Promise.all(deferred);
		expect(JSON.parse(k.store.get(options.kvKey)!)).toMatchObject({ count: 4 });
	});

	it('defers the mirror on a denial too, and the verdict is still the coordinator 429', async () => {
		const k = gatedKv();
		const deferred: Promise<unknown>[] = [];
		const verdict = await consumeOAuthRateLimit({
			...options,
			kv: k.kv,
			quotaCoordinator: coordinator({ allowed: false, limit: 30, used: 30, remaining: 0 }),
			waitUntil: (p) => void deferred.push(p),
		});
		expect(verdict).toEqual({ exceeded: true, retryAfterSeconds: 30 });
		expect(verdict.unavailable).toBeUndefined();
		expect(deferred).toHaveLength(1);
		k.release();
		await Promise.all(deferred);
	});

	it('a deferred mirror write that fails never rejects the waitUntil promise', async () => {
		const k = gatedKv({ failPut: true });
		const deferred: Promise<unknown>[] = [];
		await consumeOAuthRateLimit({
			...options,
			kv: k.kv,
			quotaCoordinator: coordinator({ allowed: true, limit: 30, used: 1, remaining: 29 }),
			waitUntil: (p) => void deferred.push(p),
		});
		k.release();
		await expect(Promise.all(deferred)).resolves.toBeDefined();
		expect(k.put).toHaveBeenCalledTimes(1);
	});

	it('without waitUntil the mirror write is still awaited before the verdict', async () => {
		const k = gatedKv();
		const verdict = consumeOAuthRateLimit({
			...options,
			kv: k.kv,
			quotaCoordinator: coordinator({ allowed: true, limit: 30, used: 1, remaining: 29 }),
		});
		expect(await settlesPromptly(verdict)).toBe(false);
		k.release();
		await expect(verdict).resolves.toEqual({ exceeded: false, retryAfterSeconds: 0 });
		expect(k.store.has(options.kvKey)).toBe(true);
	});

	it('the KV-only fallback ignores waitUntil: its write is the count, awaited, and its failure propagates', async () => {
		const waitUntil = vi.fn();
		const k = gatedKv({ failPut: true });
		const verdict = consumeOAuthRateLimit({ ...options, kv: k.kv, waitUntil });
		expect(await settlesPromptly(verdict)).toBe(false);
		k.release();
		await expect(verdict).rejects.toThrow('kv put failed');
		expect(waitUntil).not.toHaveBeenCalled();
	});
});

describe('requestWaitUntil', () => {
	it('delegates to the execution context', () => {
		const waitUntil = vi.fn();
		const p = Promise.resolve();
		requestWaitUntil({ executionCtx: { waitUntil } as unknown as ExecutionContext })?.(p);
		expect(waitUntil).toHaveBeenCalledWith(p);
	});

	it('is undefined when the context has no execution context (Hono throws on access)', () => {
		const c = {
			get executionCtx(): ExecutionContext {
				throw new Error('This context has no ExecutionContext');
			},
		};
		expect(requestWaitUntil(c)).toBeUndefined();
	});
});
