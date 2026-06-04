// SPDX-License-Identifier: BUSL-1.1
//
// #363 item 3 — automatic short-lived request-dedup window for mutating tools.
//
// A client network-retry of a *_start/register tool re-sends identical args and
// would otherwise create a duplicate watch/scan/investigation. withRequestDedup
// fingerprints (principal + tool + canonical args) into KV with a short TTL and
// replays the prior SUCCESSFUL result on a duplicate, so the retry gets the same
// operation ID instead of enqueuing fresh work.

import { describe, it, expect, vi } from 'vitest';
import { canonicalJson, computeDedupKey, withRequestDedup, DEDUP_TTL_SECONDS } from '../src/lib/request-dedup';

/** Minimal Map-backed KV stub (expirationTtl ignored — TTL is exercised via the option, not the clock). */
function fakeKv() {
	const store = new Map<string, string>();
	const puts: { key: string; ttl?: number }[] = [];
	return {
		store,
		puts,
		kv: {
			get: vi.fn(async (k: string) => store.get(k) ?? null),
			put: vi.fn(async (k: string, v: string, opts?: { expirationTtl?: number }) => {
				store.set(k, v);
				puts.push({ key: k, ttl: opts?.expirationTtl });
			}),
		} as unknown as KVNamespace,
	};
}

const base = (kv: KVNamespace) => ({ toolName: 'scan_buckets_start', principal: 'key_abc', args: { target: 'acme.example' }, kv });

describe('canonicalJson', () => {
	it('is independent of object key order', () => {
		expect(canonicalJson({ a: 1, b: 2 })).toBe(canonicalJson({ b: 2, a: 1 }));
		expect(canonicalJson({ x: { p: 1, q: 2 } })).toBe(canonicalJson({ x: { q: 2, p: 1 } }));
	});

	it('preserves array order (array order is semantic)', () => {
		expect(canonicalJson({ providers: ['a', 'b'] })).not.toBe(canonicalJson({ providers: ['b', 'a'] }));
	});
});

describe('computeDedupKey', () => {
	it('is stable, namespaced by tool, and differs by principal/args', async () => {
		const k1 = await computeDedupKey('scan_buckets_start', 'key_abc', { target: 'acme.example' });
		const k2 = await computeDedupKey('scan_buckets_start', 'key_abc', { target: 'acme.example' });
		expect(k1).toBe(k2);
		expect(k1.startsWith('idem:scan_buckets_start:')).toBe(true);
		expect(k1).not.toBe(await computeDedupKey('scan_buckets_start', 'key_OTHER', { target: 'acme.example' }));
		expect(k1).not.toBe(await computeDedupKey('scan_buckets_start', 'key_abc', { target: 'other.example' }));
	});
});

describe('withRequestDedup', () => {
	it('replays the stored result on a duplicate without re-executing', async () => {
		const { kv } = fakeKv();
		const fn = vi.fn(async () => ({ content: [{ type: 'text', text: 'scanId=123' }], isError: false }));

		const first = await withRequestDedup(base(kv), fn);
		const second = await withRequestDedup(base(kv), fn);

		expect(fn).toHaveBeenCalledTimes(1); // second call short-circuited
		expect(second).toEqual(first);
	});

	it('stores with the short TTL', async () => {
		const { kv, puts } = fakeKv();
		await withRequestDedup(base(kv), async () => ({ content: [], isError: false }));
		expect(puts[0]?.ttl).toBe(DEDUP_TTL_SECONDS);
	});

	it('does not dedup across different args', async () => {
		const { kv } = fakeKv();
		const fn = vi.fn(async () => ({ content: [], isError: false }));
		await withRequestDedup({ toolName: 'scan_buckets_start', principal: 'key_abc', args: { target: 'a.example' }, kv }, fn);
		await withRequestDedup({ toolName: 'scan_buckets_start', principal: 'key_abc', args: { target: 'b.example' }, kv }, fn);
		expect(fn).toHaveBeenCalledTimes(2);
	});

	it('does NOT store error results — a transient failure stays retryable', async () => {
		const { kv } = fakeKv();
		const fn = vi.fn(async () => ({ content: [{ type: 'text', text: 'boom' }], isError: true }));
		await withRequestDedup(base(kv), fn);
		await withRequestDedup(base(kv), fn);
		expect(fn).toHaveBeenCalledTimes(2); // not cached → retried
	});

	it('skips dedup entirely without a real principal (no cross-caller ID leak)', async () => {
		const { kv } = fakeKv();
		const fn = vi.fn(async () => ({ content: [], isError: false }));
		await withRequestDedup({ toolName: 'scan_buckets_start', principal: undefined, args: { target: 'a.example' }, kv }, fn);
		await withRequestDedup({ toolName: 'scan_buckets_start', principal: undefined, args: { target: 'a.example' }, kv }, fn);
		expect(fn).toHaveBeenCalledTimes(2);
		expect((kv.get as ReturnType<typeof vi.fn>)).not.toHaveBeenCalled();
	});

	it('is fail-soft when KV read throws — executes normally', async () => {
		const kv = { get: vi.fn(async () => { throw new Error('KV down'); }), put: vi.fn(async () => {}) } as unknown as KVNamespace;
		const fn = vi.fn(async () => ({ content: [{ type: 'text', text: 'ok' }], isError: false }));
		const result = await withRequestDedup(base(kv), fn);
		expect(fn).toHaveBeenCalledTimes(1);
		expect(result.isError).toBe(false);
	});

	it('routes the kv.put through waitUntil when provided (off the timeout budget)', async () => {
		const { kv } = fakeKv();
		const deferred: Promise<unknown>[] = [];
		const waitUntil = (p: Promise<unknown>) => deferred.push(p);
		await withRequestDedup({ ...base(kv), waitUntil }, async () => ({ content: [], isError: false }));
		expect(deferred.length).toBe(1);
		await Promise.all(deferred);
	});
});
