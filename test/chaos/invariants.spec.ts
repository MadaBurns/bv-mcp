// SPDX-License-Identifier: BUSL-1.1
//
// Regression spine for next-gen-reliability invariants. Each test corresponds
// to one phase's production fix. If the fix is reverted, exactly one test
// here should fail. Flakiness is not tolerated: fault injection is
// deterministic (synchronous throws), not timing-based.

import { describe, it, expect, afterEach, vi } from 'vitest';

describe('invariants: P1 — DohOutcome discrimination', () => {
	const savedFetch = globalThis.fetch;
	afterEach(() => { globalThis.fetch = savedFetch; vi.restoreAllMocks(); });

	it('fetchDohOutcome distinguishes timeout from ok (empty Answer)', async () => {
		const { fetchDohOutcome } = await import('../../src/lib/dns-transport');

		globalThis.fetch = vi.fn().mockRejectedValue(new DOMException('t', 'TimeoutError')) as unknown as typeof fetch;
		const timedOut = await fetchDohOutcome('https://cloudflare-dns.com/dns-query?name=example.com&type=TXT', 50);
		expect(timedOut.kind).toBe('error');
		if (timedOut.kind === 'error') expect(timedOut.reason).toBe('timeout');

		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			status: 200,
			json: async () => ({ Status: 0, Answer: [] }),
		}) as unknown as typeof fetch;
		const empty = await fetchDohOutcome('https://cloudflare-dns.com/dns-query?name=example.com&type=TXT', 3000);
		expect(empty.kind).toBe('ok');
	});
});

describe('invariants: P2 — secondary unconfirmed sentinel', () => {
	const savedFetch = globalThis.fetch;
	afterEach(() => { globalThis.fetch = savedFetch; vi.restoreAllMocks(); });

	it('both secondaries fail → { kind: "unconfirmed" }', async () => {
		globalThis.fetch = vi.fn().mockRejectedValue(new TypeError('net')) as unknown as typeof fetch;
		const { confirmWithSecondaryResolvers } = await import('../../src/lib/dns-transport');
		const result = await confirmWithSecondaryResolvers('example.com', 'TXT', false, 1000);
		expect((result as { kind?: string }).kind).toBe('unconfirmed');
	});
});

describe('invariants: P3 — sentinel lifecycle', () => {
	function makeMockKv() {
		const store = new Map<string, string>();
		const writeLog: Array<{ key: string; value: string; op: 'put' | 'delete'; ttl?: number }> = [];
		const kv = {
			async get(key: string) { return store.get(key) ?? null; },
			async put(key: string, value: string, opts?: { expirationTtl?: number }) {
				store.set(key, value);
				writeLog.push({ key, value, op: 'put', ttl: opts?.expirationTtl });
			},
			async delete(key: string) { store.delete(key); writeLog.push({ key, value: '', op: 'delete' }); },
		} as unknown as KVNamespace;
		return { kv, store, writeLog };
	}

	it('sentinel is deleted even when run() throws', async () => {
		const { kv, store } = makeMockKv();
		const { runWithCache } = await import('../../src/lib/cache');
		await expect(runWithCache('inv-key', async () => { throw new Error('x'); }, kv)).rejects.toThrow('x');
		expect(store.get('inv-key:computing')).toBeUndefined();
	});

	it('sentinel TTL is <= 10 seconds', async () => {
		const { kv, writeLog } = makeMockKv();
		const { runWithCache } = await import('../../src/lib/cache');
		await runWithCache('inv-ttl-key', async () => ({ ok: true }), kv);
		const sentinel = writeLog.find((e) => e.op === 'put' && e.key === 'inv-ttl-key:computing');
		expect(sentinel?.ttl).toBeDefined();
		expect(sentinel!.ttl!).toBeLessThanOrEqual(10);
	});
});

describe('invariants: P4 — session KV failure → degradation event', () => {
	it('KV put failure triggers kv_fallback degradation event', async () => {
		const events: Array<{ degradationType: string; component: string }> = [];
		const fakeAnalytics = {
			enabled: true,
			emitRequestEvent: vi.fn(),
			emitToolEvent: vi.fn(),
			emitRateLimitEvent: vi.fn(),
			emitSessionEvent: vi.fn(),
			emitDegradationEvent: (e: { degradationType: string; component: string }) =>
				events.push({ degradationType: e.degradationType, component: e.component }),
		};
		const kv = {
			async get() { return null; },
			async put() { throw new Error('KV down'); },
			async delete() {},
			async list() { return { keys: [] }; },
		} as unknown as KVNamespace;
		const { createSession } = await import('../../src/lib/session');
		await createSession(kv, fakeAnalytics as never);
		expect(events).toEqual([{ degradationType: 'kv_fallback', component: 'session' }]);
	});
});

describe('invariants: P5 — rate-limiter KV advisory lock is contention-gated', () => {
	it('uncontended call does not attempt advisory KV writes', async () => {
		let advisoryKeyReads = 0;
		const store = new Map<string, string>();
		const kv = {
			async get(key: string) {
				if (key.startsWith('lk:ip:')) advisoryKeyReads += 1;
				return store.get(key) ?? null;
			},
			async put(key: string, value: string) { store.set(key, value); },
			async delete(key: string) { store.delete(key); },
		} as unknown as KVNamespace;
		const { checkScopedRateLimitKVWithAdvisory } = await import('../../src/lib/rate-limiter');
		await checkScopedRateLimitKVWithAdvisory!('9.9.9.9', 'tools', 50, 300, kv);
		expect(advisoryKeyReads).toBe(0); // contention-gated — no advisory read on uncontended path
	});
});

describe('invariants: P6 — adaptive-weight KV round-trip', () => {
	it('publish then get returns the same weights', async () => {
		const store = new Map<string, string>();
		const kv = {
			async get(k: string) { return store.get(k) ?? null; },
			async put(k: string, v: string, _o?: { expirationTtl?: number }) { store.set(k, v); },
			async delete(k: string) { store.delete(k); },
		} as unknown as KVNamespace;
		const { publishAdaptiveWeightSummary, getAdaptiveWeights } = await import('../../src/lib/profile-accumulator');
		await publishAdaptiveWeightSummary('mail_enabled', 'google', { spf: 10, dmarc: 16 }, kv);
		const got = await getAdaptiveWeights('mail_enabled', 'google', kv);
		expect(got).toEqual({ spf: 10, dmarc: 16 });
	});

	it('missing summary returns null (static fallback signal)', async () => {
		const kv = {
			async get() { return null; },
			async put() {},
			async delete() {},
		} as unknown as KVNamespace;
		const { getAdaptiveWeights } = await import('../../src/lib/profile-accumulator');
		expect(await getAdaptiveWeights('mail_enabled', 'unknown', kv)).toBeNull();
	});
});

describe('invariants: P7c — DNSSEC transport failure → checkStatus=error', () => {
	const savedFetch = globalThis.fetch;
	afterEach(() => { globalThis.fetch = savedFetch; vi.restoreAllMocks(); });

	it('DNS fetch failure produces checkStatus=error, not "not configured"', async () => {
		globalThis.fetch = vi.fn().mockRejectedValue(new TypeError('net')) as unknown as typeof fetch;
		const { checkDnssec } = await import('../../src/tools/check-dnssec');
		const result = await checkDnssec('example.com');
		expect(result.checkStatus).toBe('error');
		const hasMisclassification = result.findings.some(
			(f: { title?: string }) => (f.title ?? '').toLowerCase().includes('not configured'),
		);
		expect(hasMisclassification).toBe(false);
	});
});

describe('invariants: P8 — analytics degradation dedup', () => {
	it('same (scanId, type, component) emits exactly once', async () => {
		const writes: Array<{ indexes?: string[] }> = [];
		const dataset = { writeDataPoint: (p: { indexes?: string[] }) => writes.push(p) };
		const { createAnalyticsClient } = await import('../../src/lib/analytics');
		const client = createAnalyticsClient(dataset as never);
		client.emitDegradationEvent({ degradationType: 'kv_fallback', component: 'session', scanId: 'X' });
		client.emitDegradationEvent({ degradationType: 'kv_fallback', component: 'session', scanId: 'X' });
		const degWrites = writes.filter((w) => w.indexes?.[0] === 'degradation');
		expect(degWrites.length).toBe(1);
	});

	it('different scanIds produce separate emits', async () => {
		const writes: Array<{ indexes?: string[] }> = [];
		const dataset = { writeDataPoint: (p: { indexes?: string[] }) => writes.push(p) };
		const { createAnalyticsClient } = await import('../../src/lib/analytics');
		const client = createAnalyticsClient(dataset as never);
		client.emitDegradationEvent({ degradationType: 'kv_fallback', component: 'session', scanId: 'Y1' });
		client.emitDegradationEvent({ degradationType: 'kv_fallback', component: 'session', scanId: 'Y2' });
		const degWrites = writes.filter((w) => w.indexes?.[0] === 'degradation');
		expect(degWrites.length).toBe(2);
	});
});
