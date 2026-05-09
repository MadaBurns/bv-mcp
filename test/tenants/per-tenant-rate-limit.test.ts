// SPDX-License-Identifier: BUSL-1.1

/**
 * Unit tests for the per-tenant rate limiter (Phase 6).
 *
 * Threat model: a single sub_tenant must not be able to exhaust the worker by
 * repeatedly hitting `/internal/tenants/scan` (or `/portfolio` / `/report`).
 * Each tenant gets its own KV-backed bucket; tier-keyed quotas determine the
 * cap.
 *
 * Atomicity is best-effort — KV `get + put` is racey. The threat model accepts
 * a small over-shoot (one cycle's-worth of extra messages at peak burst) in
 * exchange for not requiring a Durable Object on the hot path.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { checkAndRecord, PER_TENANT_QUOTAS } from '../../src/tenants/per-tenant-rate-limit';

/** In-memory KV mock matching the subset of `KVNamespace` we use. */
function makeKv(opts: { failGet?: boolean; failPut?: boolean } = {}): KVNamespace & { _store: Map<string, string> } {
	const store = new Map<string, string>();
	const kv = {
		_store: store,
		async get(key: string): Promise<string | null> {
			if (opts.failGet) throw new Error('kv get failed');
			return store.get(key) ?? null;
		},
		async put(key: string, value: string): Promise<void> {
			if (opts.failPut) throw new Error('kv put failed');
			store.set(key, value);
		},
		async delete(key: string): Promise<void> {
			store.delete(key);
		},
		async list(): Promise<KVNamespaceListResult<unknown, string>> {
			return { keys: [], list_complete: true, cacheStatus: null } as unknown as KVNamespaceListResult<unknown, string>;
		},
		async getWithMetadata(): Promise<unknown> {
			return { value: null, metadata: null };
		},
	};
	return kv as unknown as KVNamespace & { _store: Map<string, string> };
}

describe('checkAndRecord (per-tenant rate limiter)', () => {
	let kv: ReturnType<typeof makeKv>;
	beforeEach(() => {
		kv = makeKv();
	});

	it('allows the request and decrements remaining when under quota', async () => {
		const r = await checkAndRecord(kv, 'tenant-1', 'portfolio:min', 'default');
		expect(r.allowed).toBe(true);
		expect(r.remaining).toBe(PER_TENANT_QUOTAS.default.portfolioPerMin - 1);
		expect(r.resetAt).toBeGreaterThan(Date.now());
	});

	it('returns allowed:false when the bucket is at quota', async () => {
		// Pre-fill the KV bucket to exactly the quota.
		const tier = 'default';
		const quota = PER_TENANT_QUOTAS[tier].portfolioPerMin;
		// Walk the limiter up to the cap.
		for (let i = 0; i < quota; i++) {
			await checkAndRecord(kv, 't1', 'portfolio:min', tier);
		}
		const r = await checkAndRecord(kv, 't1', 'portfolio:min', tier);
		expect(r.allowed).toBe(false);
		expect(r.remaining).toBe(0);
	});

	it('returns allowed:false / remaining:0 when above quota', async () => {
		const tier = 'default';
		const quota = PER_TENANT_QUOTAS[tier].portfolioPerMin;
		for (let i = 0; i < quota + 5; i++) {
			await checkAndRecord(kv, 't1', 'portfolio:min', tier);
		}
		const r = await checkAndRecord(kv, 't1', 'portfolio:min', tier);
		expect(r.allowed).toBe(false);
		expect(r.remaining).toBe(0);
	});

	it('fail-soft: KV throwing on get returns allowed:true', async () => {
		const failingKv = makeKv({ failGet: true });
		const r = await checkAndRecord(failingKv, 'tenant-1', 'scans:day', 'default');
		expect(r.allowed).toBe(true);
		// remaining is the full quota (we couldn't read state, so we can't say less)
		expect(r.remaining).toBe(PER_TENANT_QUOTAS.default.scansPerDay);
	});

	it('uses YYYY-MM-DD for the daily bucket key', async () => {
		await checkAndRecord(kv, 'tenant-1', 'scans:day', 'default');
		const keys = Array.from(kv._store.keys());
		expect(keys.length).toBe(1);
		const k = keys[0];
		// Shape: `tenant-rl:<sub>:<bucket>:<window>`
		expect(k.startsWith('tenant-rl:tenant-1:scans:day:')).toBe(true);
		const window = k.slice('tenant-rl:tenant-1:scans:day:'.length);
		expect(/^\d{4}-\d{2}-\d{2}$/.test(window)).toBe(true);
	});

	it('different sub_tenants do not share buckets', async () => {
		const tier = 'default';
		const quota = PER_TENANT_QUOTAS[tier].portfolioPerMin;
		for (let i = 0; i < quota; i++) {
			await checkAndRecord(kv, 't1', 'portfolio:min', tier);
		}
		// t1 is now at quota; t2 should still be wide open.
		const r = await checkAndRecord(kv, 't2', 'portfolio:min', tier);
		expect(r.allowed).toBe(true);
		expect(r.remaining).toBe(quota - 1);
	});

	it('applies tier-specific quotas (enterprise > default)', async () => {
		const r = await checkAndRecord(kv, 't-ent', 'scans:day', 'enterprise');
		expect(r.allowed).toBe(true);
		expect(r.remaining).toBe(PER_TENANT_QUOTAS.enterprise.scansPerDay - 1);
		expect(PER_TENANT_QUOTAS.enterprise.scansPerDay).toBeGreaterThan(PER_TENANT_QUOTAS.default.scansPerDay);
	});
});
