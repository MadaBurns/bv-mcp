// SPDX-License-Identifier: BUSL-1.1

/**
 * Branch pins for `checkAndRecord`: input rejection, the strong-state (coordinator) scan path with its
 * fail-closed outcomes, the KV seed/mirror behaviour, and the fail-soft low-cost KV path. The coordinator
 * is a recording stub namespace, so these run as plain units.
 */
import { describe, it, expect } from 'vitest';
import { checkAndRecord, PER_TENANT_QUOTAS } from '../../src/tenants/per-tenant-rate-limit';
import type { BudgetReservationResult, QuotaCoordinator, QuotaCoordinatorRequest } from '../../src/lib/quota-coordinator';

function makeKv(opts: { failGet?: boolean; failPut?: boolean; seed?: Record<string, string> } = {}) {
	const store = new Map<string, string>(Object.entries(opts.seed ?? {}));
	const calls = { get: 0, put: 0 };
	const kv = {
		async get(key: string): Promise<string | null> {
			calls.get++;
			if (opts.failGet) throw new Error('kv get failed');
			return store.get(key) ?? null;
		},
		async put(key: string, value: string): Promise<void> {
			calls.put++;
			if (opts.failPut) throw new Error('kv put failed');
			store.set(key, value);
		},
	};
	return { kv: kv as unknown as KVNamespace, store, calls };
}

type DispatchResult = BudgetReservationResult | undefined;

function makeNamespace(handler: (payload: QuotaCoordinatorRequest) => DispatchResult | Promise<DispatchResult>) {
	const requests: QuotaCoordinatorRequest[] = [];
	const names: string[] = [];
	const namespace = {
		getByName(name: string) {
			names.push(name);
			return {
				async dispatch(payload: QuotaCoordinatorRequest) {
					requests.push(payload);
					return handler(payload);
				},
			};
		},
	} as unknown as DurableObjectNamespace<QuotaCoordinator>;
	return { namespace, requests, names };
}

function allowing(used: number, limit = PER_TENANT_QUOTAS.default.scansPerDay): BudgetReservationResult {
	return { allowed: true, remaining: limit - used, limit, used };
}

function utcDay(): string {
	return new Date().toISOString().slice(0, 10);
}

describe('checkAndRecord: amount validation', () => {
	for (const amount of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, Number.MAX_SAFE_INTEGER + 1]) {
		it(`rejects amount ${String(amount)} as unavailable without touching KV or the coordinator`, async () => {
			const { kv, calls } = makeKv();
			const { namespace, requests } = makeNamespace(() => allowing(1));
			for (const bucket of ['scans:day', 'portfolio:min'] as const) {
				const verdict = await checkAndRecord(kv, 't1', bucket, 'default', amount, namespace);
				expect(verdict).toEqual({ allowed: false, remaining: 0, resetAt: verdict.resetAt, unavailable: true });
				expect(verdict.resetAt).toBeGreaterThan(Date.now());
			}
			expect(calls).toEqual({ get: 0, put: 0 });
			expect(requests).toHaveLength(0);
		});
	}
});

describe('checkAndRecord: scan bucket with a coordinator', () => {
	it('reserves the weighted amount atomically and mirrors the used count to KV', async () => {
		const { kv, store } = makeKv();
		const { namespace, requests } = makeNamespace(() => allowing(7));
		const verdict = await checkAndRecord(kv, 'tenant-a', 'scans:day', 'default', 7, namespace);

		expect(verdict.allowed).toBe(true);
		expect(verdict.remaining).toBe(PER_TENANT_QUOTAS.default.scansPerDay - 7);
		expect(verdict.unavailable).toBeUndefined();
		expect(requests).toHaveLength(1);
		expect(requests[0]).toMatchObject({
			kind: 'reserve-budget',
			coordinationKey: `tenant-scan:tenant-a:${utcDay()}`,
			amount: 7,
			limit: PER_TENANT_QUOTAS.default.scansPerDay,
			expiresAt: verdict.resetAt,
			initialUsed: 0,
		});
		expect(Array.from(store.values())).toEqual(['7']);
	});

	it('uses the enterprise quota as the coordinator limit', async () => {
		const { namespace, requests } = makeNamespace(() => allowing(1, PER_TENANT_QUOTAS.enterprise.scansPerDay));
		await checkAndRecord(undefined, 'tenant-e', 'scans:day', 'enterprise', 1, namespace);
		expect(requests[0]).toMatchObject({ limit: PER_TENANT_QUOTAS.enterprise.scansPerDay });
	});

	it('seeds the coordinator with the KV mirror count', async () => {
		const day = utcDay();
		const { kv } = makeKv({ seed: { [`tenant-rl:tenant-b:scans:day:${day}`]: '41' } });
		const { namespace, requests } = makeNamespace(() => allowing(42));
		await checkAndRecord(kv, 'tenant-b', 'scans:day', 'default', 1, namespace);
		expect(requests[0]).toMatchObject({ initialUsed: 41 });
	});

	it('treats an unparsable or negative KV mirror as zero', async () => {
		const day = utcDay();
		for (const raw of ['not-a-number', '-5', '']) {
			const { kv } = makeKv({ seed: { [`tenant-rl:tenant-c:scans:day:${day}`]: raw } });
			const { namespace, requests } = makeNamespace(() => allowing(1));
			await checkAndRecord(kv, 'tenant-c', 'scans:day', 'default', 1, namespace);
			expect(requests[0]).toMatchObject({ initialUsed: 0 });
		}
	});

	it('still reserves with a zero seed when the KV read fails (the coordinator is authoritative)', async () => {
		const { kv } = makeKv({ failGet: true });
		const { namespace, requests } = makeNamespace(() => allowing(2));
		const verdict = await checkAndRecord(kv, 'tenant-d', 'scans:day', 'default', 2, namespace);
		expect(verdict.allowed).toBe(true);
		expect(requests[0]).toMatchObject({ initialUsed: 0 });
	});

	it('reserves without any KV binding and writes no mirror', async () => {
		const { namespace, requests } = makeNamespace(() => allowing(3));
		const verdict = await checkAndRecord(undefined, 'tenant-f', 'scans:day', 'default', 3, namespace);
		expect(verdict).toMatchObject({ allowed: true, remaining: PER_TENANT_QUOTAS.default.scansPerDay - 3 });
		expect(requests).toHaveLength(1);
	});

	it('returns the coordinator denial verbatim', async () => {
		const { kv, store } = makeKv();
		const { namespace } = makeNamespace(() => ({ allowed: false, remaining: 0, limit: 10, used: 10 }));
		const verdict = await checkAndRecord(kv, 'tenant-g', 'scans:day', 'default', 5, namespace);
		expect(verdict.allowed).toBe(false);
		expect(verdict.remaining).toBe(0);
		expect(verdict.unavailable).toBeUndefined();
		// The denied used count is still mirrored.
		expect(Array.from(store.values())).toEqual(['10']);
	});

	it('keeps the coordinator verdict when the KV mirror write fails', async () => {
		const { kv, calls } = makeKv({ failPut: true });
		const { namespace } = makeNamespace(() => allowing(4));
		const verdict = await checkAndRecord(kv, 'tenant-h', 'scans:day', 'default', 4, namespace);
		expect(verdict.allowed).toBe(true);
		expect(calls.put).toBe(1);
	});

	it('fails closed as unavailable when the coordinator returns no reservation', async () => {
		const { kv, store } = makeKv();
		const { namespace } = makeNamespace(() => undefined);
		const verdict = await checkAndRecord(kv, 'tenant-i', 'scans:day', 'default', 1, namespace);
		expect(verdict).toMatchObject({ allowed: false, remaining: 0, unavailable: true });
		expect(store.size).toBe(0);
	});

	it('fails closed as unavailable when the coordinator throws', async () => {
		const { kv, store } = makeKv();
		const { namespace } = makeNamespace(() => {
			throw new Error('DO outage');
		});
		const verdict = await checkAndRecord(kv, 'tenant-j', 'scans:day', 'default', 1, namespace);
		expect(verdict).toMatchObject({ allowed: false, remaining: 0, unavailable: true });
		expect(store.size).toBe(0);
	});

	it('does not consult the coordinator for the low-cost buckets', async () => {
		const { kv, store } = makeKv();
		const { namespace, requests } = makeNamespace(() => allowing(1));
		for (const bucket of ['portfolio:min', 'reports:min'] as const) {
			const verdict = await checkAndRecord(kv, 'tenant-k', bucket, 'default', 1, namespace);
			expect(verdict.allowed).toBe(true);
		}
		expect(requests).toHaveLength(0);
		expect(store.size).toBe(2);
	});
});

describe('checkAndRecord: KV-only path', () => {
	it('allows with the full quota and writes nothing when there is no KV and no coordinator', async () => {
		for (const bucket of ['scans:day', 'portfolio:min', 'reports:min'] as const) {
			const verdict = await checkAndRecord(undefined, 'tenant-l', bucket, 'default');
			expect(verdict).toMatchObject({ allowed: true });
			expect(verdict.unavailable).toBeUndefined();
		}
		const scans = await checkAndRecord(undefined, 'tenant-l', 'scans:day', 'default', 5);
		expect(scans.remaining).toBe(PER_TENANT_QUOTAS.default.scansPerDay);
	});

	it('allows the scan bucket from KV when no coordinator is bound, counting the weighted amount', async () => {
		const { kv, store } = makeKv();
		const first = await checkAndRecord(kv, 'tenant-m', 'scans:day', 'default', 4);
		const second = await checkAndRecord(kv, 'tenant-m', 'scans:day', 'default', 6);
		expect(first.remaining).toBe(PER_TENANT_QUOTAS.default.scansPerDay - 4);
		expect(second.remaining).toBe(PER_TENANT_QUOTAS.default.scansPerDay - 10);
		expect(Array.from(store.values())).toEqual(['10']);
	});

	it('fails soft with the full quota when the KV read fails, for each low-cost bucket', async () => {
		for (const [bucket, quota] of [
			['portfolio:min', PER_TENANT_QUOTAS.default.portfolioPerMin],
			['reports:min', PER_TENANT_QUOTAS.default.reportsPerMin],
		] as const) {
			const { kv, calls } = makeKv({ failGet: true });
			const verdict = await checkAndRecord(kv, 'tenant-n', bucket, 'default');
			expect(verdict).toMatchObject({ allowed: true, remaining: quota });
			expect(calls.put).toBe(0);
		}
	});

	it('still allows when the increment write fails', async () => {
		const { kv } = makeKv({ failPut: true });
		const verdict = await checkAndRecord(kv, 'tenant-o', 'portfolio:min', 'default');
		expect(verdict).toMatchObject({ allowed: true, remaining: PER_TENANT_QUOTAS.default.portfolioPerMin - 1 });
	});

	it('does not write when the request is over quota', async () => {
		const quota = PER_TENANT_QUOTAS.default.reportsPerMin;
		const { kv, calls } = makeKv();
		await checkAndRecord(kv, 'tenant-p', 'reports:min', 'default', quota);
		const putsBefore = calls.put;
		const denied = await checkAndRecord(kv, 'tenant-p', 'reports:min', 'default');
		expect(denied).toMatchObject({ allowed: false, remaining: 0 });
		expect(denied.unavailable).toBeUndefined();
		expect(calls.put).toBe(putsBefore);
	});

	it('falls back to the default tier for an unknown tier name', async () => {
		const { kv } = makeKv();
		const verdict = await checkAndRecord(kv, 'tenant-q', 'portfolio:min', 'no-such-tier');
		expect(verdict.remaining).toBe(PER_TENANT_QUOTAS.default.portfolioPerMin - 1);
	});
});
