// test/scheduler/rate-recompute.spec.ts
// SPDX-License-Identifier: BUSL-1.1
//
// Characterization of the persisted adaptive-rate pipeline (US-13 / SQ-373):
//   - recomputeAdaptiveRate: D1 cohort aggregate → per-lane KV target.
//   - readRateTarget (private, exercised through dispatchDueScans): KV target →
//     per-tick claim limit.
// These pin the CURRENT outputs for every branch so the function splits stay
// behaviour-preserving.
//
// Dynamic imports inside the test fns for mock isolation (workers pool).

import { afterEach, describe, expect, it, vi } from 'vitest';
import { makeScanScheduleDb, makeSlowQueue } from '../helpers/scan-schedule-d1';

const DAY_MS = 86_400_000;
const NOW = 1_750_000_000_000;

afterEach(() => {
	vi.restoreAllMocks();
	vi.resetModules();
});

interface AggRow {
	lane: string;
	cadenceMs: number;
	count: number;
}

/** D1 fake answering only the rate aggregate; records every prepared SQL. */
function makeRateDb(results: AggRow[] | undefined) {
	const prepare = vi.fn((_sql: string) => ({
		all: async () => ({ results }),
	}));
	return { db: { prepare } as unknown as D1Database, prepare };
}

/** KV fake recording puts in order. */
function makeRateKv(opts: { failPutAt?: number } = {}) {
	const puts: Array<{ key: string; value: string }> = [];
	const put = vi.fn(async (key: string, value: string) => {
		if (opts.failPutAt !== undefined && puts.length + 1 === opts.failPutAt) throw new Error('kv put boom');
		puts.push({ key, value });
	});
	return { kv: { put } as unknown as KVNamespace, put, puts };
}

type RateEnv = import('../../src/scheduler/dispatch').ScanDispatchEnv;

describe('recomputeAdaptiveRate — gating (dark + fail-soft)', () => {
	it('is a no-op when SCAN_DISPATCH_ENABLED is not exactly "true"', async () => {
		const { db, prepare } = makeRateDb([{ lane: 'fast', cadenceMs: DAY_MS, count: 86_400 }]);
		const { kv, put } = makeRateKv();
		const { recomputeAdaptiveRate } = await import('../../src/scheduler/rate');
		await recomputeAdaptiveRate({ SCAN_DISPATCH_ENABLED: 'false', SCAN_SCHEDULE_DB: db, RATE_LIMIT: kv } as unknown as RateEnv);
		await recomputeAdaptiveRate({ SCAN_SCHEDULE_DB: db, RATE_LIMIT: kv } as unknown as RateEnv);
		expect(prepare).not.toHaveBeenCalled();
		expect(put).not.toHaveBeenCalled();
	});

	it('is a no-op when SCAN_SCHEDULE_DB is unbound', async () => {
		const { kv, put } = makeRateKv();
		const { recomputeAdaptiveRate } = await import('../../src/scheduler/rate');
		await recomputeAdaptiveRate({ SCAN_DISPATCH_ENABLED: 'true', RATE_LIMIT: kv } as unknown as RateEnv);
		expect(put).not.toHaveBeenCalled();
	});

	it('is a no-op when RATE_LIMIT is unbound (D1 is never queried)', async () => {
		const { db, prepare } = makeRateDb([{ lane: 'fast', cadenceMs: DAY_MS, count: 86_400 }]);
		const { recomputeAdaptiveRate } = await import('../../src/scheduler/rate');
		await recomputeAdaptiveRate({ SCAN_DISPATCH_ENABLED: 'true', SCAN_SCHEDULE_DB: db } as unknown as RateEnv);
		expect(prepare).not.toHaveBeenCalled();
	});
});

describe('recomputeAdaptiveRate — persisted per-lane targets', () => {
	const env = (db: D1Database, kv: KVNamespace) =>
		({ SCAN_DISPATCH_ENABLED: 'true', SCAN_SCHEDULE_DB: db, RATE_LIMIT: kv }) as unknown as RateEnv;

	it('queries the active-row aggregate exactly once', async () => {
		const { db, prepare } = makeRateDb([]);
		const { kv } = makeRateKv();
		const { recomputeAdaptiveRate } = await import('../../src/scheduler/rate');
		await recomputeAdaptiveRate(env(db, kv));
		expect(prepare).toHaveBeenCalledTimes(1);
		expect(prepare.mock.calls[0][0]).toContain('FROM scan_schedule WHERE active=1 GROUP BY lane, cadence_ms');
	});

	it('writes one KV target per lane = sum(count/cadenceSec) * 1.5 default buffer', async () => {
		// fast: 86_400/day = 1/sec + 43_200/day = 0.5/sec → 1.5 * 1.5 = 2.25
		// slow: 8_640/day = 0.1/sec → 0.15
		const { db } = makeRateDb([
			{ lane: 'fast', cadenceMs: DAY_MS, count: 86_400 },
			{ lane: 'slow', cadenceMs: DAY_MS, count: 8_640 },
			{ lane: 'fast', cadenceMs: DAY_MS, count: 43_200 },
		]);
		const { kv, puts } = makeRateKv();
		const { recomputeAdaptiveRate } = await import('../../src/scheduler/rate');
		await recomputeAdaptiveRate(env(db, kv));
		// Lanes are written in first-seen order.
		expect(puts.map((p) => p.key)).toEqual(['scan:rate:target:fast', 'scan:rate:target:slow']);
		expect(Number(puts[0].value)).toBeCloseTo(2.25, 9);
		expect(Number(puts[1].value)).toBeCloseTo(0.15, 9);
	});

	it('clamps UP to the default 0.1/sec floor for a near-empty lane', async () => {
		const { db } = makeRateDb([{ lane: 'slow', cadenceMs: DAY_MS, count: 1 }]);
		const { kv, puts } = makeRateKv();
		const { recomputeAdaptiveRate } = await import('../../src/scheduler/rate');
		await recomputeAdaptiveRate(env(db, kv));
		expect(puts).toEqual([{ key: 'scan:rate:target:slow', value: '0.1' }]);
	});

	it('honours explicit bufferFactor and floorPerSec options', async () => {
		const { db } = makeRateDb([
			{ lane: 'fast', cadenceMs: DAY_MS, count: 86_400 }, // 1/sec * 3 = 3
			{ lane: 'slow', cadenceMs: DAY_MS, count: 1 }, // ~0 → floor 0.5
		]);
		const { kv, puts } = makeRateKv();
		const { recomputeAdaptiveRate } = await import('../../src/scheduler/rate');
		await recomputeAdaptiveRate(env(db, kv), { bufferFactor: 3, floorPerSec: 0.5 });
		expect(puts).toEqual([
			{ key: 'scan:rate:target:fast', value: '3' },
			{ key: 'scan:rate:target:slow', value: '0.5' },
		]);
	});

	it('a zero option is honoured (?? not ||): bufferFactor 0 collapses to the floor', async () => {
		const { db } = makeRateDb([{ lane: 'fast', cadenceMs: DAY_MS, count: 86_400 }]);
		const { kv, puts } = makeRateKv();
		const { recomputeAdaptiveRate } = await import('../../src/scheduler/rate');
		await recomputeAdaptiveRate(env(db, kv), { bufferFactor: 0, floorPerSec: 0 });
		expect(puts).toEqual([{ key: 'scan:rate:target:fast', value: '0' }]);
	});

	it('writes nothing when there are no active rows', async () => {
		const { db } = makeRateDb([]);
		const { kv, put } = makeRateKv();
		const { recomputeAdaptiveRate } = await import('../../src/scheduler/rate');
		await recomputeAdaptiveRate(env(db, kv));
		expect(put).not.toHaveBeenCalled();
	});

	it('treats a missing results array as no rows', async () => {
		const { db } = makeRateDb(undefined);
		const { kv, put } = makeRateKv();
		const { recomputeAdaptiveRate } = await import('../../src/scheduler/rate');
		await recomputeAdaptiveRate(env(db, kv));
		expect(put).not.toHaveBeenCalled();
	});

	it('skips non-positive cadences inside a lane (floor applies)', async () => {
		const { db } = makeRateDb([
			{ lane: 'fast', cadenceMs: 0, count: 1_000 },
			{ lane: 'fast', cadenceMs: DAY_MS, count: 86_400 },
		]);
		const { kv, puts } = makeRateKv();
		const { recomputeAdaptiveRate } = await import('../../src/scheduler/rate');
		await recomputeAdaptiveRate(env(db, kv));
		expect(Number(puts[0].value)).toBeCloseTo(1.5, 9);
	});

	it('swallows a D1 failure (never throws, nothing written)', async () => {
		const prepare = vi.fn(() => ({
			all: async () => {
				throw new Error('d1 boom');
			},
		}));
		const { kv, put } = makeRateKv();
		const { recomputeAdaptiveRate } = await import('../../src/scheduler/rate');
		await expect(recomputeAdaptiveRate(env({ prepare } as unknown as D1Database, kv))).resolves.toBeUndefined();
		expect(put).not.toHaveBeenCalled();
	});

	it('swallows a KV put failure; later lanes are NOT attempted after the throw', async () => {
		const { db } = makeRateDb([
			{ lane: 'fast', cadenceMs: DAY_MS, count: 86_400 },
			{ lane: 'slow', cadenceMs: DAY_MS, count: 86_400 },
		]);
		const { kv, put, puts } = makeRateKv({ failPutAt: 1 });
		const { recomputeAdaptiveRate } = await import('../../src/scheduler/rate');
		await expect(recomputeAdaptiveRate(env(db, kv))).resolves.toBeUndefined();
		expect(put).toHaveBeenCalledTimes(1);
		expect(puts).toEqual([]);
	});

	it('handleScanRateRecompute delegates with the default options', async () => {
		const { db } = makeRateDb([{ lane: 'fast', cadenceMs: DAY_MS, count: 86_400 }]);
		const { kv, puts } = makeRateKv();
		const { handleScanRateRecompute } = await import('../../src/scheduler/rate');
		await handleScanRateRecompute(env(db, kv));
		expect(puts).toEqual([{ key: 'scan:rate:target:fast', value: '1.5' }]);
	});
});

describe('readRateTarget (via dispatchDueScans) — KV target → per-tick claim limit', () => {
	const CAP = 500;

	/** Run one fast-lane dispatch tick and return the LIMIT bound into the claim SQL. */
	async function claimLimitFor(kv: KVNamespace | undefined): Promise<number> {
		const fake = makeScanScheduleDb([{ id: 1, tenant_id: 't', domain: 'a.com', lane: 'fast', next_scan_at: NOW - 1 }]);
		const { queue } = makeSlowQueue();
		const env = {
			SCAN_DISPATCH_ENABLED: 'true',
			SCAN_DISPATCH_BATCH_SIZE: String(CAP),
			SCAN_SCHEDULE_DB: fake.db,
			BV_SCANNER_QUEUE: queue,
			BV_SCANNER_SLOW_QUEUE: queue,
			...(kv ? { RATE_LIMIT: kv } : {}),
		} as unknown as RateEnv;
		const { dispatchDueScans } = await import('../../src/scheduler/dispatch');
		await dispatchDueScans(env, { now: NOW });
		const claims = fake.calls.filter((c) => c.sql.includes('RETURNING') && c.binds[2] === 'fast');
		expect(claims).toHaveLength(1);
		return claims[0].binds[4] as number;
	}

	const kvReturning = (raw: string | null) => ({ get: vi.fn(async () => raw) }) as unknown as KVNamespace;

	it('RATE_LIMIT unbound → limit is the batch cap', async () => {
		expect(await claimLimitFor(undefined)).toBe(CAP);
	});

	it('reads scan:rate:target:{lane} for each lane', async () => {
		const get = vi.fn(async () => null);
		await claimLimitFor({ get } as unknown as KVNamespace);
		expect(get).toHaveBeenCalledWith('scan:rate:target:fast');
		expect(get).toHaveBeenCalledWith('scan:rate:target:slow');
	});

	it('a valid target sizes the claim as ceil(rate * 60s)', async () => {
		expect(await claimLimitFor(kvReturning('2'))).toBe(120);
		expect(await claimLimitFor(kvReturning('1.5'))).toBe(90);
	});

	it('a tiny positive target still claims at least 1', async () => {
		expect(await claimLimitFor(kvReturning('0.001'))).toBe(1);
	});

	it('a target above the cap is clamped to the cap', async () => {
		expect(await claimLimitFor(kvReturning('100000'))).toBe(CAP);
	});

	it.each([
		['null (key absent)', null],
		['empty string', ''],
		['non-numeric', 'abc'],
		['zero', '0'],
		['negative', '-5'],
		['infinite', 'Infinity'],
	])('an unusable stored target (%s) falls back to the batch cap', async (_label, raw) => {
		expect(await claimLimitFor(kvReturning(raw))).toBe(CAP);
	});

	it('a KV read failure falls back to the batch cap (fail-soft)', async () => {
		const kv = {
			get: vi.fn(async () => {
				throw new Error('kv get boom');
			}),
		} as unknown as KVNamespace;
		expect(await claimLimitFor(kv)).toBe(CAP);
	});
});
