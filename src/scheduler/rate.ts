// SPDX-License-Identifier: BUSL-1.1

/**
 * Phase 2 scheduler core — **adaptive rate**.
 *
 * `computeAdaptiveRate` derives a per-second dispatch target from the live
 * schedule population: `sum(count / cadenceSeconds) * bufferFactor`, floored.
 * `recomputeAdaptiveRate` persists one target per lane to the `RATE_LIMIT` KV
 * under `scan:rate:target:{lane}` so the cron dispatcher (`dispatch.ts`) can
 * size its claim without re-querying the schedule every tick.
 *
 * The per-tick CLAIM CAP is INTENTIONALLY independent of this rate — it comes
 * from `SCAN_DISPATCH_BATCH_SIZE` via `resolveScanDispatchConfig`
 * (`src/lib/scaling-flags.ts`). Tick size is `min(ceil(rate * tickSeconds),
 * cap)`, never the rate alone. Ships DARK + fail-soft: a no-op unless
 * `SCAN_DISPATCH_ENABLED === 'true'` AND both `SCAN_SCHEDULE_DB` + `RATE_LIMIT`
 * are bound.
 */

import { isScanDispatchEnabled } from '../lib/scaling-flags';
import type { ScanDispatchEnv } from './dispatch';

/** KV key prefix for the persisted per-lane dispatch target (scans/sec). */
const RATE_KEY_PREFIX = 'scan:rate:target:';

/** Default headroom multiplier over the steady-state required rate. */
export const DEFAULT_RATE_BUFFER_FACTOR = 1.5;
/** Default minimum dispatch rate so a near-empty lane still drains slowly. */
export const DEFAULT_RATE_FLOOR_PER_SEC = 0.1;

/** Per-cadence cohort within a lane: `count` rows on a `cadenceMs` interval. */
export interface AdaptiveRateLane {
	/** Number of active schedule rows in this cohort. */
	count: number;
	/** Cadence between scans for this cohort, ms. */
	cadenceMs: number;
}

/** Input to {@link computeAdaptiveRate}. */
export interface AdaptiveRateInput {
	/** Per-cadence cohorts to sum. */
	lanes: AdaptiveRateLane[];
	/** Headroom multiplier applied to the summed required rate. */
	bufferFactor: number;
	/** Floor (scans/sec) applied after the buffer. */
	floorPerSec: number;
}

/** KV key holding the dispatch target (scans/sec) for `lane`. */
export function rateKeyForLane(lane: string): string {
	return `${RATE_KEY_PREFIX}${lane}`;
}

/**
 * Required dispatch rate (scans/sec): `sum(count / cadenceSeconds) *
 * bufferFactor`, clamped UP to `floorPerSec`. Cohorts with a non-positive
 * cadence are skipped. Pure; never throws.
 */
export function computeAdaptiveRate({ lanes, bufferFactor, floorPerSec }: AdaptiveRateInput): number {
	const required = lanes.reduce((sum, lane) => {
		const cadenceSec = lane.cadenceMs / 1000;
		if (!Number.isFinite(cadenceSec) || cadenceSec <= 0) return sum;
		return sum + lane.count / cadenceSec;
	}, 0);
	return Math.max(required * bufferFactor, floorPerSec);
}

/** Aggregates active rows into per-cadence cohorts per lane. */
const RATE_AGG_SQL = 'SELECT lane, cadence_ms AS cadenceMs, COUNT(*) AS count FROM scan_schedule WHERE active=1 GROUP BY lane, cadence_ms';

/**
 * Recompute and persist each lane's dispatch target to `RATE_LIMIT` KV. DARK +
 * fail-soft: no-op when the flag is off or either binding is absent; swallows
 * all errors (KV/D1 are best-effort, never the dispatcher's correctness floor).
 */
export async function recomputeAdaptiveRate(env: ScanDispatchEnv, opts?: { bufferFactor?: number; floorPerSec?: number }): Promise<void> {
	try {
		if (!isScanDispatchEnabled(env)) return;
		const db = env.SCAN_SCHEDULE_DB;
		const kv = env.RATE_LIMIT;
		if (!db || !kv) return;
		const bufferFactor = opts?.bufferFactor ?? DEFAULT_RATE_BUFFER_FACTOR;
		const floorPerSec = opts?.floorPerSec ?? DEFAULT_RATE_FLOOR_PER_SEC;
		const { results } = await db.prepare(RATE_AGG_SQL).all<{ lane: string; cadenceMs: number; count: number }>();
		const byLane = new Map<string, AdaptiveRateLane[]>();
		for (const row of results ?? []) {
			const cohorts = byLane.get(row.lane) ?? [];
			cohorts.push({ count: row.count, cadenceMs: row.cadenceMs });
			byLane.set(row.lane, cohorts);
		}
		for (const [lane, cohorts] of byLane) {
			const rate = computeAdaptiveRate({ lanes: cohorts, bufferFactor, floorPerSec });
			await kv.put(rateKeyForLane(lane), String(rate));
		}
	} catch {
		// Fail-soft — telemetry/rate path must never throw from a cron tick.
	}
}

/**
 * Cron handler for the `scan-rate-recompute` route. Thin fail-soft wrapper —
 * dark by default (no-ops unless the dispatch flag is armed).
 */
export async function handleScanRateRecompute(env: ScanDispatchEnv, _ctx?: ExecutionContext): Promise<void> {
	await recomputeAdaptiveRate(env);
}
