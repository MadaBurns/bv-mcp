// SPDX-License-Identifier: BUSL-1.1

/**
 * Phase 2 scheduler core — the **dark-wired dispatcher**.
 *
 * `dispatchDueScans` is the cron-tick entrypoint: it reads the persisted
 * per-lane rate target (`scan:rate:target:{lane}` in `RATE_LIMIT` KV), claims
 * `min(ceil(target * tickSeconds), batchSizeCap)` due rows per lane via the
 * GATE-4 Form-B claim (`schedule-index.ts`), and fans each onto a Queue — the
 * `fast` lane to the existing `BV_SCANNER_QUEUE`, the `slow` lane to the new
 * optional `BV_SCANNER_SLOW_QUEUE` (falling back to whichever queue IS bound so
 * a partial deploy still drains).
 *
 * Ships DARK + fail-soft: a NO-OP (no claim, no enqueue) unless
 * `isScanDispatchEnabled(env)` (i.e. `SCAN_DISPATCH_ENABLED === 'true'`) AND the
 * optional `SCAN_SCHEDULE_DB` binding is present. Gating reuses the readers in
 * `src/lib/scaling-flags.ts` — never re-derived here. No cron is added to
 * `wrangler.jsonc`; the operator binds the DB/queue and adds the cron entry at
 * enable time.
 */

import { isScanDispatchEnabled, resolveScanDispatchConfig, type ScalingFlagEnv } from '../lib/scaling-flags';
import { claimDue } from './schedule-index';
import { rateKeyForLane } from './rate';

/** Scheduling lanes. Aligned with the `scan:rate:target:{fast,slow}` KV keys. */
export const SCAN_LANES = ['fast', 'slow'] as const;

/** A configured scheduling lane. */
export type ScanLane = (typeof SCAN_LANES)[number];

/** Default cron cadence (seconds) the dispatcher assumes between ticks. */
const DEFAULT_TICK_SECONDS = 60;

/** Per-lane cadence used to advance claimed rows (the claim "hold" before re-scan). */
const LANE_CADENCE_MS: Record<ScanLane, number> = {
	fast: 6 * 60 * 60 * 1000, // 6h
	slow: 7 * 24 * 60 * 60 * 1000, // 7d
};

/** Minimal queue producer shape (matches the tenant scanner-queue contract). */
interface ScanQueueProducer {
	send(message: unknown, options?: { contentType?: 'json' }): Promise<void>;
}

/** Env shape the Phase 2 dispatcher consults. Every binding is OPTIONAL (absent → no-op). */
export interface ScanDispatchEnv extends ScalingFlagEnv {
	/** D1 holding the `scan_schedule` table. Absent → no scheduled scanning. */
	SCAN_SCHEDULE_DB?: D1Database;
	/** Slow-lane queue (Phase 2, new optional). */
	BV_SCANNER_SLOW_QUEUE?: ScanQueueProducer;
	/** Fast-lane queue (existing tenant scanner queue). */
	BV_SCANNER_QUEUE?: ScanQueueProducer;
	/** KV holding persisted per-lane rate targets. */
	RATE_LIMIT?: KVNamespace;
}

/** Args for {@link dispatchDueScans}. */
export interface DispatchOptions {
	/** Wall-clock epoch ms "now". */
	now: number;
	/** Cron tick width in seconds (default 60). */
	tickSeconds?: number;
}

/** Message enqueued per claimed schedule row. */
interface ScheduledScanMessage {
	tenant_id: string;
	domain: string;
	lane: string;
	scheduled_at: number;
}

/**
 * Claim due rows per lane and fan them onto the lane's queue. DARK by default
 * and fail-soft throughout — a per-lane error is swallowed so one bad lane can't
 * starve the others, and the whole call no-ops when disabled or unprovisioned.
 */
export async function dispatchDueScans(env: ScanDispatchEnv, { now, tickSeconds = DEFAULT_TICK_SECONDS }: DispatchOptions): Promise<void> {
	try {
		if (!isScanDispatchEnabled(env)) return;
		const db = env.SCAN_SCHEDULE_DB;
		if (!db) return;

		const cap = resolveScanDispatchConfig(env).batchSize;

		for (const lane of SCAN_LANES) {
			try {
				const target = await readRateTarget(env, lane);
				const rateBasedLimit = target !== undefined ? Math.max(1, Math.ceil(target * tickSeconds)) : cap;
				const limit = Math.min(rateBasedLimit, cap);

				const claimed = await claimDue(db, { lane, now, limit, cadenceMs: LANE_CADENCE_MS[lane] });
				if (claimed.length === 0) continue;

				const queue = resolveLaneQueue(env, lane);
				if (!queue) continue;

				for (const row of claimed) {
					const message: ScheduledScanMessage = { tenant_id: row.tenant_id, domain: row.domain, lane: row.lane, scheduled_at: now };
					await queue.send(message, { contentType: 'json' });
				}
			} catch {
				// Fail-soft per lane.
			}
		}
	} catch {
		// Fail-soft — a scheduler tick must never throw.
	}
}

/**
 * Cron handler for the `scan-dispatch` route. Thin fail-soft wrapper — dark by
 * default (no-ops unless the dispatch flag is armed).
 */
export async function handleScanDispatch(env: ScanDispatchEnv, _ctx?: ExecutionContext): Promise<void> {
	await dispatchDueScans(env, { now: Date.now() });
}

/** Read the persisted dispatch target (scans/sec) for `lane`, or `undefined`. Fail-soft. */
async function readRateTarget(env: ScanDispatchEnv, lane: string): Promise<number | undefined> {
	const kv = env.RATE_LIMIT;
	if (!kv) return undefined;
	try {
		const raw = await kv.get(rateKeyForLane(lane));
		if (!raw) return undefined;
		const parsed = Number.parseFloat(raw);
		return Number.isFinite(parsed) && parsed > 0 ? parsed : undefined;
	} catch {
		return undefined;
	}
}

/**
 * Resolve the queue for a lane: `fast` → `BV_SCANNER_QUEUE`, `slow` →
 * `BV_SCANNER_SLOW_QUEUE`. If the preferred queue is unbound, fall back to the
 * other so a partial deploy still drains rather than silently dropping rows.
 */
function resolveLaneQueue(env: ScanDispatchEnv, lane: string): ScanQueueProducer | undefined {
	const preferred = lane === 'fast' ? env.BV_SCANNER_QUEUE : env.BV_SCANNER_SLOW_QUEUE;
	const fallback = lane === 'fast' ? env.BV_SCANNER_SLOW_QUEUE : env.BV_SCANNER_QUEUE;
	return preferred ?? fallback;
}
