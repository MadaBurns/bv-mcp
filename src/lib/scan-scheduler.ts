// SPDX-License-Identifier: BUSL-1.1

/**
 * Phase 2 scheduler core — public barrel.
 *
 * Re-exports the schedule index (`schedule-index.ts`), adaptive rate
 * (`rate.ts`), and the dark-wired dispatcher (`dispatch.ts`) under one import
 * path. The whole subsystem ships DARK: it is inert unless
 * `SCAN_DISPATCH_ENABLED === 'true'` AND the optional `SCAN_SCHEDULE_DB` binding
 * is present. Flag readers are reused from `src/lib/scaling-flags.ts` — never
 * duplicated here.
 */

export {
	claimDue,
	upsertSchedule,
	reSpreadOnCadenceChange,
	markCompleted,
	type ClaimedScanRow,
	type ClaimDueOptions,
	type UpsertScheduleOptions,
	type ReSpreadOptions,
	type MarkCompletedOptions,
} from '../scheduler/schedule-index';

export {
	computeAdaptiveRate,
	recomputeAdaptiveRate,
	handleScanRateRecompute,
	rateKeyForLane,
	DEFAULT_RATE_BUFFER_FACTOR,
	DEFAULT_RATE_FLOOR_PER_SEC,
	type AdaptiveRateInput,
	type AdaptiveRateLane,
} from '../scheduler/rate';

export {
	dispatchDueScans,
	handleScanDispatch,
	SCAN_LANES,
	type ScanLane,
	type ScanDispatchEnv,
	type DispatchOptions,
} from '../scheduler/dispatch';
