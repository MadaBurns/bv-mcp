/**
 * Scaling roadmap feature flags — TYPED, DEFAULT-OFF readers for the Phase 2 and
 * Phase 4 seams declared on `BvMcpEnv` (`src/index.ts`).
 *
 * These readers exist so later phases can flip behavior behind a flag without
 * re-deriving env-var parsing in multiple call sites. They are intentionally
 * INERT today: nothing in the runtime imports them yet, and with the backing
 * env vars unset every reader returns the OFF / undefined default — behavior is
 * byte-for-byte identical to today.
 *
 * Phases & decisions: `docs/superpowers/scaling-millions-domains-multitenancy.md`
 * (empirical gates + maintainer §5 decisions in the companion
 * `scaling-gates-resolved.md`).
 *
 * - Phase 2 — scheduled / queue-driven background scanning (cron dispatcher
 *   claim-and-advances `scan_schedule`, fans onto a slow-lane Queue).
 * - Phase 4 — Workers-for-Platforms multi-tenancy (per-tenant D1 via dynamic
 *   dispatch instead of a baked binding + redeploy per tenant).
 *
 * R8 quota-sharding and R10 profile-sharding flags are resolved elsewhere
 * (`resolveQuotaShardRouting` in `src/index.ts`, `resolveAccumulatorShardModeFromEnv`
 * in `lib/profile-accumulator.ts`) and are deliberately NOT duplicated here.
 */

/** Minimal env shape the scaling-flag readers consult. Optional everywhere. */
export interface ScalingFlagEnv {
	/** Phase 2 — `'true'` arms the cron dispatcher (default-OFF). */
	SCAN_DISPATCH_ENABLED?: string;
	/** Phase 2 — max schedule rows claimed per cron tick (string env-var). */
	SCAN_DISPATCH_BATCH_SIZE?: string;
	/** Phase 4 — `'dispatch'` selects Workers-for-Platforms routing (default-OFF). */
	TENANT_ROUTING_MODE?: string;
}

/** Built-in claim batch size used when the env var is unset/invalid. Inert while dispatch is OFF. */
export const DEFAULT_SCAN_DISPATCH_BATCH_SIZE = 50;

/** Lower/upper clamp for the per-tick claim batch (matches the Form-B `LIMIT ?` budget). */
export const SCAN_DISPATCH_BATCH_SIZE_MIN = 1;
export const SCAN_DISPATCH_BATCH_SIZE_MAX = 500;

/** Resolved Phase 2 scheduler config. */
export interface ScanDispatchConfig {
	/** Whether the cron dispatcher is armed. Default `false`. */
	readonly enabled: boolean;
	/** Rows to claim per tick, clamped to [MIN, MAX]. Inert while `enabled` is false. */
	readonly batchSize: number;
}

/** Phase 4 tenant routing mode. `'convention'` = today's binding-name string convention (default). */
export type TenantRoutingMode = 'convention' | 'dispatch';

/**
 * Phase 2 — resolve the scheduler dispatch config from env. DEFAULT-OFF: only the
 * exact string `'true'` enables the dispatcher; anything else (including unset)
 * yields `{ enabled: false, ... }`, i.e. no scheduled scanning (today's behavior).
 * The batch size is always clamped so a future caller can read it unconditionally.
 *
 * TODO(phase-2): consult `enabled` before the cron handler claims `scan_schedule`
 * rows, and use `batchSize` as the Form-B `LIMIT ?`. See spec Gate 4.
 */
export function resolveScanDispatchConfig(env: ScalingFlagEnv): ScanDispatchConfig {
	return {
		enabled: env.SCAN_DISPATCH_ENABLED === 'true',
		batchSize: clampBatchSize(env.SCAN_DISPATCH_BATCH_SIZE),
	};
}

/** Convenience: is the Phase 2 cron dispatcher armed? Default `false`. */
export function isScanDispatchEnabled(env: ScalingFlagEnv): boolean {
	return env.SCAN_DISPATCH_ENABLED === 'true';
}

/**
 * Phase 4 — resolve the tenant routing mode from env. DEFAULT-OFF: only the exact
 * string `'dispatch'` selects Workers-for-Platforms dynamic dispatch; anything
 * else (including unset) yields `'convention'`, i.e. the legacy binding-name
 * string convention (today's behavior).
 *
 * TODO(phase-4): branch the tenant resolver on this once
 * `TENANT_DISPATCH_NAMESPACE` is provisioned. See spec Phase-4 routing spike.
 */
export function resolveTenantRoutingMode(env: ScalingFlagEnv): TenantRoutingMode {
	return env.TENANT_ROUTING_MODE === 'dispatch' ? 'dispatch' : 'convention';
}

/**
 * Parse + clamp the optional batch-size env var. Non-numeric / out-of-range /
 * unset → `DEFAULT_SCAN_DISPATCH_BATCH_SIZE`. Pure; never throws.
 */
function clampBatchSize(raw: string | undefined): number {
	if (raw === undefined) return DEFAULT_SCAN_DISPATCH_BATCH_SIZE;
	const parsed = Number.parseInt(raw, 10);
	if (!Number.isFinite(parsed)) return DEFAULT_SCAN_DISPATCH_BATCH_SIZE;
	return Math.min(SCAN_DISPATCH_BATCH_SIZE_MAX, Math.max(SCAN_DISPATCH_BATCH_SIZE_MIN, parsed));
}
