// SPDX-License-Identifier: BUSL-1.1

/**
 * Per-tenant rate limiter for `/internal/tenants/*`.
 *
 * The public per-IP limiter in `src/lib/rate-limiter.ts` doesn't apply to the
 * internal Tenant surface (service-binding traffic carries no `cf-connecting-ip`).
 * Without a tenant-scoped cap, one runaway customer could exhaust the worker
 * for everyone else.
 *
 * Implementation
 * --------------
 * - Buckets are keyed by `(sub_tenant_id, bucket, window)`. `bucket` selects
 *   one of the three workloads (`scans:day` / `portfolio:min` / `reports:min`);
 *   `window` is the fixed-width time slice (UTC date or `YYYY-MM-DDTHH:MM`).
 * - Portfolio/report counters are stored in `RATE_LIMIT` KV. Each call does
 *   `get → +1 → put`; those low-cost defense-in-depth buckets remain best-effort.
 * - Scan dispatches are weighted by the number of validated domains. When the
 *   coordinator is bound, the whole weighted reservation is committed
 *   atomically before any inline work or queue send. This is a cost boundary:
 *   concurrent requests may not split or overshoot the daily domain budget.
 * - Fail-soft: any KV error short-circuits to `allowed:true`. The counter is
 *   purely a defense in depth — losing it must not cause a request outage.
 *
 * Tier defaults are intentionally generous so the default deployment behaves
 * the same as before this limiter existed for legitimate traffic patterns.
 * Recent enterprise-scale benchmarks sit around 100 portfolio updates/day,
 * 6 reports/min during dashboard refreshes, and 50k scans/day in steady state.
 */

import { reserveBudgetWithCoordinator, type QuotaCoordinator } from '../lib/quota-coordinator';

export interface PerTenantQuota {
	/** Max scan-domain dispatches per tenant per UTC day. */
	scansPerDay: number;
	/** Max portfolio updates per tenant per minute. */
	portfolioPerMin: number;
	/** Max report reads per tenant per minute. */
	reportsPerMin: number;
}

/**
 * Tier → quota table. `default` applies when no override is present in the
 * tenant_keys.scope row. Add tier rows here when bv-web introduces new Tenant
 * pricing tiers.
 */
export const PER_TENANT_QUOTAS: Record<string, PerTenantQuota> = {
	default: { scansPerDay: 100_000, portfolioPerMin: 30, reportsPerMin: 60 },
	enterprise: { scansPerDay: 2_500_000, portfolioPerMin: 120, reportsPerMin: 300 },
};

export type RateLimitBucket = 'scans:day' | 'portfolio:min' | 'reports:min';

/** TTLs picked to outlive the bucket window so a stale key never undercounts. */
const TTL_BY_BUCKET: Record<RateLimitBucket, number> = {
	'scans:day': 90_000, // 25h, covers the 24h window with slack for clock skew.
	'portfolio:min': 90, // 1.5 minutes — KV's minimum is 60s.
	'reports:min': 90,
};

const KEY_PREFIX = 'tenant-rl:';

/** UTC date `YYYY-MM-DD`. */
function dailyWindowKey(now: Date): string {
	const y = now.getUTCFullYear();
	const m = String(now.getUTCMonth() + 1).padStart(2, '0');
	const d = String(now.getUTCDate()).padStart(2, '0');
	return `${y}-${m}-${d}`;
}

/** UTC `YYYY-MM-DDTHH:MM`. */
function minuteWindowKey(now: Date): string {
	const day = dailyWindowKey(now);
	const h = String(now.getUTCHours()).padStart(2, '0');
	const min = String(now.getUTCMinutes()).padStart(2, '0');
	return `${day}T${h}:${min}`;
}

function windowKey(bucket: RateLimitBucket, now: Date): string {
	return bucket === 'scans:day' ? dailyWindowKey(now) : minuteWindowKey(now);
}

/** When does the current window expire (epoch ms)? */
function resetAt(bucket: RateLimitBucket, now: Date): number {
	if (bucket === 'scans:day') {
		const next = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1, 0, 0, 0, 0);
		return next;
	}
	// minute bucket — round up to next minute boundary.
	const next = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), now.getUTCHours(), now.getUTCMinutes() + 1, 0, 0);
	return next;
}

function quotaFor(bucket: RateLimitBucket, tier: keyof typeof PER_TENANT_QUOTAS): number {
	const q = PER_TENANT_QUOTAS[tier] ?? PER_TENANT_QUOTAS.default;
	switch (bucket) {
		case 'scans:day':
			return q.scansPerDay;
		case 'portfolio:min':
			return q.portfolioPerMin;
		case 'reports:min':
			return q.reportsPerMin;
	}
}

type RateVerdict = { allowed: boolean; remaining: number; resetAt: number; unavailable?: boolean };

/** Everything one bucket check needs once the window, key and quota are resolved. */
interface BucketCall {
	kv: KVNamespace | undefined;
	key: string;
	bucket: RateLimitBucket;
	amount: number;
	quota: number;
	reset: number;
}

/** A reservation is a whole number of units, at least one. */
function isReservableAmount(amount: number): boolean {
	return Number.isSafeInteger(amount) && amount >= 1;
}

function unavailableVerdict(reset: number): RateVerdict {
	return { allowed: false, remaining: 0, resetAt: reset, unavailable: true };
}

/** Fail-soft verdict: let the request through when the best-effort counter cannot be read. */
function softAllowVerdict(call: BucketCall): RateVerdict {
	return { allowed: true, remaining: call.quota, resetAt: call.reset };
}

/** Current KV count (0 when absent or unparsable), or `undefined` when the KV read itself failed. */
async function readKvCount(kv: KVNamespace, key: string): Promise<number | undefined> {
	try {
		const raw = await kv.get(key);
		const parsed = raw === null ? Number.NaN : Number.parseInt(raw, 10);
		return Number.isFinite(parsed) && parsed >= 0 ? parsed : 0;
	} catch {
		return undefined;
	}
}

/** Seed value for a coordinator reservation: the KV mirror when readable, else 0 (the coordinator stays authoritative). */
async function seedCount(kv: KVNamespace | undefined, key: string): Promise<number> {
	if (!kv) return 0;
	return (await readKvCount(kv, key)) ?? 0;
}

/** Best-effort write: the verdict was already decided, so a failed put must not fail the request. */
async function putCountBestEffort(kv: KVNamespace, key: string, count: number, bucket: RateLimitBucket): Promise<void> {
	try {
		await kv.put(key, String(count), { expirationTtl: TTL_BY_BUCKET[bucket] });
	} catch {
		// Non-authoritative / best-effort only.
	}
}

/**
 * Scan dispatches: commit the whole weighted reservation atomically in the coordinator before any work.
 * A configured strong-state boundary must fail closed, otherwise a DO outage would silently turn into
 * unlimited scan dispatches.
 */
async function reserveScanBudget(
	call: BucketCall,
	coordinationKey: string,
	quotaCoordinator: DurableObjectNamespace<QuotaCoordinator>,
): Promise<RateVerdict> {
	const current = await seedCount(call.kv, call.key);
	try {
		const reservation = await reserveBudgetWithCoordinator(coordinationKey, call.amount, call.quota, call.reset, quotaCoordinator, current);
		if (!reservation) return unavailableVerdict(call.reset);
		if (call.kv) await putCountBestEffort(call.kv, call.key, reservation.used, call.bucket);
		return { allowed: reservation.allowed, remaining: reservation.remaining, resetAt: call.reset };
	} catch {
		return unavailableVerdict(call.reset);
	}
}

/** Low-cost buckets: KV `get -> check -> put`, racey by design and fail-soft on any KV error. */
async function recordInKv(call: BucketCall): Promise<RateVerdict> {
	if (!call.kv) return softAllowVerdict(call);
	const current = await readKvCount(call.kv, call.key);
	if (current === undefined) return softAllowVerdict(call);
	if (call.amount > call.quota - current) {
		// Over quota — do not spend a write op on the increment, but do not fail.
		return { allowed: false, remaining: 0, resetAt: call.reset };
	}
	const next = current + call.amount;
	await putCountBestEffort(call.kv, call.key, next, call.bucket);
	return { allowed: true, remaining: Math.max(0, call.quota - next), resetAt: call.reset };
}

/**
 * Reserve `amount` units and return the post-reservation verdict. Scan units
 * use strong state when supplied; the lower-cost KV buckets are best-effort.
 *
 * Caller must:
 *   - return 429 with `Retry-After: <seconds-to-resetAt>` when `allowed:false`
 *   - emit an audit event with outcome `'denied'` on the rejection path.
 */
export async function checkAndRecord(
	kv: KVNamespace | undefined,
	subTenantId: string,
	bucket: RateLimitBucket,
	tier: keyof typeof PER_TENANT_QUOTAS,
	amount = 1,
	quotaCoordinator?: DurableObjectNamespace<QuotaCoordinator>,
): Promise<RateVerdict> {
	const now = new Date();
	const reset = resetAt(bucket, now);
	const quota = quotaFor(bucket, tier);
	const key = `${KEY_PREFIX}${subTenantId}:${bucket}:${windowKey(bucket, now)}`;
	if (!isReservableAmount(amount)) return unavailableVerdict(reset);

	const call: BucketCall = { kv, key, bucket, amount, quota, reset };
	const strongState = bucket === 'scans:day' ? quotaCoordinator : undefined;
	return strongState ? reserveScanBudget(call, `tenant-scan:${subTenantId}:${windowKey(bucket, now)}`, strongState) : recordInKv(call);
}
