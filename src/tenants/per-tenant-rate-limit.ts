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
): Promise<{ allowed: boolean; remaining: number; resetAt: number; unavailable?: boolean }> {
	const now = new Date();
	const reset = resetAt(bucket, now);
	const quota = quotaFor(bucket, tier);
	const key = `${KEY_PREFIX}${subTenantId}:${bucket}:${windowKey(bucket, now)}`;
	if (!Number.isSafeInteger(amount) || amount < 1) {
		return { allowed: false, remaining: 0, resetAt: reset, unavailable: true };
	}

	let current = 0;
	if (kv) {
		try {
			const raw = await kv.get(key);
			if (raw !== null) {
				const parsed = Number.parseInt(raw, 10);
				if (Number.isFinite(parsed) && parsed >= 0) current = parsed;
			}
		} catch {
			// The scan coordinator remains authoritative even when its KV mirror
			// cannot seed/mirror state. Other low-cost buckets preserve their
			// historical fail-soft behavior.
			if (bucket !== 'scans:day' || !quotaCoordinator) {
				return { allowed: true, remaining: quota, resetAt: reset };
			}
		}
	}

	if (bucket === 'scans:day' && quotaCoordinator) {
		try {
			const reservation = await reserveBudgetWithCoordinator(
				`tenant-scan:${subTenantId}:${windowKey(bucket, now)}`,
				amount,
				quota,
				reset,
				quotaCoordinator,
				current,
			);
			if (!reservation) {
				return { allowed: false, remaining: 0, resetAt: reset, unavailable: true };
			}
			if (kv) {
				try {
					await kv.put(key, String(reservation.used), { expirationTtl: TTL_BY_BUCKET[bucket] });
				} catch {
					// Non-authoritative mirror only; the atomic reservation committed.
				}
			}
			return { allowed: reservation.allowed, remaining: reservation.remaining, resetAt: reset };
		} catch {
			// A configured strong-state boundary must fail closed. Otherwise a DO
			// outage would silently turn into unlimited scan dispatches.
			return { allowed: false, remaining: 0, resetAt: reset, unavailable: true };
		}
	}

	if (!kv) {
		return { allowed: true, remaining: quota, resetAt: reset };
	}

	if (amount > quota - current) {
		// Over quota — do not spend a write op on the increment, but do not fail.
		return { allowed: false, remaining: 0, resetAt: reset };
	}

	const next = current + amount;
	try {
		await kv.put(key, String(next), { expirationTtl: TTL_BY_BUCKET[bucket] });
	} catch {
		// Best-effort: even if the put fails we already returned the verdict
		// based on the read, so let the request proceed.
	}

	return { allowed: true, remaining: Math.max(0, quota - next), resetAt: reset };
}
