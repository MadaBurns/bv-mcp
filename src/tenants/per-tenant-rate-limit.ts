// SPDX-License-Identifier: BUSL-1.1

/**
 * Per-tenant rate limiter for `/internal/tenants/*`.
 *
 * Phase 6 hardening (tenant-Scalable-Architecture-Design.md §6): the public per-IP
 * limiter in `src/lib/rate-limiter.ts` doesn't apply to the internal Tenant
 * surface (service-binding traffic carries no `cf-connecting-ip`). Without a
 * tenant-scoped cap, one runaway customer could exhaust the worker for
 * everyone else.
 *
 * Implementation
 * --------------
 * - Buckets are keyed by `(sub_tenant_id, bucket, window)`. `bucket` selects
 *   one of the three workloads (`scans:day` / `portfolio:min` / `reports:min`);
 *   `window` is the fixed-width time slice (UTC date or `YYYY-MM-DDTHH:MM`).
 * - Counter is stored in `RATE_LIMIT` KV. Each call does `get → +1 → put`.
 *   That is racey under concurrent writes, but the threat model is "stop a
 *   tenant from burning the worker for hours", not pixel-perfect counting:
 *   the over-shoot at peak burst is at most a few requests per isolate.
 * - Fail-soft: any KV error short-circuits to `allowed:true`. The counter is
 *   purely a defense in depth — losing it must not cause a request outage.
 *
 * Tier defaults are intentionally generous so the default deployment behaves
 * the same as before this limiter existed for legitimate traffic patterns
 * (redacted-tenant is hitting ~100 portfolio updates/day in benchmarks, ~6 reports
 * /min during dashboard refreshes, ~50k scans/day in steady state).
 */

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
 * Atomically (best-effort) increment the per-tenant counter and return the
 * post-increment verdict.
 *
 * Caller must:
 *   - return 429 with `Retry-After: <seconds-to-resetAt>` when `allowed:false`
 *   - emit an audit event with outcome `'denied'` on the rejection path.
 */
export async function checkAndRecord(
	kv: KVNamespace,
	subTenantId: string,
	bucket: RateLimitBucket,
	tier: keyof typeof PER_TENANT_QUOTAS,
): Promise<{ allowed: boolean; remaining: number; resetAt: number }> {
	const now = new Date();
	const reset = resetAt(bucket, now);
	const quota = quotaFor(bucket, tier);
	const key = `${KEY_PREFIX}${subTenantId}:${bucket}:${windowKey(bucket, now)}`;

	let current = 0;
	try {
		const raw = await kv.get(key);
		if (raw !== null) {
			const parsed = Number.parseInt(raw, 10);
			if (Number.isFinite(parsed) && parsed >= 0) current = parsed;
		}
	} catch {
		// KV unavailable — fail-soft: allow the request, return full quota so
		// the caller's `Retry-After` math still works.
		return { allowed: true, remaining: quota, resetAt: reset };
	}

	if (current >= quota) {
		// Over quota — do not spend a write op on the increment, but do not fail.
		return { allowed: false, remaining: 0, resetAt: reset };
	}

	const next = current + 1;
	try {
		await kv.put(key, String(next), { expirationTtl: TTL_BY_BUCKET[bucket] });
	} catch {
		// Best-effort: even if the put fails we already returned the verdict
		// based on the read, so let the request proceed.
	}

	return { allowed: true, remaining: Math.max(0, quota - next), resetAt: reset };
}
