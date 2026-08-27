// SPDX-License-Identifier: BUSL-1.1

/**
 * Brand-audit per-tier monthly quotas.
 *
 * Independent of FREE_TOOL_DAILY_LIMITS (which is daily, per-IP). Brand audits
 * are metered separately because each target is a multi-minute deep-discovery
 * operation, not a single DNS check — fairness lives at the tier-month layer,
 * not the IP-day layer.
 *
 * Authoritative counter storage: QuotaCoordinator Durable Object, routed by
 * principal + UTC month. RATE_LIMIT KV receives only a best-effort mirror for
 * operator visibility; it is never used to authorize work.
 */

import type { McpApiKeyTier } from './config';
import { reserveBudgetWithCoordinator, type QuotaCoordinator } from './quota-coordinator';

/** Monthly per-tier brand-audit target budgets. */
export const BRAND_AUDIT_QUOTAS: Record<McpApiKeyTier, number> = {
	free: 0,
	agent: 0,
	developer: 50,
	partner: 200,
	enterprise: 500,
	owner: Number.POSITIVE_INFINITY,
};

/** Result of a quota check. `allowed=false` MUST short-circuit the audit and surface an error. */
export interface BrandAuditQuotaCheck {
	allowed: boolean;
	/** Targets remaining in the current monthly window (after this call would consume `count`). */
	remaining: number;
	/** Hard ceiling for the tier. */
	limit: number;
	/** Milliseconds until the window resets. Only populated when `allowed=false`. */
	retryAfterMs?: number;
}

/** Compute the UTC month-start timestamp (ms) for the window the given moment belongs to. */
function monthStart(nowMs: number): number {
	const d = new Date(nowMs);
	return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), 1);
}

/** Compute the next UTC month-start timestamp (ms) — used for `retryAfterMs`. */
function nextMonthStart(nowMs: number): number {
	const d = new Date(nowMs);
	return Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 1, 1);
}

/** Minimal KV interface — typed locally to avoid a global Workers env dep in unit tests. */
export interface BrandAuditQuotaKv {
	get(key: string): Promise<string | null>;
	put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>;
}

export interface EnforceBrandAuditQuotaArgs {
	kv?: BrandAuditQuotaKv;
	quotaCoordinator?: DurableObjectNamespace<QuotaCoordinator>;
	principalId: string;
	tier: McpApiKeyTier;
	count: number;
	/** Override for tests; defaults to `Date.now()`. */
	now?: number;
}

/**
 * Enforce + consume monthly brand-audit quota.
 *
 * This is a paid-usage/cost boundary and therefore fails closed when strong
 * state is unavailable. KV is a non-authoritative observability mirror only.
 */
export async function enforceBrandAuditQuota(args: EnforceBrandAuditQuotaArgs): Promise<BrandAuditQuotaCheck> {
	const { kv, principalId, tier, count } = args;
	const limit = BRAND_AUDIT_QUOTAS[tier] ?? 0;
	if (!Number.isFinite(limit)) {
		return { allowed: true, remaining: Number.POSITIVE_INFINITY, limit };
	}
	if (limit === 0) {
		const now = args.now ?? Date.now();
		return { allowed: false, remaining: 0, limit: 0, retryAfterMs: nextMonthStart(now) - now };
	}

	const now = args.now ?? Date.now();
	const window = monthStart(now);
	const key = `brand_audit:${principalId}:${window}`;
	if (!Number.isSafeInteger(count) || count < 1) {
		return { allowed: false, remaining: 0, limit };
	}

	if (!kv) return { allowed: false, remaining: 0, limit, retryAfterMs: 60_000 };
	let initialUsed: number;
	try {
		const raw = await kv.get(key);
		const parsed = raw === null ? 0 : Number.parseInt(raw, 10);
		if (!Number.isSafeInteger(parsed) || parsed < 0 || parsed > limit) {
			return { allowed: false, remaining: 0, limit, retryAfterMs: 60_000 };
		}
		initialUsed = parsed;
	} catch {
		return { allowed: false, remaining: 0, limit, retryAfterMs: 60_000 };
	}

	let reservation;
	try {
		reservation = await reserveBudgetWithCoordinator(key, count, limit, nextMonthStart(now), args.quotaCoordinator, initialUsed);
	} catch {
		return { allowed: false, remaining: 0, limit, retryAfterMs: 60_000 };
	}
	if (!reservation) {
		return { allowed: false, remaining: 0, limit, retryAfterMs: 60_000 };
	}
	if (!reservation.allowed) {
		return { allowed: false, remaining: reservation.remaining, limit, retryAfterMs: nextMonthStart(now) - now };
	}

	try {
		// Clamped to KV's 60s minimum expirationTtl — in the final minute of a
		// month the remaining-window value drops below 60, which KV rejects.
		// The key is month-windowed, so lingering ≤59s into the next month is inert.
		const ttlSeconds = Math.max(60, Math.ceil((nextMonthStart(now) - now) / 1000));
		await kv?.put(key, String(reservation.used), { expirationTtl: ttlSeconds });
	} catch {
		// Non-authoritative mirror only; the DO reservation has already committed.
	}

	return { allowed: true, remaining: reservation.remaining, limit };
}
