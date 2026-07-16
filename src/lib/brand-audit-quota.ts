// SPDX-License-Identifier: BUSL-1.1

/**
 * Brand-audit per-tier monthly quotas.
 *
 * Independent of FREE_TOOL_DAILY_LIMITS (which is daily, per-IP). Brand audits
 * are metered separately because each target is a multi-minute deep-discovery
 * operation, not a single DNS check — fairness lives at the tier-month layer,
 * not the IP-day layer.
 *
 * Counter storage: `RATE_LIMIT` KV namespace with `brand_audit:<principalId>:<month>`
 * key prefix; window aligned to UTC calendar month.
 */

import type { McpApiKeyTier } from './config';

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
	kv: BrandAuditQuotaKv;
	principalId: string;
	tier: McpApiKeyTier;
	count: number;
	/** Override for tests; defaults to `Date.now()`. */
	now?: number;
}

/**
 * Enforce + consume monthly brand-audit quota.
 *
 * Best-effort: KV errors fail-open (allowed=true, remaining=limit). Aligns with
 * the project's `lib/rate-limiter.ts` cache-availability stance — the rate limit
 * is a courtesy guard, not a security boundary.
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

	let current = 0;
	try {
		const raw = await kv.get(key);
		current = raw ? Number.parseInt(raw, 10) || 0 : 0;
	} catch {
		return { allowed: true, remaining: limit, limit };
	}

	if (current + count > limit) {
		return { allowed: false, remaining: Math.max(0, limit - current), limit, retryAfterMs: nextMonthStart(now) - now };
	}

	const next = current + count;
	try {
		// Clamped to KV's 60s minimum expirationTtl — in the final minute of a
		// month the remaining-window value drops below 60, which KV rejects.
		// The key is month-windowed, so lingering ≤59s into the next month is inert.
		const ttlSeconds = Math.max(60, Math.ceil((nextMonthStart(now) - now) / 1000));
		await kv.put(key, String(next), { expirationTtl: ttlSeconds });
	} catch {
		// KV write failure ≠ refusal; counter will simply be less precise this window.
	}

	return { allowed: true, remaining: limit - next, limit };
}
