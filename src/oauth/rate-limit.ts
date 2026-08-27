// SPDX-License-Identifier: BUSL-1.1

import {
	reserveBudgetWithCoordinator,
	type BudgetReservationResult,
	type QuotaCoordinator,
} from '../lib/quota-coordinator';

export interface OAuthRateLimitResult {
	exceeded: boolean;
	retryAfterSeconds: number;
	unavailable?: true;
}

interface OAuthRateLimitOptions {
	kv: KVNamespace;
	quotaCoordinator?: DurableObjectNamespace<QuotaCoordinator>;
	/** Stable endpoint label, e.g. `register:min`; the principal/window are appended. */
	coordinationScope: string;
	/** Existing KV key retained as an unbound fallback and strong-path mirror. */
	kvKey: string;
	principal: string;
	limit: number;
	windowSeconds: number;
	nowMs?: number;
}

interface StoredWindow {
	count: number;
	expiresAt: number;
}

function parseStoredWindow(raw: string | null, nowMs: number): StoredWindow | null {
	if (!raw) return null;
	try {
		const parsed = JSON.parse(raw) as { count?: unknown; expiresAt?: unknown };
		if (
			typeof parsed.expiresAt !== 'number' ||
			!Number.isSafeInteger(parsed.expiresAt) ||
			parsed.expiresAt <= nowMs ||
			typeof parsed.count !== 'number' ||
			!Number.isSafeInteger(parsed.count) ||
			parsed.count < 0
		) {
			return null;
		}
		return { count: parsed.count, expiresAt: parsed.expiresAt };
	} catch {
		return null;
	}
}

function retryAfterSeconds(expiresAt: number, nowMs: number): number {
	return Math.max(1, Math.ceil((expiresAt - nowMs) / 1000));
}

function isBudgetReservation(value: unknown, expectedLimit: number): value is BudgetReservationResult {
	if (!value || typeof value !== 'object') return false;
	const candidate = value as Partial<BudgetReservationResult>;
	return (
		typeof candidate.allowed === 'boolean' &&
		candidate.limit === expectedLimit &&
		Number.isSafeInteger(candidate.used) &&
		(candidate.used as number) >= 0 &&
		(candidate.used as number) <= expectedLimit &&
		Number.isSafeInteger(candidate.remaining) &&
		(candidate.remaining as number) >= 0 &&
		(candidate.remaining as number) <= expectedLimit &&
		(!candidate.allowed || (candidate.used as number) >= 1)
	);
}

/**
 * Consume one request from an OAuth endpoint window.
 *
 * Production uses a deterministic window key in the quota coordinator, making
 * concurrent requests linearizable. KV remains a best-effort mirror and the
 * bounded self-host fallback when no coordinator is provisioned. Once a
 * coordinator is configured, its failure never falls through to racy KV.
 */
export async function consumeOAuthRateLimit(options: OAuthRateLimitOptions): Promise<OAuthRateLimitResult> {
	const nowMs = options.nowMs ?? Date.now();
	const windowMs = options.windowSeconds * 1000;
	if (!Number.isSafeInteger(options.limit) || options.limit < 1 || !Number.isSafeInteger(windowMs) || windowMs < 1) {
		throw new RangeError('Invalid OAuth rate-limit configuration');
	}

	if (options.quotaCoordinator) {
		// Aligned windows ensure every colo derives the same coordinator key. Using
		// `now + window` would create different keys during a concurrent first burst.
		const windowStart = Math.floor(nowMs / windowMs) * windowMs;
		const expiresAt = windowStart + windowMs;
		let initialUsed = 0;
		try {
			initialUsed = parseStoredWindow(await options.kv.get(options.kvKey), nowMs)?.count ?? 0;
		} catch {
			// The coordinator is authoritative; an unavailable mirror cannot relax it
			// after the first reservation and must not turn into a request outage.
		}

		try {
			const reservation = await reserveBudgetWithCoordinator(
				`oauth-rate:${options.coordinationScope}:${options.principal}:${windowStart}`,
				1,
				options.limit,
				expiresAt,
				options.quotaCoordinator,
				Math.min(initialUsed, options.limit),
			);
			if (!isBudgetReservation(reservation, options.limit)) {
				return { exceeded: true, retryAfterSeconds: retryAfterSeconds(expiresAt, nowMs), unavailable: true };
			}
			try {
				await options.kv.put(options.kvKey, JSON.stringify({ count: reservation.used, expiresAt }), {
					expirationTtl: Math.max(60, retryAfterSeconds(expiresAt, nowMs)),
				});
			} catch {
				// Non-authoritative migration/visibility mirror only.
			}
			return {
				exceeded: !reservation.allowed,
				retryAfterSeconds: reservation.allowed ? 0 : retryAfterSeconds(expiresAt, nowMs),
			};
		} catch {
			return { exceeded: true, retryAfterSeconds: retryAfterSeconds(expiresAt, nowMs), unavailable: true };
		}
	}

	// Self-host compatibility path: preserve the existing first-request-pinned
	// fixed window without requiring a Durable Object namespace.
	const stored = parseStoredWindow(await options.kv.get(options.kvKey), nowMs);
	const count = stored?.count ?? 0;
	const expiresAt = stored?.expiresAt ?? nowMs + windowMs;
	if (count >= options.limit) {
		return { exceeded: true, retryAfterSeconds: retryAfterSeconds(expiresAt, nowMs) };
	}
	await options.kv.put(options.kvKey, JSON.stringify({ count: count + 1, expiresAt }), {
		expirationTtl: Math.max(60, retryAfterSeconds(expiresAt, nowMs)),
	});
	return { exceeded: false, retryAfterSeconds: 0 };
}
