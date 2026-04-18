// SPDX-License-Identifier: BUSL-1.1

/**
 * Rate limiter for the DNS Security MCP Server.
 * Enforces per-IP limits: 50 requests/minute, 300 requests/hour.
 * Also enforces a global daily cap across all IPs as a cost ceiling.
 *
 * Uses Cloudflare KV for distributed rate limiting when available,
 * with in-memory fallback when KV is not configured.
 *
 * KV strategy: fixed-window counters with expirationTtl for automatic cleanup.
 * Key format: rl:min:{ip}:{windowId} (minute), rl:hr:{ip}:{windowId} (hour)
 *
 * Compatible with Cloudflare Workers runtime (no Node.js APIs).
 */

import {
	checkScopedRateLimitInMemory,
	checkToolDailyRateLimitInMemory,
	pruneTimestamps,
	resetAllRateLimits,
	resetRateLimit,
	type RateLimitScope,
} from './rate-limiter-memory';
import {
	checkGlobalDailyLimitWithCoordinator,
	checkScopedRateLimitWithCoordinator,
	checkToolDailyRateLimitWithCoordinator,
} from './quota-coordinator';
import { CircuitBreaker, CircuitBreakerOpen } from './circuit-breaker';
import { logError } from './log';
import { IP_LOCK_TTL_MS, IP_LOCK_RETRY_MS } from './config';

export interface RateLimitResult {
	allowed: boolean;
	retryAfterMs?: number;
	minuteRemaining: number;
	hourRemaining: number;
}

export interface ToolDailyRateLimitResult {
	allowed: boolean;
	retryAfterMs?: number;
	remaining: number;
	limit: number;
}

export interface GlobalRateLimitResult {
	allowed: boolean;
	retryAfterMs?: number;
	remaining: number;
	limit: number;
}

const MINUTE_LIMIT = 50;
const HOUR_LIMIT = 300;
const CONTROL_PLANE_MINUTE_LIMIT = 60;
const CONTROL_PLANE_HOUR_LIMIT = 600;
const MINUTE_MS = 60_000;
const HOUR_MS = 3_600_000;
const DAY_MS = 86_400_000;

// Best-effort per-IP serialization for KV updates inside a single isolate.
// This does not provide cross-isolate atomicity, but it prevents local races.
// Capped at 5000 entries — excess IPs skip serialization (acceptable for best-effort).
const KV_IP_LOCK_TAILS = new Map<string, Promise<void>>();
const KV_IP_LOCK_MAX = 5000;

/** Circuit breaker for QuotaCoordinator DO — avoids hammering a failing DO. */
const quotaCoordinatorBreaker = new CircuitBreaker({
	name: 'QuotaCoordinator',
	failureThreshold: 3,
	cooldownMs: 60_000,
});

/** @internal Reset the DO circuit breaker (test use only). */
export function resetQuotaCoordinatorBreaker(): void {
	quotaCoordinatorBreaker.reset();
}

function checkRateLimitInMemory(ip: string): RateLimitResult {
	return checkScopedRateLimitInMemory(ip, 'tools', MINUTE_LIMIT, HOUR_LIMIT);
}

function checkControlPlaneRateLimitInMemory(ip: string): RateLimitResult {
	return checkScopedRateLimitInMemory(ip, 'control', CONTROL_PLANE_MINUTE_LIMIT, CONTROL_PLANE_HOUR_LIMIT);
}

/** Parse a KV counter value, returning 0 for NaN/corrupt values. */
function parseKvCounter(val: string | null): number {
	if (!val) return 0;
	const n = parseInt(val, 10);
	return Number.isFinite(n) && n >= 0 ? n : 0;
}

// ---------------------------------------------------------------------------
// KV-backed rate limiting (fixed-window counters)
// ---------------------------------------------------------------------------

async function checkScopedRateLimitKV(
	ip: string,
	scope: RateLimitScope,
	minuteLimit: number,
	hourLimit: number,
	kv: KVNamespace,
): Promise<RateLimitResult> {
	return withIpKvLock(ip, async () => {
	const now = Date.now();
	const minuteWindow = Math.floor(now / MINUTE_MS);
	const hourWindow = Math.floor(now / HOUR_MS);

	const minuteKey = scope === 'tools' ? `rl:min:${ip}:${minuteWindow}` : `rl:ctl:min:${ip}:${minuteWindow}`;
	const hourKey = scope === 'tools' ? `rl:hr:${ip}:${hourWindow}` : `rl:ctl:hr:${ip}:${hourWindow}`;

	// Read both counters in parallel
	const [minuteVal, hourVal] = await Promise.all([kv.get(minuteKey), kv.get(hourKey)]);

	const minuteCount = parseKvCounter(minuteVal);
	const hourCount = parseKvCounter(hourVal);

	// Check minute limit
	if (minuteCount >= minuteLimit) {
		const windowEnd = (minuteWindow + 1) * MINUTE_MS;
		return {
			allowed: false,
			retryAfterMs: Math.max(windowEnd - now, 0),
			minuteRemaining: 0,
			hourRemaining: Math.max(hourLimit - hourCount, 0),
		};
	}

	// Check hour limit
	if (hourCount >= hourLimit) {
		const windowEnd = (hourWindow + 1) * HOUR_MS;
		return {
			allowed: false,
			retryAfterMs: Math.max(windowEnd - now, 0),
			minuteRemaining: Math.max(minuteLimit - minuteCount, 0),
			hourRemaining: 0,
		};
	}

	// Allowed — increment both counters (write in parallel)
	// Use remaining window time as TTL so keys expire when their window ends
	const newMinute = minuteCount + 1;
	const newHour = hourCount + 1;
	const minuteTtl = Math.max(1, Math.ceil(((minuteWindow + 1) * MINUTE_MS - now) / 1000));
	const hourTtl = Math.max(1, Math.ceil(((hourWindow + 1) * HOUR_MS - now) / 1000));
	await Promise.all([
		kv.put(minuteKey, String(newMinute), { expirationTtl: minuteTtl }),
		kv.put(hourKey, String(newHour), { expirationTtl: hourTtl }),
	]);

	return {
		allowed: true,
		minuteRemaining: minuteLimit - newMinute,
		hourRemaining: hourLimit - newHour,
	};
	});
}

async function checkRateLimitKV(ip: string, kv: KVNamespace): Promise<RateLimitResult> {
	return checkScopedRateLimitKVWithAdvisory(ip, 'tools', MINUTE_LIMIT, HOUR_LIMIT, kv);
}

async function checkControlPlaneRateLimitKV(ip: string, kv: KVNamespace): Promise<RateLimitResult> {
	return checkScopedRateLimitKV(ip, 'control', CONTROL_PLANE_MINUTE_LIMIT, CONTROL_PLANE_HOUR_LIMIT, kv);
}

export async function withIpKvLock<T>(ip: string, work: () => Promise<T>): Promise<T> {
	// Skip serialization if map is at capacity — best-effort fairness
	if (KV_IP_LOCK_TAILS.size >= KV_IP_LOCK_MAX && !KV_IP_LOCK_TAILS.has(ip)) {
		return work();
	}
	const prevTail = KV_IP_LOCK_TAILS.get(ip) ?? Promise.resolve();
	let release: (() => void) | undefined;
	const current = new Promise<void>((resolve) => {
		release = resolve;
	});
	const tail = prevTail.then(() => current);
	KV_IP_LOCK_TAILS.set(ip, tail);

	await prevTail;
	try {
		return await work();
	} finally {
		release?.();
		if (KV_IP_LOCK_TAILS.get(ip) === tail) {
			KV_IP_LOCK_TAILS.delete(ip);
		}
	}
}

/**
 * Best-effort cross-isolate per-IP advisory lock. Activates only when the
 * in-memory KV_IP_LOCK_TAILS already has a tail for this IP (indicating
 * contention on this isolate). On uncontended paths, skips the KV read
 * entirely — zero added latency.
 *
 * KV outage → falls through to `work()` without the advisory layer.
 */
async function withIpKvAdvisoryLock<T>(ip: string, kv: KVNamespace, work: () => Promise<T>): Promise<T> {
	const contended = KV_IP_LOCK_TAILS.has(ip);
	if (!contended) return work();
	const advisoryKey = `lk:ip:${ip}`;
	try {
		const held = await kv.get(advisoryKey);
		if (held) await new Promise((r) => setTimeout(r, IP_LOCK_RETRY_MS));
		await kv.put(advisoryKey, String(Date.now()), { expirationTtl: Math.max(1, Math.ceil(IP_LOCK_TTL_MS / 1000)) });
	} catch {
		// KV outage → best-effort fallback to in-memory lock only.
	}
	try {
		return await work();
	} finally {
		try { await kv.delete(advisoryKey); } catch { /* best-effort */ }
	}
}

export async function checkScopedRateLimitKVWithAdvisory(
	ip: string,
	scope: RateLimitScope,
	minuteLimit: number,
	hourLimit: number,
	kv: KVNamespace,
): Promise<RateLimitResult> {
	try {
		return await withIpKvAdvisoryLock(ip, kv, () => checkScopedRateLimitKV(ip, scope, minuteLimit, hourLimit, kv));
	} catch {
		// KV outage — log warning and fall back to in-memory
		logError('[rate-limiter] KV error, falling back to in-memory');
		return checkScopedRateLimitInMemory(ip, scope, minuteLimit, hourLimit);
	}
}

async function checkToolDailyRateLimitKV(
	principalId: string,
	toolName: string,
	limit: number,
	kv: KVNamespace,
): Promise<ToolDailyRateLimitResult> {
	return withIpKvLock(`tool:${principalId}:${toolName}`, async () => {
		const now = Date.now();
		const dayWindow = Math.floor(now / DAY_MS);
		const toolKey = toolName.trim().toLowerCase();
		const key = `rl:day:tool:${toolKey}:${principalId}:${dayWindow}`;

		const currentVal = await kv.get(key);
		const currentCount = parseKvCounter(currentVal);

		if (currentCount >= limit) {
			const windowEnd = (dayWindow + 1) * DAY_MS;
			return {
				allowed: false,
				retryAfterMs: Math.max(windowEnd - now, 0),
				remaining: 0,
				limit,
			};
		}

		const nextCount = currentCount + 1;
		await kv.put(key, String(nextCount), { expirationTtl: 86_400 });

		return {
			allowed: true,
			remaining: Math.max(limit - nextCount, 0),
			limit,
		};
	});
}

// ---------------------------------------------------------------------------
// Global daily cap (cost ceiling across all IPs)
// ---------------------------------------------------------------------------

let globalDayWindow = 0;
let globalDayCount = 0;

function checkGlobalDailyLimitInMemory(limit: number): GlobalRateLimitResult {
	const now = Date.now();
	const currentWindow = Math.floor(now / DAY_MS);
	if (currentWindow !== globalDayWindow) {
		globalDayWindow = currentWindow;
		globalDayCount = 0;
	}
	if (globalDayCount >= limit) {
		const windowEnd = (currentWindow + 1) * DAY_MS;
		return { allowed: false, retryAfterMs: Math.max(windowEnd - now, 0), remaining: 0, limit };
	}
	globalDayCount++;
	return { allowed: true, remaining: Math.max(limit - globalDayCount, 0), limit };
}

async function checkGlobalDailyLimitKV(limit: number, kv: KVNamespace): Promise<GlobalRateLimitResult> {
	return withIpKvLock('global:daily', async () => {
		const now = Date.now();
		const currentWindow = Math.floor(now / DAY_MS);
		const key = `rl:global:day:${currentWindow}`;

		const currentVal = await kv.get(key);
		const currentCount = parseKvCounter(currentVal);

		if (currentCount >= limit) {
			const windowEnd = (currentWindow + 1) * DAY_MS;
			return { allowed: false, retryAfterMs: Math.max(windowEnd - now, 0), remaining: 0, limit };
		}

		const nextCount = currentCount + 1;
		await kv.put(key, String(nextCount), { expirationTtl: 86_400 });

		return { allowed: true, remaining: Math.max(limit - nextCount, 0), limit };
	});
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Check if a request from the given IP is allowed under rate limits.
 * If allowed, the request is counted. If not, returns retry-after info.
 *
 * @param ip - Client IP address
 * @param kv - Optional KV namespace for distributed rate limiting.
 *             Falls back to in-memory when not provided or on KV errors.
 */
export async function checkRateLimit(ip: string, kv?: KVNamespace, quotaCoordinator?: DurableObjectNamespace): Promise<RateLimitResult> {
	if (quotaCoordinator) {
		try {
			const coordinated = await quotaCoordinatorBreaker.call(
				() => checkScopedRateLimitWithCoordinator(ip, 'tools', MINUTE_LIMIT, HOUR_LIMIT, quotaCoordinator),
			);
			if (coordinated) return coordinated;
		} catch (err) {
			if (!(err instanceof CircuitBreakerOpen)) {
				logError('[rate-limiter] quota coordinator error, falling back to KV/in-memory');
			}
		}
	}
       if (kv) {
	       try {
		       return await checkRateLimitKV(ip, kv);
	       } catch {
		       // KV error — log warning and fall back to in-memory
		       logError('[rate-limiter] KV error, falling back to in-memory');
	       }
       }
       return checkRateLimitInMemory(ip);
}

/**
 * Check if a request from the given IP is allowed under lower-cost control-plane limits.
 * Uses KV when available, with in-memory fallback on failure.
 */
export async function checkControlPlaneRateLimit(
	ip: string,
	kv?: KVNamespace,
	quotaCoordinator?: DurableObjectNamespace,
): Promise<RateLimitResult> {
	if (quotaCoordinator) {
		try {
			const coordinated = await quotaCoordinatorBreaker.call(
				() => checkScopedRateLimitWithCoordinator(ip, 'control', CONTROL_PLANE_MINUTE_LIMIT, CONTROL_PLANE_HOUR_LIMIT, quotaCoordinator),
			);
			if (coordinated) return coordinated;
		} catch (err) {
			if (!(err instanceof CircuitBreakerOpen)) {
				logError('[rate-limiter] quota coordinator control-plane error, falling back to KV/in-memory');
			}
		}
	}
	if (kv) {
		try {
			return await checkControlPlaneRateLimitKV(ip, kv);
		} catch {
			logError('[rate-limiter] KV control-plane error, falling back to in-memory');
		}
	}
	return checkControlPlaneRateLimitInMemory(ip);
}

/**
 * Check a per-principal daily quota for a specific tool.
 * Uses KV when available, with in-memory fallback on failure.
 */
export async function checkToolDailyRateLimit(
	principalId: string,
	toolName: string,
	limit: number,
	kv?: KVNamespace,
	quotaCoordinator?: DurableObjectNamespace,
): Promise<ToolDailyRateLimitResult> {
	if (quotaCoordinator) {
		try {
			const coordinated = await quotaCoordinatorBreaker.call(
				() => checkToolDailyRateLimitWithCoordinator(principalId, toolName, limit, quotaCoordinator),
			);
			if (coordinated) return coordinated;
		} catch (err) {
			if (!(err instanceof CircuitBreakerOpen)) {
				logError('[rate-limiter] quota coordinator tool quota error, falling back to KV/in-memory');
			}
		}
	}
	if (kv) {
		try {
			return await checkToolDailyRateLimitKV(principalId, toolName, limit, kv);
		} catch {
			logError('[rate-limiter] KV tool quota error, falling back to in-memory');
		}
	}
	return checkToolDailyRateLimitInMemory(principalId, toolName, limit);
}

/**
 * Check if the global daily tool call budget has been exhausted.
 * Uses KV when available, with in-memory fallback on failure.
 */
export async function checkGlobalDailyLimit(
	limit: number,
	kv?: KVNamespace,
	quotaCoordinator?: DurableObjectNamespace,
): Promise<GlobalRateLimitResult> {
	if (quotaCoordinator) {
		try {
			const coordinated = await quotaCoordinatorBreaker.call(
				() => checkGlobalDailyLimitWithCoordinator(limit, quotaCoordinator),
			);
			if (coordinated) return coordinated;
		} catch (err) {
			if (!(err instanceof CircuitBreakerOpen)) {
				logError('[rate-limiter] quota coordinator global cap error, falling back to KV/in-memory');
			}
		}
	}
	if (kv) {
		try {
			return await checkGlobalDailyLimitKV(limit, kv);
		} catch {
			logError('[rate-limiter] KV global cap error, falling back to in-memory');
		}
	}
	return checkGlobalDailyLimitInMemory(limit);
}

/**
 * Reset rate limit state for an IP (useful for testing).
 * @internal Exported for test use only.
 */
export { pruneTimestamps, resetRateLimit, resetAllRateLimits };

/** @internal Reset global daily counter (test use only). */
export function resetGlobalDailyLimit(): void {
	globalDayWindow = 0;
	globalDayCount = 0;
}

// ---------------------------------------------------------------------------
// Per-tier concurrency limits (best-effort per-isolate fairness)
// ---------------------------------------------------------------------------

/**
 * In-memory map tracking active concurrent tool executions per principal.
 * Keyed by principalId (API key hash for authenticated, IP for unauthenticated).
 */
const activeConcurrency = new Map<string, number>();

export interface ConcurrencyLimitResult {
	allowed: boolean;
	retryAfterMs?: number;
	active: number;
	limit: number;
}

/**
 * Attempt to acquire a concurrency slot for the given principal/tier.
 * Returns allowed=true and increments the active count, or
 * allowed=false with retryAfterMs if the limit is reached.
 */
export function acquireConcurrencySlot(principalId: string, limit: number): ConcurrencyLimitResult {
	const current = activeConcurrency.get(principalId) ?? 0;
	if (current >= limit) {
		return { allowed: false, retryAfterMs: 1000, active: current, limit };
	}
	activeConcurrency.set(principalId, current + 1);
	return { allowed: true, active: current + 1, limit };
}

/**
 * Release a concurrency slot for the given principal.
 * Must be called in a `finally` block after tool execution completes.
 */
export function releaseConcurrencySlot(principalId: string): void {
	const current = activeConcurrency.get(principalId) ?? 0;
	if (current <= 1) {
		activeConcurrency.delete(principalId);
	} else {
		activeConcurrency.set(principalId, current - 1);
	}
}

/** @internal Reset all concurrency tracking state (test use only). */
export function resetConcurrencyLimits(): void {
	activeConcurrency.clear();
}
