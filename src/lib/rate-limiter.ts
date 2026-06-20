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
	checkIpDailyLimitInMemory,
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
import { IP_LOCK_TTL_MS, IP_LOCK_RETRY_MS, FREE_IP_DAILY_LIMIT } from './config';

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

/**
 * True when the QuotaCoordinator DO circuit breaker is currently OPEN — i.e. the
 * authoritative cross-isolate global counter is unreachable and every isolate is
 * running on the degraded fallback path.
 *
 * Reading `.state` also lazily advances OPEN → HALF_OPEN once the cooldown
 * elapses, so this returns `false` again as soon as a probe is allowed.
 */
function isQuotaCoordinatorBreakerOpen(): boolean {
	return quotaCoordinatorBreaker.state === 'OPEN';
}

/**
 * Narrow degradation-telemetry sink. Structurally satisfied by the analytics
 * client's `emitDegradationEvent`; declared locally so the rate limiter doesn't
 * import the analytics module (keeps the dependency graph acyclic and the limiter
 * cheap to unit-test). The call site in `mcp/execute.ts` passes
 * `options.analytics` directly.
 */
export interface GlobalCostCeilingDegradationSink {
	emitDegradationEvent(event: { degradationType: 'cost_ceiling_degraded'; component: string }): void;
}

/**
 * Conservative estimate of how many Worker isolates may be serving traffic
 * concurrently at peak. Used ONLY to shrink the per-isolate in-memory global
 * cost ceiling when both the coordinator DO AND shared KV are unavailable —
 * the last-resort path. Dividing the cap by this factor keeps the aggregate
 * cap across all isolates roughly bounded by `GLOBAL_DAILY_TOOL_LIMIT` instead
 * of ballooning to `limit × isolate-count` exactly when traffic is highest.
 *
 * Deliberately coarse: under-estimating leaves the aggregate cap a little high;
 * over-estimating throttles a touch early. Either is far safer than the
 * unbounded per-isolate behaviour it replaces. KV (shared, approximate) is
 * always preferred over this path when present.
 *
 * @internal Exported for tests asserting the scaled last-resort cap.
 */
export const GLOBAL_CEILING_ISOLATE_FANOUT_ESTIMATE = 50;

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

/**
 * Per-isolate in-memory global counter. This is the LAST-RESORT cost ceiling:
 * it only fires when neither the coordinator DO nor shared KV is reachable.
 *
 * `effectiveLimit` lets the breaker-open path pass a DOWN-SCALED cap (the
 * configured limit divided by the estimated isolate fan-out) so the aggregate
 * across all isolates stays roughly bounded instead of `limit × isolate-count`.
 * The reported `limit` in the result intentionally echoes `effectiveLimit` —
 * it reflects the budget THIS isolate is actually enforcing.
 */
function checkGlobalDailyLimitInMemory(effectiveLimit: number): GlobalRateLimitResult {
	const now = Date.now();
	const currentWindow = Math.floor(now / DAY_MS);
	if (currentWindow !== globalDayWindow) {
		globalDayWindow = currentWindow;
		globalDayCount = 0;
	}
	if (globalDayCount >= effectiveLimit) {
		const windowEnd = (currentWindow + 1) * DAY_MS;
		return { allowed: false, retryAfterMs: Math.max(windowEnd - now, 0), remaining: 0, limit: effectiveLimit };
	}
	globalDayCount++;
	return { allowed: true, remaining: Math.max(effectiveLimit - globalDayCount, 0), limit: effectiveLimit };
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
// Per-IP daily cap (FIND-02)
// ---------------------------------------------------------------------------

async function checkIpDailyLimitKV(ip: string, limit: number, kv: KVNamespace): Promise<GlobalRateLimitResult> {
	return withIpKvLock(`ipday:${ip}`, async () => {
		const now = Date.now();
		const dayWindow = Math.floor(now / DAY_MS);
		const key = `rl:ipday:${ip}:${dayWindow}`;
		const ttl = Math.ceil(DAY_MS / 1000);

		const currentVal = await kv.get(key);
		const currentCount = parseKvCounter(currentVal);

		if (currentCount >= limit) {
			const windowEnd = (dayWindow + 1) * DAY_MS;
			return { allowed: false, retryAfterMs: Math.max(windowEnd - now, 0), remaining: 0, limit };
		}

		const nextCount = currentCount + 1;
		await kv.put(key, String(nextCount), { expirationTtl: ttl });

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
	// Unlimited tiers (owner) pass Infinity. JSON.stringify(Infinity) === "null",
	// which the coordinator validator rejects with HTTP 400 and every KV write
	// would be wasted bookkeeping for a counter that can never trip. Short-circuit.
	// NOTE: don't extend this to limit <= 0 — TIER_TOOL_DAILY_LIMITS encodes
	// "tier blocked from tool" as 0 (e.g. agent + brand_audit_*), which must
	// flow through the normal counter so the first call denies.
	if (!Number.isFinite(limit)) {
		return { allowed: true, remaining: limit, limit };
	}
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
 * Check if the global daily tool-call budget (the COST ceiling) has been exhausted.
 *
 * Enforcement is deliberately tiered to keep this a *globally* shared guardrail:
 *
 *   1. QuotaCoordinator DO  — authoritative, exact, cross-isolate.
 *   2. Shared KV            — globally shared but eventually-consistent
 *                             (`rl:global:day:*`). Approximate, can undercount
 *                             under write contention, but bounded.
 *   3. Per-isolate memory   — LAST RESORT only. Per-isolate, so the aggregate
 *                             cap would otherwise balloon to `limit × isolate-
 *                             count`. We DOWN-SCALE the cap by the estimated
 *                             isolate fan-out to keep the aggregate bounded.
 *
 * When the DO circuit breaker is OPEN the authoritative tier is gone and we are
 * on tier 2 or 3. A globally-shared-and-approximate counter (KV) beats a
 * per-isolate-and-unbounded one (memory) for a coarse cost ceiling, so KV is
 * always preferred while the breaker is open. We emit a `degradation`
 * event with degradationType `cost_ceiling_degraded` (component
 * `global_cost_ceiling`) so operators can see the cost guardrail is running
 * degraded. It is a DISTINCT degradationType from the session-store `kv_fallback`
 * signal precisely so `queryBindingDegradation` (which excludes `kv_fallback`)
 * does NOT swallow it and it DOES reach the 15-min cron alert. That alert keys on
 * degradationType (blob1), not component (blob2), so a distinct component alone
 * would not have sufficed.
 *
 * @param limit            Configured global daily cap (`GLOBAL_DAILY_TOOL_LIMIT`).
 * @param kv               Shared KV namespace (tier 2).
 * @param quotaCoordinator QuotaCoordinator DO (tier 1).
 * @param degradationSink  Optional telemetry sink (the analytics client) — emits
 *                         when the breaker forces a degraded fallback path.
 */
export async function checkGlobalDailyLimit(
	limit: number,
	kv?: KVNamespace,
	quotaCoordinator?: DurableObjectNamespace,
	degradationSink?: GlobalCostCeilingDegradationSink,
): Promise<GlobalRateLimitResult> {
	// Same Infinity/JSON-encoding trap as checkToolDailyRateLimit. A self-host
	// that disables the global cap by setting it to Infinity would otherwise
	// 400 every coordinator call.
	if (!Number.isFinite(limit)) {
		return { allowed: true, remaining: limit, limit };
	}
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

	// The authoritative DO is gone whenever the breaker is OPEN (or no DO was
	// wired at all). In that degraded state the global cost ceiling is no longer
	// exact — surface it once per affected request so operators can react. KV is
	// the globally-shared tier we WANT to land on; in-memory is the last resort.
	const breakerOpen = isQuotaCoordinatorBreakerOpen();
	// Emit exactly once per degraded request, regardless of which fallback tier
	// ultimately serves it.
	if (breakerOpen) {
		degradationSink?.emitDegradationEvent({ degradationType: 'cost_ceiling_degraded', component: 'global_cost_ceiling' });
	}

	if (kv) {
		try {
			return await checkGlobalDailyLimitKV(limit, kv);
		} catch {
			logError('[rate-limiter] KV global cap error, falling back to in-memory');
		}
	}

	// Last resort: per-isolate in-memory. Down-scale the cap by the estimated
	// isolate fan-out so hundreds of isolates don't each enforce the full `limit`
	// (which would let the real global spend reach `limit × isolate-count`).
	// `Math.max(1, …)` guards a tiny configured limit from flooring to 0.
	const effectiveLimit = breakerOpen ? Math.max(1, Math.floor(limit / GLOBAL_CEILING_ISOLATE_FANOUT_ESTIMATE)) : limit;
	return checkGlobalDailyLimitInMemory(effectiveLimit);
}

/**
 * Check if a single IP has exceeded its per-IP daily cap for unauthenticated callers.
 * Uses KV when available, with in-memory fallback on failure (FIND-02).
 *
 * @param ip  - Client IP address (cf-connecting-ip)
 * @param kv  - Optional KV namespace; falls back to in-memory when absent or on error.
 */
export async function checkIpDailyLimit(ip: string, kv: KVNamespace | undefined): Promise<GlobalRateLimitResult> {
	if (kv) {
		try {
			return await checkIpDailyLimitKV(ip, FREE_IP_DAILY_LIMIT, kv);
		} catch {
			logError('[rate-limiter] KV ip-daily cap error, falling back to in-memory');
		}
	}
	return checkIpDailyLimitInMemory(ip, FREE_IP_DAILY_LIMIT);
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

/**
 * Test-only helper. Removes every `rl:*` key from the given KV namespace —
 * complement to `resetAllRateLimits()` which only clears the per-isolate
 * Map. Call from `beforeEach` in test files that exercise the public
 * rate-limit code path; without it the 60s minute-window keys can bleed
 * across tests on slow CI workers (#96).
 *
 * Fail-soft: returns silently on KV errors. Test isolation must never
 * reject the surrounding beforeEach.
 */
export async function resetAllRateLimitsKv(kv: KVNamespace): Promise<void> {
	try {
		let cursor: string | undefined;
		do {
			const list = await kv.list({ prefix: 'rl:', cursor });
			await Promise.all(list.keys.map((k) => kv.delete(k.name)));
			cursor = list.list_complete ? undefined : list.cursor;
		} while (cursor);
	} catch {
		// Best-effort — surfaced via test flake if the helper truly fails.
	}
}

/**
 * Best-effort per-IP daily cap on the number of DISTINCT domains scanned.
 * Uses two KV keys per (principal, day): a per-domain marker and a counter.
 * A repeat domain consumes no new budget. Fail-open: any KV error or absent KV
 * returns allowed. Not a hard lock — IP rotation defeats it by design.
 *
 * KV eventual-consistency and partial-write drift are accepted as best-effort.
 * The counter is written BEFORE the marker so a partial failure (counter
 * written, marker not) leaves no marker — the domain is re-counted next time
 * (a harmless over-count) rather than slipping through free (an under-count).
 */
export async function checkDistinctDomainDailyLimit(
	principalId: string,
	domainFingerprint: string,
	limit: number,
	kv?: KVNamespace,
): Promise<ToolDailyRateLimitResult> {
	if (!Number.isFinite(limit)) {
		return { allowed: true, remaining: limit, limit };
	}
	if (!kv) {
		return { allowed: true, remaining: limit, limit };
	}
	try {
		return await withIpKvLock(`ddc:${principalId}`, async () => {
			const now = Date.now();
			const dayWindow = Math.floor(now / DAY_MS);
			const markerKey = `rl:day:ddc:mark:${principalId}:${dayWindow}:${domainFingerprint}`;
			const countKey = `rl:day:ddc:count:${principalId}:${dayWindow}`;

			const alreadySeen = await kv.get(markerKey);
			if (alreadySeen) {
				const seenCount = parseKvCounter(await kv.get(countKey));
				return { allowed: true, remaining: Math.max(limit - seenCount, 0), limit };
			}

			const currentCount = parseKvCounter(await kv.get(countKey));
			if (currentCount >= limit) {
				const windowEnd = (dayWindow + 1) * DAY_MS;
				return { allowed: false, retryAfterMs: Math.max(windowEnd - now, 0), remaining: 0, limit };
			}

			const nextCount = currentCount + 1;
			await kv.put(countKey, String(nextCount), { expirationTtl: 86_400 });
			await kv.put(markerKey, '1', { expirationTtl: 86_400 });
			return { allowed: true, remaining: Math.max(limit - nextCount, 0), limit };
		});
	} catch {
		logError('[rate-limiter] distinct-domain KV error, failing open');
		return { allowed: true, remaining: limit, limit };
	}
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
