/**
 * Rate limiter for the DNS Security MCP Server.
 * Enforces per-IP limits: 100 requests/hour, 10 requests/minute.
 *
 * Uses Cloudflare KV for distributed rate limiting when available,
 * with in-memory fallback when KV is not configured.
 *
 * KV strategy: fixed-window counters with expirationTtl for automatic cleanup.
 * Key format: rl:min:{ip}:{windowId} (minute), rl:hr:{ip}:{windowId} (hour)
 *
 * Compatible with Cloudflare Workers runtime (no Node.js APIs).
 */

interface RateLimitWindow {
	timestamps: number[];
}

interface RateLimitEntry {
	minute: RateLimitWindow;
	hour: RateLimitWindow;
}

interface ToolDailyRateLimitEntry {
	timestamps: number[];
}

type RateLimitScope = 'tools' | 'control';

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

const MINUTE_LIMIT = 10;
const HOUR_LIMIT = 100;
const CONTROL_PLANE_MINUTE_LIMIT = 30;
const CONTROL_PLANE_HOUR_LIMIT = 300;
const MINUTE_MS = 60_000;
const HOUR_MS = 3_600_000;
const DAY_MS = 86_400_000;
const CLEANUP_INTERVAL_MS = 300_000; // 5 minutes

// Best-effort per-IP serialization for KV updates inside a single isolate.
// This does not provide cross-isolate atomicity, but it prevents local races.
const kvIpLockTails = new Map<string, Promise<void>>();

// ---------------------------------------------------------------------------
// In-memory fallback
// ---------------------------------------------------------------------------
const entries = new Map<string, RateLimitEntry>();
const toolDailyEntries = new Map<string, ToolDailyRateLimitEntry>();
let lastCleanup = Date.now();

/** Prune timestamps that fall outside a sliding window. */
export function pruneTimestamps(timestamps: number[], windowMs: number, now: number): number[] {
	const cutoff = now - windowMs;
	let i = 0;
	while (i < timestamps.length && timestamps[i] <= cutoff) {
		i++;
	}
	return i > 0 ? timestamps.slice(i) : timestamps;
}

function cleanupExpiredEntries(now: number): void {
	if (now - lastCleanup < CLEANUP_INTERVAL_MS) return;
	lastCleanup = now;

	const hourCutoff = now - HOUR_MS;
	for (const [key, entry] of entries) {
		if (entry.hour.timestamps.length === 0 || entry.hour.timestamps[entry.hour.timestamps.length - 1] <= hourCutoff) {
			entries.delete(key);
		}
	}

	const dayCutoff = now - DAY_MS;
	for (const [key, entry] of toolDailyEntries) {
		if (entry.timestamps.length === 0 || entry.timestamps[entry.timestamps.length - 1] <= dayCutoff) {
			toolDailyEntries.delete(key);
		}
	}
}

function getOrCreateEntry(key: string): RateLimitEntry {
	let entry = entries.get(key);
	if (!entry) {
		entry = {
			minute: { timestamps: [] },
			hour: { timestamps: [] },
		};
		entries.set(key, entry);
	}
	return entry;
}

function buildScopedEntryKey(ip: string, scope: RateLimitScope): string {
	return `${scope}:${ip}`;
}

function getOrCreateToolDailyEntry(key: string): ToolDailyRateLimitEntry {
	let entry = toolDailyEntries.get(key);
	if (!entry) {
		entry = { timestamps: [] };
		toolDailyEntries.set(key, entry);
	}
	return entry;
}

function checkScopedRateLimitInMemory(ip: string, scope: RateLimitScope, minuteLimit: number, hourLimit: number): RateLimitResult {
	const now = Date.now();
	cleanupExpiredEntries(now);

	const entry = getOrCreateEntry(buildScopedEntryKey(ip, scope));

	entry.minute.timestamps = pruneTimestamps(entry.minute.timestamps, MINUTE_MS, now);
	entry.hour.timestamps = pruneTimestamps(entry.hour.timestamps, HOUR_MS, now);

	const minuteCount = entry.minute.timestamps.length;
	const hourCount = entry.hour.timestamps.length;

	if (minuteCount >= minuteLimit) {
		const oldestInWindow = entry.minute.timestamps[0];
		const retryAfterMs = oldestInWindow + MINUTE_MS - now;
		return {
			allowed: false,
			retryAfterMs: Math.max(retryAfterMs, 0),
			minuteRemaining: 0,
			hourRemaining: Math.max(hourLimit - hourCount, 0),
		};
	}

	if (hourCount >= hourLimit) {
		const oldestInWindow = entry.hour.timestamps[0];
		const retryAfterMs = oldestInWindow + HOUR_MS - now;
		return {
			allowed: false,
			retryAfterMs: Math.max(retryAfterMs, 0),
			minuteRemaining: Math.max(minuteLimit - minuteCount, 0),
			hourRemaining: 0,
		};
	}

	entry.minute.timestamps.push(now);
	entry.hour.timestamps.push(now);

	return {
		allowed: true,
		minuteRemaining: minuteLimit - minuteCount - 1,
		hourRemaining: hourLimit - hourCount - 1,
	};
}

function checkRateLimitInMemory(ip: string): RateLimitResult {
	return checkScopedRateLimitInMemory(ip, 'tools', MINUTE_LIMIT, HOUR_LIMIT);
}

function checkControlPlaneRateLimitInMemory(ip: string): RateLimitResult {
	return checkScopedRateLimitInMemory(ip, 'control', CONTROL_PLANE_MINUTE_LIMIT, CONTROL_PLANE_HOUR_LIMIT);
}

function buildToolDailyKey(principalId: string, toolName: string): string {
	return `${principalId}:${toolName.trim().toLowerCase()}`;
}

function checkToolDailyRateLimitInMemory(principalId: string, toolName: string, limit: number): ToolDailyRateLimitResult {
	const now = Date.now();
	cleanupExpiredEntries(now);

	const key = buildToolDailyKey(principalId, toolName);
	const entry = getOrCreateToolDailyEntry(key);
	entry.timestamps = pruneTimestamps(entry.timestamps, DAY_MS, now);

	const count = entry.timestamps.length;
	if (count >= limit) {
		const oldestInWindow = entry.timestamps[0];
		const retryAfterMs = oldestInWindow + DAY_MS - now;
		return {
			allowed: false,
			retryAfterMs: Math.max(retryAfterMs, 0),
			remaining: 0,
			limit,
		};
	}

	entry.timestamps.push(now);
	return {
		allowed: true,
		remaining: Math.max(limit - entry.timestamps.length, 0),
		limit,
	};
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

	const minuteCount = minuteVal ? parseInt(minuteVal, 10) : 0;
	const hourCount = hourVal ? parseInt(hourVal, 10) : 0;

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
	const newMinute = minuteCount + 1;
	const newHour = hourCount + 1;
	await Promise.all([
		kv.put(minuteKey, String(newMinute), { expirationTtl: 60 }),
		kv.put(hourKey, String(newHour), { expirationTtl: 3600 }),
	]);

	return {
		allowed: true,
		minuteRemaining: minuteLimit - newMinute,
		hourRemaining: hourLimit - newHour,
	};
	});
}

async function checkRateLimitKV(ip: string, kv: KVNamespace): Promise<RateLimitResult> {
	return checkScopedRateLimitKV(ip, 'tools', MINUTE_LIMIT, HOUR_LIMIT, kv);
}

async function checkControlPlaneRateLimitKV(ip: string, kv: KVNamespace): Promise<RateLimitResult> {
	return checkScopedRateLimitKV(ip, 'control', CONTROL_PLANE_MINUTE_LIMIT, CONTROL_PLANE_HOUR_LIMIT, kv);
}

async function withIpKvLock<T>(ip: string, work: () => Promise<T>): Promise<T> {
	const prevTail = kvIpLockTails.get(ip) ?? Promise.resolve();
	let release: (() => void) | undefined;
	const current = new Promise<void>((resolve) => {
		release = resolve;
	});
	const tail = prevTail.then(() => current);
	kvIpLockTails.set(ip, tail);

	await prevTail;
	try {
		return await work();
	} finally {
		release?.();
		if (kvIpLockTails.get(ip) === tail) {
			kvIpLockTails.delete(ip);
		}
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
		const currentCount = currentVal ? parseInt(currentVal, 10) : 0;

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
export async function checkRateLimit(ip: string, kv?: KVNamespace): Promise<RateLimitResult> {
       if (kv) {
	       try {
		       return await checkRateLimitKV(ip, kv);
	       } catch (err) {
		       // KV error — log warning and fall back to in-memory
		       console.warn('[rate-limiter] KV error, falling back to in-memory:', (err instanceof Error ? err.message : err));
	       }
       }
       return checkRateLimitInMemory(ip);
}

/**
 * Check if a request from the given IP is allowed under lower-cost control-plane limits.
 * Uses KV when available, with in-memory fallback on failure.
 */
export async function checkControlPlaneRateLimit(ip: string, kv?: KVNamespace): Promise<RateLimitResult> {
	if (kv) {
		try {
			return await checkControlPlaneRateLimitKV(ip, kv);
		} catch (err) {
			console.warn('[rate-limiter] KV control-plane error, falling back to in-memory:', err instanceof Error ? err.message : err);
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
): Promise<ToolDailyRateLimitResult> {
	if (kv) {
		try {
			return await checkToolDailyRateLimitKV(principalId, toolName, limit, kv);
		} catch (err) {
			console.warn('[rate-limiter] KV tool quota error, falling back to in-memory:', err instanceof Error ? err.message : err);
		}
	}
	return checkToolDailyRateLimitInMemory(principalId, toolName, limit);
}

/**
 * Reset rate limit state for an IP (useful for testing).
 * @internal Exported for test use only.
 */
export function resetRateLimit(ip: string): void {
	entries.delete(buildScopedEntryKey(ip, 'tools'));
	entries.delete(buildScopedEntryKey(ip, 'control'));
}

/**
 * Reset all rate limit state (useful for testing).
 * @internal Exported for test use only.
 */
export function resetAllRateLimits(): void {
	entries.clear();
	toolDailyEntries.clear();
	lastCleanup = Date.now();
}
