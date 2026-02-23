/**
 * Rate limiter for the DNS Security MCP Server.
 * Enforces per-IP limits: 50 requests/hour, 10 requests/minute.
 *
 * Uses in-memory sliding window counters.
 * Compatible with Cloudflare Workers runtime (no Node.js APIs).
 */

interface RateLimitWindow {
  timestamps: number[];
}

interface RateLimitEntry {
  minute: RateLimitWindow;
  hour: RateLimitWindow;
}

export interface RateLimitResult {
  allowed: boolean;
  retryAfterMs?: number;
  minuteRemaining: number;
  hourRemaining: number;
}

const MINUTE_LIMIT = 10;
const HOUR_LIMIT = 50;
const MINUTE_MS = 60_000;
const HOUR_MS = 3_600_000;
const CLEANUP_INTERVAL_MS = 300_000; // 5 minutes

// ---------------------------------------------------------------------------
// In-memory fallback
// ---------------------------------------------------------------------------
const entries = new Map<string, RateLimitEntry>();
let lastCleanup = Date.now();

function pruneTimestamps(timestamps: number[], windowMs: number, now: number): number[] {
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
    if (
      entry.hour.timestamps.length === 0 ||
      entry.hour.timestamps[entry.hour.timestamps.length - 1] <= hourCutoff
    ) {
      entries.delete(key);
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

function checkRateLimitInMemory(ip: string): RateLimitResult {
  const now = Date.now();
  cleanupExpiredEntries(now);

  const entry = getOrCreateEntry(ip);

  entry.minute.timestamps = pruneTimestamps(entry.minute.timestamps, MINUTE_MS, now);
  entry.hour.timestamps = pruneTimestamps(entry.hour.timestamps, HOUR_MS, now);

  const minuteCount = entry.minute.timestamps.length;
  const hourCount = entry.hour.timestamps.length;

  if (minuteCount >= MINUTE_LIMIT) {
    const oldestInWindow = entry.minute.timestamps[0];
    const retryAfterMs = oldestInWindow + MINUTE_MS - now;
    return {
      allowed: false,
      retryAfterMs: Math.max(retryAfterMs, 0),
      minuteRemaining: 0,
      hourRemaining: Math.max(HOUR_LIMIT - hourCount, 0),
    };
  }

  if (hourCount >= HOUR_LIMIT) {
    const oldestInWindow = entry.hour.timestamps[0];
    const retryAfterMs = oldestInWindow + HOUR_MS - now;
    return {
      allowed: false,
      retryAfterMs: Math.max(retryAfterMs, 0),
      minuteRemaining: Math.max(MINUTE_LIMIT - minuteCount, 0),
      hourRemaining: 0,
    };
  }

  entry.minute.timestamps.push(now);
  entry.hour.timestamps.push(now);

  return {
    allowed: true,
    minuteRemaining: MINUTE_LIMIT - minuteCount - 1,
    hourRemaining: HOUR_LIMIT - hourCount - 1,
  };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Check if a request from the given IP is allowed under rate limits.
 * If allowed, the request is counted. If not, returns retry-after info.
 *
 * @param ip - Client IP address
 */
export async function checkRateLimit(ip: string): Promise<RateLimitResult> {
  return checkRateLimitInMemory(ip);
}

/**
 * Get current rate limit status for an IP without consuming a request.
 */
export function getRateLimitStatus(ip: string): RateLimitResult {
  const now = Date.now();
  const entry = entries.get(ip);

  if (!entry) {
    return { allowed: true, minuteRemaining: MINUTE_LIMIT, hourRemaining: HOUR_LIMIT };
  }

  const minuteTimestamps = pruneTimestamps(entry.minute.timestamps, MINUTE_MS, now);
  const hourTimestamps = pruneTimestamps(entry.hour.timestamps, HOUR_MS, now);

  const minuteCount = minuteTimestamps.length;
  const hourCount = hourTimestamps.length;

  return {
    allowed: minuteCount < MINUTE_LIMIT && hourCount < HOUR_LIMIT,
    minuteRemaining: Math.max(MINUTE_LIMIT - minuteCount, 0),
    hourRemaining: Math.max(HOUR_LIMIT - hourCount, 0),
  };
}

/**
 * Reset rate limit state for an IP (useful for testing).
 */
export function resetRateLimit(ip: string): void {
  entries.delete(ip);
}

/**
 * Reset all rate limit state (useful for testing).
 */
export function resetAllRateLimits(): void {
  entries.clear();
  lastCleanup = Date.now();
}

