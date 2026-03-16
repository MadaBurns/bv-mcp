// SPDX-License-Identifier: BUSL-1.1

import type { RateLimitResult, ToolDailyRateLimitResult } from './rate-limiter';

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

export type RateLimitScope = 'tools' | 'control';

const MINUTE_MS = 60_000;
const HOUR_MS = 3_600_000;
const DAY_MS = 86_400_000;
const CLEANUP_INTERVAL_MS = 300_000;

const RATE_LIMIT_ENTRIES = new Map<string, RateLimitEntry>();
const TOOL_DAILY_ENTRIES = new Map<string, ToolDailyRateLimitEntry>();
let lastCleanup = Date.now();

/** Prune timestamps that fall outside a sliding window. */
export function pruneTimestamps(timestamps: number[], windowMs: number, now: number): number[] {
	const cutoff = now - windowMs;
	let index = 0;
	while (index < timestamps.length && timestamps[index] <= cutoff) {
		index++;
	}
	return index > 0 ? timestamps.slice(index) : timestamps;
}

function cleanupExpiredEntries(now: number): void {
	if (now - lastCleanup < CLEANUP_INTERVAL_MS) return;
	lastCleanup = now;

	const hourCutoff = now - HOUR_MS;
	for (const [key, entry] of RATE_LIMIT_ENTRIES) {
		if (entry.hour.timestamps.length === 0 || entry.hour.timestamps[entry.hour.timestamps.length - 1] <= hourCutoff) {
			RATE_LIMIT_ENTRIES.delete(key);
		}
	}

	const dayCutoff = now - DAY_MS;
	for (const [key, entry] of TOOL_DAILY_ENTRIES) {
		if (entry.timestamps.length === 0 || entry.timestamps[entry.timestamps.length - 1] <= dayCutoff) {
			TOOL_DAILY_ENTRIES.delete(key);
		}
	}
}

function getOrCreateEntry(key: string): RateLimitEntry {
	let entry = RATE_LIMIT_ENTRIES.get(key);
	if (!entry) {
		entry = {
			minute: { timestamps: [] },
			hour: { timestamps: [] },
		};
		RATE_LIMIT_ENTRIES.set(key, entry);
	}
	return entry;
}

function buildScopedEntryKey(ip: string, scope: RateLimitScope): string {
	return `${scope}:${ip}`;
}

function getOrCreateToolDailyEntry(key: string): ToolDailyRateLimitEntry {
	let entry = TOOL_DAILY_ENTRIES.get(key);
	if (!entry) {
		entry = { timestamps: [] };
		TOOL_DAILY_ENTRIES.set(key, entry);
	}
	return entry;
}

export function checkScopedRateLimitInMemory(ip: string, scope: RateLimitScope, minuteLimit: number, hourLimit: number): RateLimitResult {
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

export function checkToolDailyRateLimitInMemory(principalId: string, toolName: string, limit: number): ToolDailyRateLimitResult {
	const now = Date.now();
	cleanupExpiredEntries(now);

	const key = `${principalId}:${toolName.trim().toLowerCase()}`;
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

export function resetRateLimit(ip: string): void {
	RATE_LIMIT_ENTRIES.delete(buildScopedEntryKey(ip, 'tools'));
	RATE_LIMIT_ENTRIES.delete(buildScopedEntryKey(ip, 'control'));
}

export function resetAllRateLimits(): void {
	RATE_LIMIT_ENTRIES.clear();
	TOOL_DAILY_ENTRIES.clear();
	lastCleanup = Date.now();
}