// SPDX-License-Identifier: BUSL-1.1

import { pruneTimestamps } from './rate-limiter';

export interface SessionRecord {
	createdAt: number;
	lastAccessedAt: number;
}

export interface SessionCreateRateResult {
	allowed: boolean;
	retryAfterMs?: number;
	remaining: number;
}

/** Active sessions keyed by session ID */
export const ACTIVE_SESSIONS = new Map<string, SessionRecord>();

/** Tombstones for explicitly-deleted sessions (prevents revival after DELETE).
 *  Keyed by session ID → deletion timestamp. Short-lived (10 min TTL). */
export const SESSION_TOMBSTONES = new Map<string, number>();
const TOMBSTONE_TTL_MS = 10 * 60 * 1000;

/** Session idle TTL (2 hours) — extended from 30min to accommodate Claude Desktop
 *  users who go idle between queries. mcp-remote does not auto-reinitialize on
 *  session expiry, so a short TTL causes persistent "session expired" 404 loops. */
export const SESSION_TTL_MS = 2 * 60 * 60 * 1000;
export const SESSION_REFRESH_INTERVAL_MS = 5 * 60 * 1000;

export const SESSION_CREATE_WINDOW_MS = 60_000;
export const SESSION_CREATE_LIMIT_PER_MINUTE = 30;
const MAX_IN_MEMORY_SESSIONS = 2000;
const SESSION_CLEANUP_INTERVAL_MS = 5 * 60 * 1000;

/** Maximum number of unique IPs tracked for session creation rate limiting */
export const MAX_SESSION_CREATE_IPS = 5000;

let lastCleanupAt = 0;
export const SESSION_CREATE_BY_IP = new Map<string, number[]>();

function isExpired(lastAccessedAt: number, now: number): boolean {
	return now - lastAccessedAt > SESSION_TTL_MS;
}

function maybeCleanupSessions(now: number): void {
	if (now - lastCleanupAt < SESSION_CLEANUP_INTERVAL_MS) return;
	lastCleanupAt = now;

	for (const [id, session] of ACTIVE_SESSIONS.entries()) {
		if (isExpired(session.lastAccessedAt, now)) {
			ACTIVE_SESSIONS.delete(id);
		}
	}
}

function evictLeastRecentlyUsedSession(): void {
	let oldestId: string | undefined;
	let oldestAccess = Number.POSITIVE_INFINITY;

	for (const [id, session] of ACTIVE_SESSIONS.entries()) {
		if (session.lastAccessedAt < oldestAccess) {
			oldestAccess = session.lastAccessedAt;
			oldestId = id;
		}
	}

	if (oldestId) {
		ACTIVE_SESSIONS.delete(oldestId);
	}
}

export function checkSessionCreateRateLimitInMemory(ip: string): SessionCreateRateResult {
	const now = Date.now();
	const key = ip || 'unknown';
	const existing = SESSION_CREATE_BY_IP.get(key) ?? [];
	const recent = pruneTimestamps(existing, SESSION_CREATE_WINDOW_MS, now);

	// Clean up empty entries after pruning to prevent memory leak
	if (recent.length === 0) {
		SESSION_CREATE_BY_IP.delete(key);
	}

	if (recent.length >= SESSION_CREATE_LIMIT_PER_MINUTE) {
		const oldest = recent[0];
		return {
			allowed: false,
			retryAfterMs: Math.max(oldest + SESSION_CREATE_WINDOW_MS - now, 0),
			remaining: 0,
		};
	}

	recent.push(now);
	SESSION_CREATE_BY_IP.set(key, recent);

	// Enforce size cap with eviction of oldest entries
	if (SESSION_CREATE_BY_IP.size > MAX_SESSION_CREATE_IPS) {
		evictOldestSessionCreateIps(SESSION_CREATE_BY_IP.size - MAX_SESSION_CREATE_IPS);
	}

	return {
		allowed: true,
		remaining: SESSION_CREATE_LIMIT_PER_MINUTE - recent.length,
	};
}

/** Evict the N oldest IP entries from SESSION_CREATE_BY_IP based on latest timestamp */
function evictOldestSessionCreateIps(count: number): void {
	if (count <= 0) return;

	// Build a list of [key, latestTimestamp] pairs
	const entries: Array<[string, number]> = [];
	for (const [key, timestamps] of SESSION_CREATE_BY_IP.entries()) {
		const latest = timestamps.length > 0 ? timestamps[timestamps.length - 1] : 0;
		entries.push([key, latest]);
	}

	// Sort by latest timestamp ascending (oldest first)
	entries.sort((a, b) => a[1] - b[1]);

	// Delete the oldest entries
	for (let i = 0; i < count && i < entries.length; i++) {
		SESSION_CREATE_BY_IP.delete(entries[i][0]);
	}
}

export function createSessionInMemory(id: string): void {
	const now = Date.now();
	const record: SessionRecord = { createdAt: now, lastAccessedAt: now };
	ACTIVE_SESSIONS.set(id, record);
	maybeCleanupSessions(now);
	if (ACTIVE_SESSIONS.size > MAX_IN_MEMORY_SESSIONS) {
		evictLeastRecentlyUsedSession();
	}
}

export function validateSessionInMemory(id: string): boolean {
	const now = Date.now();
	maybeCleanupSessions(now);

	const session = ACTIVE_SESSIONS.get(id);
	if (!session) return false;

	if (isExpired(session.lastAccessedAt, now)) {
		ACTIVE_SESSIONS.delete(id);
		return false;
	}

	if (now - session.lastAccessedAt >= SESSION_REFRESH_INTERVAL_MS) {
		session.lastAccessedAt = now;
	}
	return true;
}

export function deleteSessionInMemory(id: string): boolean {
	const existed = ACTIVE_SESSIONS.delete(id);
	// Always set the tombstone to prevent revival of this ID on this isolate
	SESSION_TOMBSTONES.set(id, Date.now());
	return existed;
}

/** Check whether a session was explicitly terminated (not just idle-expired). */
export function isSessionTombstoned(id: string): boolean {
	const deletedAt = SESSION_TOMBSTONES.get(id);
	if (deletedAt === undefined) return false;
	if (Date.now() - deletedAt > TOMBSTONE_TTL_MS) {
		SESSION_TOMBSTONES.delete(id);
		return false;
	}
	return true;
}

export function resetSessions(): void {
	ACTIVE_SESSIONS.clear();
	SESSION_TOMBSTONES.clear();
	SESSION_CREATE_BY_IP.clear();
	lastCleanupAt = 0;
}