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

/** Session idle TTL (30 minutes) */
export const SESSION_TTL_MS = 30 * 60 * 1000;
export const SESSION_REFRESH_INTERVAL_MS = 5 * 60 * 1000;

const SESSION_CREATE_WINDOW_MS = 60_000;
const SESSION_CREATE_LIMIT_PER_MINUTE = 30;
const MAX_IN_MEMORY_SESSIONS = 2000;
const SESSION_CLEANUP_INTERVAL_MS = 5 * 60 * 1000;

let lastCleanupAt = 0;
const SESSION_CREATE_BY_IP = new Map<string, number[]>();

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
	return {
		allowed: true,
		remaining: SESSION_CREATE_LIMIT_PER_MINUTE - recent.length,
	};
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
	return ACTIVE_SESSIONS.delete(id);
}

export function resetSessions(): void {
	ACTIVE_SESSIONS.clear();
	SESSION_CREATE_BY_IP.clear();
	lastCleanupAt = 0;
}