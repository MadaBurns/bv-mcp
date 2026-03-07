/**
 * Session Management
 *
 * KV-backed (when configured) or in-memory (fallback) session store.
 * Sessions are created
 * on `initialize`, refreshed on successful validation, and removed
 * on `DELETE /mcp` or when expired.
 */

import { pruneTimestamps } from './rate-limiter';

interface SessionRecord {
	createdAt: number;
	lastAccessedAt: number;
}

/** Active sessions keyed by session ID */
export const activeSessions = new Map<string, SessionRecord>();

/** Session idle TTL (30 minutes) */
export const SESSION_TTL_MS = 30 * 60 * 1000;
const SESSION_TTL_SECONDS = Math.ceil(SESSION_TTL_MS / 1000);
const SESSION_CREATE_WINDOW_MS = 60_000;
const SESSION_CREATE_LIMIT_PER_MINUTE = 30;
export const SESSION_REFRESH_INTERVAL_MS = 5 * 60 * 1000;
const MAX_IN_MEMORY_SESSIONS = 2000;

const SESSION_KEY_PREFIX = 'session:';
const SESSION_CREATE_RATE_KEY_PREFIX = 'rl:session-create';

/** Cleanup cadence for lazy background pruning (5 minutes) */
const SESSION_CLEANUP_INTERVAL_MS = 5 * 60 * 1000;

let lastCleanupAt = 0;
const sessionCreateByIp = new Map<string, number[]>();

function isExpired(lastAccessedAt: number, now: number): boolean {
	return now - lastAccessedAt > SESSION_TTL_MS;
}

function maybeCleanupSessions(now: number): void {
	if (now - lastCleanupAt < SESSION_CLEANUP_INTERVAL_MS) return;
	lastCleanupAt = now;

	for (const [id, session] of activeSessions.entries()) {
		if (isExpired(session.lastAccessedAt, now)) {
			activeSessions.delete(id);
		}
	}
}

function sessionKey(id: string): string {
	return `${SESSION_KEY_PREFIX}${id}`;
}

function evictLeastRecentlyUsedSession(): void {
	let oldestId: string | undefined;
	let oldestAccess = Number.POSITIVE_INFINITY;

	for (const [id, session] of activeSessions.entries()) {
		if (session.lastAccessedAt < oldestAccess) {
			oldestAccess = session.lastAccessedAt;
			oldestId = id;
		}
	}

	if (oldestId) {
		activeSessions.delete(oldestId);
	}
}

export interface SessionCreateRateResult {
	allowed: boolean;
	retryAfterMs?: number;
	remaining: number;
}

/**
 * Best-effort per-IP gate for session creation endpoints.
 * Used to reduce abuse pressure when anonymous clients spam initialize/SSE starts.
 */
function checkSessionCreateRateLimitInMemory(ip: string): SessionCreateRateResult {
	const now = Date.now();
	const key = ip || 'unknown';
	const existing = sessionCreateByIp.get(key) ?? [];
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
	sessionCreateByIp.set(key, recent);
	return {
		allowed: true,
		remaining: SESSION_CREATE_LIMIT_PER_MINUTE - recent.length,
	};
}

export async function checkSessionCreateRateLimit(ip: string, kv?: KVNamespace): Promise<SessionCreateRateResult> {
	if (kv) {
		try {
			const now = Date.now();
			const keyIp = ip || 'unknown';
			const minuteWindow = Math.floor(now / SESSION_CREATE_WINDOW_MS);
			const key = `${SESSION_CREATE_RATE_KEY_PREFIX}:${keyIp}:${minuteWindow}`;
			const currentVal = await kv.get(key);
			const currentCount = currentVal ? parseInt(currentVal, 10) : 0;

			if (currentCount >= SESSION_CREATE_LIMIT_PER_MINUTE) {
				const windowEnd = (minuteWindow + 1) * SESSION_CREATE_WINDOW_MS;
				return {
					allowed: false,
					retryAfterMs: Math.max(windowEnd - now, 0),
					remaining: 0,
				};
			}

			const nextCount = currentCount + 1;
			await kv.put(key, String(nextCount), { expirationTtl: 60 });
			return {
				allowed: true,
				remaining: SESSION_CREATE_LIMIT_PER_MINUTE - nextCount,
			};
		} catch (err) {
			console.warn('[session] KV create limiter failed, falling back to in-memory:', err instanceof Error ? err.message : String(err));
		}
	}

	return checkSessionCreateRateLimitInMemory(ip);
}

async function createSessionKVRecord(id: string, kv: KVNamespace, record: SessionRecord): Promise<void> {
	await kv.put(sessionKey(id), JSON.stringify(record), { expirationTtl: SESSION_TTL_SECONDS });
}

async function readSessionKVRecord(id: string, kv: KVNamespace): Promise<SessionRecord | undefined> {
	const record = await kv.get(sessionKey(id), 'json');
	if (!record || typeof record !== 'object') return undefined;

	const candidate = record as Partial<SessionRecord>;
	if (typeof candidate.createdAt !== 'number' || typeof candidate.lastAccessedAt !== 'number') {
		return undefined;
	}

	return {
		createdAt: candidate.createdAt,
		lastAccessedAt: candidate.lastAccessedAt,
	};
}

/** Generate a cryptographically secure session ID (hex, visible ASCII) */
export function generateSessionId(): string {
	const bytes = new Uint8Array(32);
	crypto.getRandomValues(bytes);
	return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/** Create a new session and return its ID */
export async function createSession(kv?: KVNamespace): Promise<string> {
	const id = generateSessionId();
	const now = Date.now();
	const record: SessionRecord = { createdAt: now, lastAccessedAt: now };

	if (kv) {
		try {
			await createSessionKVRecord(id, kv, record);
			return id;
		} catch (err) {
			console.warn('[session] KV create failed, falling back to in-memory:', err instanceof Error ? err.message : String(err));
		}
	}

	activeSessions.set(id, record);
	maybeCleanupSessions(now);
	if (activeSessions.size > MAX_IN_MEMORY_SESSIONS) {
		evictLeastRecentlyUsedSession();
	}
	return id;
}

/** Check whether a session ID exists in the active sessions store */
export async function validateSession(id: string, kv?: KVNamespace): Promise<boolean> {
	const now = Date.now();

	if (kv) {
		try {
			const record = await readSessionKVRecord(id, kv);
			if (!record) return false;

			if (isExpired(record.lastAccessedAt, now)) {
				await kv.delete(sessionKey(id));
				return false;
			}

			if (now - record.lastAccessedAt >= SESSION_REFRESH_INTERVAL_MS) {
				record.lastAccessedAt = now;
				await createSessionKVRecord(id, kv, record);
			}
			return true;
		} catch (err) {
			console.warn('[session] KV validate failed, falling back to in-memory:', err instanceof Error ? err.message : String(err));
		}
	}

	maybeCleanupSessions(now);

	const session = activeSessions.get(id);
	if (!session) return false;

	if (isExpired(session.lastAccessedAt, now)) {
		activeSessions.delete(id);
		return false;
	}

	if (now - session.lastAccessedAt >= SESSION_REFRESH_INTERVAL_MS) {
		session.lastAccessedAt = now;
	}
	return true;
}

/** Remove a session from the store. Returns true if the session existed. */
export async function deleteSession(id: string, kv?: KVNamespace): Promise<boolean> {
	if (kv) {
		try {
			const existing = await readSessionKVRecord(id, kv);
			if (!existing) return false;
			await kv.delete(sessionKey(id));
			return true;
		} catch (err) {
			console.warn('[session] KV delete failed, falling back to in-memory:', err instanceof Error ? err.message : String(err));
		}
	}

	return activeSessions.delete(id);
}

/**
 * Reset all sessions (test helper).
 * @internal Exported for test use only.
 */
export function resetSessions(): void {
	activeSessions.clear();
	sessionCreateByIp.clear();
	lastCleanupAt = 0;
}
