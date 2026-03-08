/**
 * Session Management
 *
 * KV-backed (when configured) or in-memory (fallback) session store.
 * Sessions are created
 * on `initialize`, refreshed on successful validation, and removed
 * on `DELETE /mcp` or when expired.
 */

import {
	activeSessions,
	checkSessionCreateRateLimitInMemory,
	createSessionInMemory,
	deleteSessionInMemory,
	resetSessions,
	SESSION_REFRESH_INTERVAL_MS,
	SESSION_TTL_MS,
	type SessionCreateRateResult,
	type SessionRecord,
	validateSessionInMemory,
} from './session-memory';

export { activeSessions, resetSessions, SESSION_REFRESH_INTERVAL_MS, SESSION_TTL_MS };

const SESSION_TTL_SECONDS = Math.ceil(SESSION_TTL_MS / 1000);
const SESSION_CREATE_WINDOW_MS = 60_000;
const SESSION_CREATE_LIMIT_PER_MINUTE = 30;

const SESSION_KEY_PREFIX = 'session:';
const SESSION_CREATE_RATE_KEY_PREFIX = 'rl:session-create';

/** Cleanup cadence for lazy background pruning (5 minutes) */
function sessionKey(id: string): string {
	return `${SESSION_KEY_PREFIX}${id}`;
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

	createSessionInMemory(id);
	return id;
}

/** Check whether a session ID exists in the active sessions store */
export async function validateSession(id: string, kv?: KVNamespace): Promise<boolean> {
	if (kv) {
		try {
			const now = Date.now();
			const record = await readSessionKVRecord(id, kv);
			if (!record) return false;

			if (now - record.lastAccessedAt > SESSION_TTL_MS) {
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

	return validateSessionInMemory(id);
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

	return deleteSessionInMemory(id);
}
