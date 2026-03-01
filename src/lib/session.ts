/**
 * Session Management
 *
 * In-memory session store (per Worker isolate). Sessions are created
 * on `initialize` and removed on `DELETE /mcp`. No TTL/expiry —
 * sessions persist for the lifetime of the isolate.
 */

/** Active sessions keyed by session ID */
export const activeSessions = new Map<string, { createdAt: number }>();

/** Generate a cryptographically secure session ID (hex, visible ASCII) */
export function generateSessionId(): string {
	const bytes = new Uint8Array(32);
	crypto.getRandomValues(bytes);
	return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/** Create a new session and return its ID */
export function createSession(): string {
	const id = generateSessionId();
	activeSessions.set(id, { createdAt: Date.now() });
	return id;
}

/** Check whether a session ID exists in the active sessions store */
export function validateSession(id: string): boolean {
	return activeSessions.has(id);
}

/** Remove a session from the store. Returns true if the session existed. */
export function deleteSession(id: string): boolean {
	return activeSessions.delete(id);
}
