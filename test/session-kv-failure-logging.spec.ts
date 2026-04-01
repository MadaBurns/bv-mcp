import { afterEach, describe, expect, it, vi } from 'vitest';

afterEach(() => {
	vi.restoreAllMocks();
});

describe('session KV failure logging', () => {
	it('calls logError (not console.warn) when KV write fails during createSession', async () => {
		const logModule = await import('../src/lib/log');
		const logErrorSpy = vi.spyOn(logModule, 'logError');
		const consoleWarnSpy = vi.spyOn(console, 'warn');

		const { createSession, resetSessions } = await import('../src/lib/session');

		try {
			const kv = {
				get: vi.fn().mockResolvedValue(null),
				put: vi.fn().mockRejectedValue(new Error('KV write failed')),
				delete: vi.fn().mockResolvedValue(undefined),
			} as unknown as KVNamespace;

			const id = await createSession(kv);
			// Session should still be created successfully (in-memory fallback)
			expect(id).toBeDefined();
			expect(typeof id).toBe('string');
			expect(id.length).toBeGreaterThan(0);

			// logError should have been called with the KV failure message
			expect(logErrorSpy).toHaveBeenCalledWith(
				'[session] KV create failed, in-memory fallback active',
				expect.objectContaining({ category: 'session' }),
			);

			// console.warn should NOT have been called for this error
			const sessionWarnCalls = consoleWarnSpy.mock.calls.filter(
				(call) => typeof call[0] === 'string' && call[0].includes('KV create failed'),
			);
			expect(sessionWarnCalls).toHaveLength(0);
		} finally {
			resetSessions();
		}
	});

	it('calls logError when KV validate fails', async () => {
		const logModule = await import('../src/lib/log');
		const logErrorSpy = vi.spyOn(logModule, 'logError');

		const { createSession, validateSession, resetSessions } = await import('../src/lib/session');

		try {
			// Create session without KV
			const id = await createSession();

			// Force validation through KV path by clearing in-memory
			const { ACTIVE_SESSIONS } = await import('../src/lib/session');
			ACTIVE_SESSIONS.delete(id);

			const kv = {
				get: vi.fn().mockRejectedValue(new Error('KV read failed')),
				put: vi.fn().mockResolvedValue(undefined),
				delete: vi.fn().mockResolvedValue(undefined),
			} as unknown as KVNamespace;

			// This will try KV (fails) and return false
			const result = await validateSession(id, kv);
			expect(result).toBe(false);

			// logError should have been called
			expect(logErrorSpy).toHaveBeenCalledWith(
				'[session] KV validate failed',
				expect.objectContaining({ category: 'session' }),
			);
		} finally {
			resetSessions();
		}
	});

	it('session is still usable in-memory after KV create failure (intentional single-isolate degradation)', async () => {
		const { createSession, validateSession, resetSessions } = await import('../src/lib/session');

		try {
			const kv = {
				get: vi.fn().mockResolvedValue(null),
				put: vi.fn().mockRejectedValue(new Error('KV write failed')),
				delete: vi.fn().mockResolvedValue(undefined),
			} as unknown as KVNamespace;

			const id = await createSession(kv);

			// Session should be valid via in-memory (without KV)
			expect(await validateSession(id)).toBe(true);

			// Session should also validate with KV (in-memory fast path)
			expect(await validateSession(id, kv)).toBe(true);
		} finally {
			resetSessions();
		}
	});
});
