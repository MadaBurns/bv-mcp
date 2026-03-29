import { afterEach, describe, expect, it, vi } from 'vitest';

afterEach(() => {
	vi.restoreAllMocks();
});

describe('dispatch re-initialize session invalidation', () => {
	it('keeps old session valid when re-initializing (TTL handles cleanup)', async () => {
		const { dispatchMcpMethod } = await import('../src/mcp/dispatch');
		const { createSession, validateSession, resetSessions } = await import('../src/lib/session');

		try {
			// Create an initial session (simulating first initialize)
			const oldSessionId = await createSession();
			expect(await validateSession(oldSessionId)).toBe(true);

			// Re-initialize with the old session ID in existingSessionId
			const result = await dispatchMcpMethod({
				id: 1,
				method: 'initialize',
				params: undefined,
				ip: '198.51.100.1',
				isAuthenticated: true, // Skip rate limiting for simplicity
				rateHeaders: {},
				serverVersion: '1.0.0',
				createSessionOnInitialize: true,
				existingSessionId: oldSessionId,
			});

			expect(result.kind).toBe('success');
			if (result.kind === 'success') {
				expect(result.newSessionId).toBeDefined();
				expect(result.newSessionId).not.toBe(oldSessionId);
			}

			// Old session stays valid — no eager deletion prevents race conditions
			// where in-flight tools/call requests with the old session ID get 404s
			expect(await validateSession(oldSessionId)).toBe(true);

			// New session should be valid
			if (result.kind === 'success' && result.newSessionId) {
				expect(await validateSession(result.newSessionId)).toBe(true);
			}
		} finally {
			resetSessions();
		}
	});

	it('behaves normally when initializing without an existing session', async () => {
		const { dispatchMcpMethod } = await import('../src/mcp/dispatch');
		const { validateSession, resetSessions } = await import('../src/lib/session');

		try {
			const result = await dispatchMcpMethod({
				id: 1,
				method: 'initialize',
				params: undefined,
				ip: '198.51.100.1',
				isAuthenticated: true,
				rateHeaders: {},
				serverVersion: '1.0.0',
				createSessionOnInitialize: true,
			});

			expect(result.kind).toBe('success');
			if (result.kind === 'success') {
				expect(result.newSessionId).toBeDefined();
				expect(await validateSession(result.newSessionId!)).toBe(true);
			}
		} finally {
			resetSessions();
		}
	});

	it('does not delete old session when createSessionOnInitialize is false', async () => {
		const { dispatchMcpMethod } = await import('../src/mcp/dispatch');
		const { createSession, validateSession, resetSessions } = await import('../src/lib/session');

		try {
			const oldSessionId = await createSession();

			const result = await dispatchMcpMethod({
				id: 1,
				method: 'initialize',
				params: undefined,
				ip: '198.51.100.1',
				isAuthenticated: true,
				rateHeaders: {},
				serverVersion: '1.0.0',
				createSessionOnInitialize: false,
				existingSessionId: oldSessionId,
			});

			expect(result.kind).toBe('success');
			// Old session should still be valid (legacy path doesn't create new sessions)
			expect(await validateSession(oldSessionId)).toBe(true);
		} finally {
			resetSessions();
		}
	});
});
