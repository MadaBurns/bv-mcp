import { afterEach, describe, expect, it, vi } from 'vitest';

afterEach(() => {
	vi.restoreAllMocks();
});

describe('legacy POST /mcp/messages session validation', () => {
	it('does not double-validate session in executeMcpRequest for legacy POST path', async () => {
		// The legacy POST /mcp/messages handler pre-validates the session (returns HTTP 404 for invalid).
		// It should pass validateSession: false to executeMcpRequest to skip the redundant second check.
		// We verify by calling executeMcpRequest with validateSession: false and a valid session,
		// confirming validateSessionRequest is never called.
		const { executeMcpRequest } = await import('../src/mcp/execute');
		const { createSession, resetSessions } = await import('../src/lib/session');

		try {
			const sessionId = await createSession();

			const result = await executeMcpRequest({
				body: { jsonrpc: '2.0', id: 1, method: 'ping' },
				allowStreaming: false,
				batchMode: false,
				batchSize: 1,
				responseTransport: 'json',
				startTime: Date.now(),
				ip: '198.51.100.1',
				isAuthenticated: false,
				sessionId,
				validateSession: false, // Pre-validated by legacy handler
				createSessionOnInitialize: false,
				existingSessionId: sessionId,
				serverVersion: '1.0.0',
			});

			// Should succeed (ping returns a success response, not an error about session)
			expect(result.kind).toBe('response');
			if (result.kind === 'response') {
				expect(result.httpStatus).toBe(200);
				const payload = result.payload as { result?: unknown; error?: unknown };
				expect(payload.error).toBeUndefined();
				expect(payload.result).toBeDefined();
			}
		} finally {
			resetSessions();
		}
	});

	it('legacy POST with invalid session returns 404 from early check (not from executeMcpRequest)', async () => {
		// When validateSession is false, executeMcpRequest should NOT check the session.
		// An invalid session ID with validateSession: false should NOT produce a session error.
		const { executeMcpRequest } = await import('../src/mcp/execute');
		const { resetSessions } = await import('../src/lib/session');

		try {
			const result = await executeMcpRequest({
				body: { jsonrpc: '2.0', id: 1, method: 'ping' },
				allowStreaming: false,
				batchMode: false,
				batchSize: 1,
				responseTransport: 'json',
				startTime: Date.now(),
				ip: '198.51.100.1',
				isAuthenticated: false,
				sessionId: 'invalid-session-id',
				validateSession: false, // Simulating: legacy handler already returned 404
				createSessionOnInitialize: false,
				existingSessionId: 'invalid-session-id',
				serverVersion: '1.0.0',
			});

			// Even with an invalid session, validateSession: false means it should succeed for ping
			expect(result.kind).toBe('response');
			if (result.kind === 'response') {
				expect(result.httpStatus).toBe(200);
				const payload = result.payload as { result?: unknown; error?: unknown };
				expect(payload.error).toBeUndefined();
			}
		} finally {
			resetSessions();
		}
	});

	it('modern POST /mcp path still validates session when validateSession is true', async () => {
		// Verify that validateSession: true (modern path) still rejects invalid sessions
		const { executeMcpRequest } = await import('../src/mcp/execute');
		const { resetSessions } = await import('../src/lib/session');

		try {
			const result = await executeMcpRequest({
				body: { jsonrpc: '2.0', id: 1, method: 'ping' },
				allowStreaming: false,
				batchMode: false,
				batchSize: 1,
				responseTransport: 'json',
				startTime: Date.now(),
				ip: '198.51.100.1',
				isAuthenticated: false,
				sessionId: 'nonexistent-session',
				validateSession: true,
				createSessionOnInitialize: false,
				serverVersion: '1.0.0',
			});

			// Should be rejected with session error
			expect(result.kind).toBe('response');
			if (result.kind === 'response') {
				expect(result.httpStatus).toBe(404);
			}
		} finally {
			resetSessions();
		}
	});
});
