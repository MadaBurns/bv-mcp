import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import worker from '../src';
import { resetAllRateLimits } from '../src/lib/rate-limiter';
import { resetSessions } from '../src/lib/session';
import { resetLegacySseState } from '../src/lib/legacy-sse';
import { ACTIVE_SESSIONS } from '../src/lib/session-memory';

beforeEach(async () => {
	resetAllRateLimits();
	resetSessions();
	resetLegacySseState();
});

afterEach(() => {
	vi.useRealTimers();
	vi.restoreAllMocks();
});

/** Helper: initialize a session and return the Mcp-Session-Id */
async function initSession(): Promise<string> {
	const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ jsonrpc: '2.0', id: 0, method: 'initialize', params: {} }),
	});
	const ctx = createExecutionContext();
	const response = await worker.fetch(request, env, ctx);
	await waitOnExecutionContext(ctx);
	const sessionId = response.headers.get('mcp-session-id');
	if (!sessionId) throw new Error('initSession: no Mcp-Session-Id returned');
	return sessionId;
}

/** Helper: delete a session to simulate expiry */
async function deleteSession(sessionId: string): Promise<void> {
	const delReq = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
		method: 'DELETE',
		headers: { 'Mcp-Session-Id': sessionId },
	});
	const delCtx = createExecutionContext();
	await worker.fetch(delReq, env, delCtx);
	await waitOnExecutionContext(delCtx);
}

describe('Session expiration recovery', () => {
	it('revives expired session on tools/call using the same session ID', async () => {
		const sessionId = await initSession();

		// Terminate the session to simulate expiry
		await deleteSession(sessionId);

		// Confirm session is expired
		expect(ACTIVE_SESSIONS.has(sessionId)).toBe(false);

		// Send a tools/call with the expired session — should auto-recover
		const req = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'Mcp-Session-Id': sessionId,
			},
			body: JSON.stringify({
				jsonrpc: '2.0',
				id: 1,
				method: 'tools/call',
				params: { name: 'check_spf', arguments: { domain: 'example.com' } },
			}),
		});
		const ctx = createExecutionContext();
		const res = await worker.fetch(req, env, ctx);
		await waitOnExecutionContext(ctx);

		// Should succeed (not 404)
		expect(res.status).toBe(200);
		const body = (await res.json()) as { result?: { content: Array<{ text: string }> }; error?: unknown };
		expect(body.error).toBeUndefined();
		expect(body.result).toBeDefined();

		// The session should be revived in memory with the SAME ID
		expect(ACTIVE_SESSIONS.has(sessionId)).toBe(true);
	});

	it('does not return a new session ID header on recovery', async () => {
		const sessionId = await initSession();
		await deleteSession(sessionId);

		const req = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'Mcp-Session-Id': sessionId,
			},
			body: JSON.stringify({
				jsonrpc: '2.0',
				id: 2,
				method: 'tools/call',
				params: { name: 'check_spf', arguments: { domain: 'example.com' } },
			}),
		});
		const ctx = createExecutionContext();
		const res = await worker.fetch(req, env, ctx);
		await waitOnExecutionContext(ctx);

		expect(res.status).toBe(200);

		// No mcp-session-id header should be returned (client already has it)
		const returnedSessionId = res.headers.get('mcp-session-id');
		expect(returnedSessionId).toBeNull();
	});

	it('subsequent requests with the same session ID succeed after recovery', async () => {
		const sessionId = await initSession();
		await deleteSession(sessionId);

		// First tools/call triggers recovery
		const req1 = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'Mcp-Session-Id': sessionId,
			},
			body: JSON.stringify({
				jsonrpc: '2.0',
				id: 3,
				method: 'tools/call',
				params: { name: 'check_spf', arguments: { domain: 'example.com' } },
			}),
		});
		const ctx1 = createExecutionContext();
		const res1 = await worker.fetch(req1, env, ctx1);
		await waitOnExecutionContext(ctx1);
		expect(res1.status).toBe(200);

		// Second request with the same session ID should also succeed
		const req2 = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'Mcp-Session-Id': sessionId,
			},
			body: JSON.stringify({
				jsonrpc: '2.0',
				id: 4,
				method: 'tools/call',
				params: { name: 'check_spf', arguments: { domain: 'example.com' } },
			}),
		});
		const ctx2 = createExecutionContext();
		const res2 = await worker.fetch(req2, env, ctx2);
		await waitOnExecutionContext(ctx2);
		expect(res2.status).toBe(200);
		const body2 = (await res2.json()) as { result?: unknown; error?: unknown };
		expect(body2.error).toBeUndefined();
		expect(body2.result).toBeDefined();
	});

	it('does not recover expired sessions for tools/list (only tools/call)', async () => {
		const sessionId = await initSession();
		await deleteSession(sessionId);

		const req = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'Mcp-Session-Id': sessionId,
			},
			body: JSON.stringify({
				jsonrpc: '2.0',
				id: 5,
				method: 'tools/list',
				params: {},
			}),
		});
		const ctx = createExecutionContext();
		const res = await worker.fetch(req, env, ctx);
		await waitOnExecutionContext(ctx);

		// tools/list should NOT trigger recovery — returns 404
		expect(res.status).toBe(404);
	});

	it('rejects recovery for malformed session IDs', async () => {
		const req = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'Mcp-Session-Id': 'not-a-valid-hex-id',
			},
			body: JSON.stringify({
				jsonrpc: '2.0',
				id: 6,
				method: 'tools/call',
				params: { name: 'check_spf', arguments: { domain: 'example.com' } },
			}),
		});
		const ctx = createExecutionContext();
		const res = await worker.fetch(req, env, ctx);
		await waitOnExecutionContext(ctx);

		// Malformed session IDs should NOT trigger recovery
		expect(res.status).toBe(404);
		expect(ACTIVE_SESSIONS.has('not-a-valid-hex-id')).toBe(false);
	});
});
