import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createExecutionContext, env, waitOnExecutionContext } from 'cloudflare:test';
import worker from '../src';
import { resetAllRateLimits } from '../src/lib/rate-limiter';
import { resetSessions } from '../src/lib/session';
import { resetLegacySseState } from '../src/lib/legacy-sse';
import { ACTIVE_SESSIONS } from '../src/lib/session-memory';

beforeEach(() => {
	resetAllRateLimits();
	resetSessions();
	resetLegacySseState();
});

afterEach(() => {
	vi.restoreAllMocks();
});

async function fetchMcp(body: object, sessionId?: string): Promise<Response> {
	const headers = new Headers({ 'Content-Type': 'application/json' });
	if (sessionId) headers.set('Mcp-Session-Id', sessionId);
	const ctx = createExecutionContext();
	const response = await worker.fetch(
		new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
			method: 'POST',
			headers,
			body: JSON.stringify(body),
		}),
		env,
		ctx,
	);
	await waitOnExecutionContext(ctx);
	return response;
}

async function initSession(): Promise<string> {
	const response = await fetchMcp({ jsonrpc: '2.0', id: 0, method: 'initialize', params: {} });
	const sessionId = response.headers.get('mcp-session-id');
	if (!sessionId) throw new Error('initSession: no Mcp-Session-Id returned');
	return sessionId;
}

describe('Unknown session handling', () => {
	it('accepts a session ID assigned by initialize', async () => {
		const sessionId = await initSession();
		const response = await fetchMcp({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }, sessionId);

		expect(response.status).toBe(200);
		expect(ACTIVE_SESSIONS.has(sessionId)).toBe(true);
	});

	it('rejects an arbitrary valid-shaped session ID without creating it', async () => {
		const attackerChosenId = 'a'.repeat(64);
		const response = await fetchMcp(
			{
				jsonrpc: '2.0',
				id: 2,
				method: 'tools/call',
				params: { name: 'explain_finding', arguments: { finding_id: 'spf_softfail' } },
			},
			attackerChosenId,
		);

		expect(response.status).toBe(404);
		expect(ACTIVE_SESSIONS.has(attackerChosenId)).toBe(false);
	});

	it('rejects a notification carrying an arbitrary valid-shaped session ID', async () => {
		const attackerChosenId = 'b'.repeat(64);
		const response = await fetchMcp({ jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: 1 } }, attackerChosenId);

		expect(response.status).toBe(404);
		expect(ACTIVE_SESSIONS.has(attackerChosenId)).toBe(false);
	});

	it('rejects a malformed session ID without creating it', async () => {
		const response = await fetchMcp(
			{
				jsonrpc: '2.0',
				id: 3,
				method: 'tools/call',
				params: { name: 'explain_finding', arguments: { finding_id: 'spf_softfail' } },
			},
			'not-a-valid-hex-id',
		);

		expect(response.status).toBe(404);
		expect(ACTIVE_SESSIONS.has('not-a-valid-hex-id')).toBe(false);
	});
});
