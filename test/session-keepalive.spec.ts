import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import worker from '../src';
import { resetAllRateLimits } from '../src/lib/rate-limiter';
import { resetSessions, SESSION_TTL_MS, SESSION_REFRESH_INTERVAL_MS } from '../src/lib/session';
import { resetLegacySseState, openLegacySseStream } from '../src/lib/legacy-sse';
import {
	ACTIVE_SESSIONS,
	createSessionInMemory,
	validateSessionInMemory,
} from '../src/lib/session-memory';
import { detectMcpClient } from '../src/lib/client-detection';
import type { McpClientType } from '../src/lib/client-detection';

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

/** Read a single chunk from a response stream */
async function readSseChunk(response: Response): Promise<string> {
	const reader = response.body?.getReader();
	if (!reader) throw new Error('Expected response body stream');
	const { value, done } = await reader.read();
	reader.releaseLock();
	if (done || !value) throw new Error('Expected SSE chunk');
	return new TextDecoder().decode(value);
}

// ─── Session TTL refresh (fake timers) ──────────────────────────────

describe('Session keep-alive - TTL refresh', () => {
	it('session validates within 30-minute window', () => {
		const base = 1_700_000_000_000;
		const nowSpy = vi.spyOn(Date, 'now').mockReturnValue(base);
		createSessionInMemory('keep-alive-1');

		// 29 minutes later — still valid
		nowSpy.mockReturnValue(base + SESSION_TTL_MS - 60_000);
		expect(validateSessionInMemory('keep-alive-1')).toBe(true);
	});

	it('activity refreshes lastAccessedAt (sliding TTL)', () => {
		const base = 1_700_000_000_000;
		const nowSpy = vi.spyOn(Date, 'now').mockReturnValue(base);
		createSessionInMemory('sliding-1');

		// 6 minutes later — past refresh interval, triggers refresh
		nowSpy.mockReturnValue(base + SESSION_REFRESH_INTERVAL_MS + 60_000);
		expect(validateSessionInMemory('sliding-1')).toBe(true);
		expect(ACTIVE_SESSIONS.get('sliding-1')?.lastAccessedAt).toBe(base + SESSION_REFRESH_INTERVAL_MS + 60_000);

		// 30 minutes after the refresh — should still be valid (TTL slides)
		nowSpy.mockReturnValue(base + SESSION_REFRESH_INTERVAL_MS + 60_000 + SESSION_TTL_MS - 60_000);
		expect(validateSessionInMemory('sliding-1')).toBe(true);
	});

	it('session expires after 30 minutes of inactivity', () => {
		const base = 1_700_000_000_000;
		const nowSpy = vi.spyOn(Date, 'now').mockReturnValue(base);
		createSessionInMemory('expire-1');

		// Exactly 30 min + 1ms later — expired
		nowSpy.mockReturnValue(base + SESSION_TTL_MS + 1);
		expect(validateSessionInMemory('expire-1')).toBe(false);
		expect(ACTIVE_SESSIONS.has('expire-1')).toBe(false);
	});

	it('validation within refresh interval does not update lastAccessedAt', () => {
		const base = 1_700_000_000_000;
		const nowSpy = vi.spyOn(Date, 'now').mockReturnValue(base);
		createSessionInMemory('no-refresh-1');

		// 2 minutes later — within refresh interval
		nowSpy.mockReturnValue(base + 2 * 60_000);
		expect(validateSessionInMemory('no-refresh-1')).toBe(true);
		// lastAccessedAt should NOT have been updated
		expect(ACTIVE_SESSIONS.get('no-refresh-1')?.lastAccessedAt).toBe(base);
	});
});

// ─── Session expiry → 404 (integration) ────────────────────────────

describe('Session keep-alive - Expiry returns 404', () => {
	it('POST /mcp with expired session returns HTTP 404', async () => {
		const sessionId = await initSession();

		// Terminate the session to simulate expiry
		const delReq = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
			method: 'DELETE',
			headers: { 'Mcp-Session-Id': sessionId },
		});
		const delCtx = createExecutionContext();
		await worker.fetch(delReq, env, delCtx);
		await waitOnExecutionContext(delCtx);

		// Request with expired session
		const req = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'Mcp-Session-Id': sessionId,
			},
			body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
		});
		const ctx = createExecutionContext();
		const res = await worker.fetch(req, env, ctx);
		await waitOnExecutionContext(ctx);

		expect(res.status).toBe(404);
	});

	it('SSE-accepting client gets 404 with SSE-formatted error body', async () => {
		const sessionId = await initSession();

		// Terminate session
		const delReq = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
			method: 'DELETE',
			headers: { 'Mcp-Session-Id': sessionId },
		});
		const delCtx = createExecutionContext();
		await worker.fetch(delReq, env, delCtx);
		await waitOnExecutionContext(delCtx);

		// SSE-accepting request with expired session
		const req = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Accept: 'text/event-stream',
				'Mcp-Session-Id': sessionId,
			},
			body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
		});
		const ctx = createExecutionContext();
		const res = await worker.fetch(req, env, ctx);
		await waitOnExecutionContext(ctx);

		expect(res.status).toBe(404);
		expect(res.headers.get('content-type')).toBe('text/event-stream');
		const body = await res.text();
		expect(body).toContain('event: message');
		expect(body).toContain('session expired or terminated');
	});

	it('client can re-initialize after session expiry', async () => {
		const sessionId = await initSession();

		// Terminate session
		const delReq = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
			method: 'DELETE',
			headers: { 'Mcp-Session-Id': sessionId },
		});
		const delCtx = createExecutionContext();
		await worker.fetch(delReq, env, delCtx);
		await waitOnExecutionContext(delCtx);

		// Confirm expired
		const expiredReq = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'Mcp-Session-Id': sessionId,
			},
			body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
		});
		const expiredCtx = createExecutionContext();
		const expiredRes = await worker.fetch(expiredReq, env, expiredCtx);
		await waitOnExecutionContext(expiredCtx);
		expect(expiredRes.status).toBe(404);

		// Re-initialize — should get a new session
		const newSessionId = await initSession();
		expect(newSessionId).toBeTruthy();
		expect(newSessionId).not.toBe(sessionId);

		// New session works
		const req = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'Mcp-Session-Id': newSessionId,
			},
			body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }),
		});
		const ctx = createExecutionContext();
		const res = await worker.fetch(req, env, ctx);
		await waitOnExecutionContext(ctx);
		expect(res.status).toBe(200);
	});
});

// ─── Legacy SSE transport ───────────────────────────────────────────

describe('Session keep-alive - Legacy SSE heartbeat', () => {
	it('legacy SSE bootstrap stream emits endpoint event', async () => {
		const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp/sse', {
			method: 'GET',
			headers: { Accept: 'text/event-stream' },
		});
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);

		expect(response.status).toBe(200);
		expect(response.headers.get('content-type')).toBe('text/event-stream');
		expect(response.headers.get('mcp-session-id')).toBeTruthy();

		const chunk = await readSseChunk(response);
		expect(chunk).toContain('event: endpoint');
		expect(chunk).toContain('/mcp/messages?sessionId=');
	});

	it('openLegacySseStream emits heartbeats at 5s intervals (fake timers)', async () => {
		vi.useFakeTimers();

		const response = openLegacySseStream('legacy-hb-test', 'http://example.com/mcp/messages?sessionId=legacy-hb-test');
		const reader = response.body!.getReader();

		// First chunk is the endpoint event
		const endpoint = await reader.read();
		const endpointText = new TextDecoder().decode(endpoint.value);
		expect(endpointText).toContain('event: endpoint');

		// Advance 5s — should get heartbeat
		vi.advanceTimersByTime(5_000);
		const hb1 = await reader.read();
		expect(new TextDecoder().decode(hb1.value)).toBe(': heartbeat\n\n');

		// Advance another 5s — second heartbeat
		vi.advanceTimersByTime(5_000);
		const hb2 = await reader.read();
		expect(new TextDecoder().decode(hb2.value)).toBe(': heartbeat\n\n');

		reader.releaseLock();
		resetLegacySseState();
	});

	it('legacy POST /mcp/messages delivers response to SSE stream', async () => {
		// Open bootstrap stream
		const openReq = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp/sse', {
			method: 'GET',
			headers: { Accept: 'text/event-stream' },
		});
		const openCtx = createExecutionContext();
		const streamRes = await worker.fetch(openReq, env, openCtx);
		await waitOnExecutionContext(openCtx);

		const endpointChunk = await readSseChunk(streamRes);
		const dataLine = endpointChunk.split('\n').find((l) => l.startsWith('data: '));
		const endpoint = dataLine!.slice('data: '.length);
		const sessionId = streamRes.headers.get('mcp-session-id')!;

		// Send initialize via legacy POST
		const initReq = new Request<unknown, IncomingRequestCfProperties>(endpoint, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
		});
		const initCtx = createExecutionContext();
		const initRes = await worker.fetch(initReq, env, initCtx);
		await waitOnExecutionContext(initCtx);

		// Legacy transport returns 202 (response delivered via SSE stream)
		expect(initRes.status).toBe(202);

		// Read the response from the SSE stream
		const messageChunk = await readSseChunk(streamRes);
		expect(messageChunk).toContain('event: message');
		expect(messageChunk).toContain('"protocolVersion"');
		expect(messageChunk).toContain('"Blackveil DNS"');

		// Clean up: terminate session
		const delReq = new Request<unknown, IncomingRequestCfProperties>(`http://example.com/mcp?sessionId=${sessionId}`, {
			method: 'DELETE',
		});
		const delCtx = createExecutionContext();
		await worker.fetch(delReq, env, delCtx);
		await waitOnExecutionContext(delCtx);
	});
});

// ─── Client detection tagging ───────────────────────────────────────

describe('Session keep-alive - Client detection', () => {
	const CLIENT_CASES: Array<[string, McpClientType]> = [
		['claude-code/1.0.0', 'claude_code'],
		['Claude_Code/2.0', 'claude_code'],
		['claudecode/1.0', 'claude_code'],
		['Claude-Desktop/1.0', 'claude_desktop'],
		['claude_desktop/0.5', 'claude_desktop'],
		['Cursor/0.48.0', 'cursor'],
		['cursor-mcp/1.0', 'cursor'],
		['Windsurf/1.0', 'windsurf'],
		['Visual Studio Code/1.95.0', 'vscode'],
		['vscode-mcp/1.0', 'vscode'],
		['GitHub Copilot/1.0', 'vscode'],
		['mcp-remote/1.0', 'mcp_remote'],
	];

	it.each(CLIENT_CASES)('detects "%s" as %s', (userAgent, expected) => {
		expect(detectMcpClient(userAgent)).toBe(expected);
	});

	it('returns "unknown" for missing User-Agent', () => {
		expect(detectMcpClient(undefined)).toBe('unknown');
		expect(detectMcpClient('')).toBe('unknown');
	});

	it('returns "unknown" for unrecognized User-Agent', () => {
		expect(detectMcpClient('Mozilla/5.0')).toBe('unknown');
		expect(detectMcpClient('MyCustomClient/1.0')).toBe('unknown');
	});

	it('detection is case-insensitive', () => {
		expect(detectMcpClient('CLAUDE-CODE/1.0')).toBe('claude_code');
		expect(detectMcpClient('CURSOR/1.0')).toBe('cursor');
		expect(detectMcpClient('WINDSURF/1.0')).toBe('windsurf');
		expect(detectMcpClient('MCP-REMOTE/1.0')).toBe('mcp_remote');
	});

	it('first match wins when User-Agent contains multiple patterns', () => {
		// claude_code pattern comes before cursor in CLIENT_PATTERNS
		expect(detectMcpClient('claude-code cursor hybrid')).toBe('claude_code');
	});
});
