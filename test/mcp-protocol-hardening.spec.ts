import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import worker from '../src';
import { resetQuotaCoordinatorState } from '../src/lib/quota-coordinator';
import { resetAllRateLimits, resetAllRateLimitsKv } from '../src/lib/rate-limiter';
import { resetLegacySseState } from '../src/lib/legacy-sse';
import { resetSessions } from '../src/lib/session';
import { parseJsonRpcRequest, validateJsonRpcRequest } from '../src/mcp/request';

type RpcError = { jsonrpc: string; id: unknown; error: { code: number; message: string } };

async function post(rawBody: string, headers: Record<string, string> = {}): Promise<Response> {
	const request = new Request('http://example.com/mcp', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', ...headers },
		body: rawBody,
	});
	const ctx = createExecutionContext();
	const response = await worker.fetch(request, env, ctx);
	await waitOnExecutionContext(ctx);
	return response;
}

async function initSession(): Promise<string> {
	const response = await post(JSON.stringify({ jsonrpc: '2.0', id: 0, method: 'initialize', params: {} }));
	const sessionId = response.headers.get('mcp-session-id');
	if (!sessionId) throw new Error('initSession: no Mcp-Session-Id returned');
	return sessionId;
}

/** Extract the JSON payload out of a single-event SSE body. */
function parseSse(text: string): { id?: string; payload: RpcError } {
	const idLine = text.split('\n').find((line) => line.startsWith('id: '));
	const dataLine = text.split('\n').find((line) => line.startsWith('data: '));
	if (!dataLine) throw new Error(`No SSE data line in: ${text}`);
	return { id: idLine?.slice(4), payload: JSON.parse(dataLine.slice(6)) as RpcError };
}

beforeEach(async () => {
	resetAllRateLimits();
	resetSessions();
	resetLegacySseState();
	await resetQuotaCoordinatorState(env.QUOTA_COORDINATOR);
	await resetAllRateLimitsKv(env.RATE_LIMIT);
});

afterEach(() => {
	vi.restoreAllMocks();
});

describe('mcp-protocol-hardening: non-object single request body (item 1)', () => {
	it.each(['null', '5', '"hello"', 'true', '1.5'])('POST /mcp body %s returns 400 / -32600 / id null', async (raw) => {
		const response = await post(raw);
		expect(response.status).toBe(400);
		const body = (await response.json()) as RpcError;
		expect(body.error.code).toBe(-32600);
		expect(body.id).toBeNull();
	});

	it('POST /mcp body null over SSE returns a 400 error event with id null', async () => {
		const response = await post('null', { Accept: 'text/event-stream' });
		expect(response.status).toBe(400);
		const { payload } = parseSse(await response.text());
		expect(payload.error.code).toBe(-32600);
		expect(payload.id).toBeNull();
	});

	it('parseJsonRpcRequest rejects a bare null / primitive body', () => {
		for (const raw of ['null', '0', '"x"', 'false']) {
			const result = parseJsonRpcRequest(raw);
			expect(result.ok).toBe(false);
			expect(result.status).toBe(400);
			expect(result.payload?.error.code).toBe(-32600);
			expect(result.payload?.id).toBeNull();
		}
	});

	it('validateJsonRpcRequest does not throw on null', () => {
		const result = validateJsonRpcRequest(null as never);
		expect(result?.status).toBe(400);
		expect(result?.payload.id).toBeNull();
	});
});

describe('mcp-protocol-hardening: missing / mistyped params (item 2)', () => {
	it.each(['tools/call', 'resources/read', 'prompts/get'])('%s without params returns -32602 with the request id preserved', async (method) => {
		const sessionId = await initSession();
		const response = await post(JSON.stringify({ jsonrpc: '2.0', id: 77, method }), { 'Mcp-Session-Id': sessionId });
		expect(response.status).not.toBe(500);
		const body = (await response.json()) as RpcError;
		expect(body.id).toBe(77);
		expect(body.error.code).toBe(-32602);
	});

	it('tools/call with a non-string name returns -32602 with id preserved', async () => {
		const sessionId = await initSession();
		const response = await post(JSON.stringify({ jsonrpc: '2.0', id: 78, method: 'tools/call', params: { name: 42 } }), {
			'Mcp-Session-Id': sessionId,
		});
		expect(response.status).not.toBe(500);
		const body = (await response.json()) as RpcError;
		expect(body.id).toBe(78);
		expect(body.error.code).toBe(-32602);
	});

	it('tools/call without params over SSE does not emit an id:null internal-error event', async () => {
		const sessionId = await initSession();
		const response = await post(JSON.stringify({ jsonrpc: '2.0', id: 79, method: 'tools/call' }), {
			'Mcp-Session-Id': sessionId,
			Accept: 'text/event-stream',
		});
		const { payload } = parseSse(await response.text());
		expect(payload.id).toBe(79);
		expect(payload.error.code).toBe(-32602);
	});
});

describe('mcp-protocol-hardening: invalid JSON-RPC id is not echoed (item 5)', () => {
	it.each([
		['object', { a: 1 }],
		['array', [1, 2]],
	])('%s id yields id null in the error body', async (_label, id) => {
		const response = await post(JSON.stringify({ jsonrpc: '2.0', id, method: 'ping' }));
		expect(response.status).toBe(400);
		const body = (await response.json()) as RpcError;
		expect(body.error.code).toBe(-32600);
		expect(body.id).toBeNull();
	});

	it('invalid id yields id null in the SSE payload and no SSE event id', async () => {
		const response = await post(JSON.stringify({ jsonrpc: '2.0', id: { a: 1 }, method: 'ping' }), { Accept: 'text/event-stream' });
		expect(response.status).toBe(400);
		const text = await response.text();
		expect(text).not.toContain('[object Object]');
		const { id, payload } = parseSse(text);
		expect(id).toBeUndefined();
		expect(payload.id).toBeNull();
	});

	it('a valid id is still echoed when another field is invalid', async () => {
		const response = await post(JSON.stringify({ jsonrpc: '1.0', id: 12, method: 'ping' }));
		expect(response.status).toBe(400);
		const body = (await response.json()) as RpcError;
		expect(body.id).toBe(12);
	});

	it('a fractional numeric id is a JSON number and is echoed unchanged (not-a-bug probe)', async () => {
		const sessionId = await initSession();
		const response = await post(JSON.stringify({ jsonrpc: '2.0', id: 1.5, method: 'ping' }), { 'Mcp-Session-Id': sessionId });
		expect(response.status).toBe(200);
		const body = (await response.json()) as { id: unknown };
		expect(body.id).toBe(1.5);
	});
});

describe('mcp-protocol-hardening: one-element initialize batch session header (item 6)', () => {
	it('[initialize] batch returns the Mcp-Session-Id header', async () => {
		const response = await post(JSON.stringify([{ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }]));
		expect(response.status).toBe(200);
		const body = (await response.json()) as Array<{ id: number; result?: unknown }>;
		expect(body).toHaveLength(1);
		expect(body[0]?.result).toBeTruthy();
		const sessionId = response.headers.get('mcp-session-id');
		expect(sessionId).toBeTruthy();
		expect(sessionId!.length).toBeGreaterThanOrEqual(32);
	});

	it('[initialize] batch over SSE also carries the Mcp-Session-Id header', async () => {
		const response = await post(JSON.stringify([{ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }]), {
			Accept: 'text/event-stream',
		});
		expect(response.status).toBe(200);
		expect(response.headers.get('mcp-session-id')).toBeTruthy();
	});

	it('a non-initialize batch does not emit a session header', async () => {
		const sessionId = await initSession();
		const response = await post(JSON.stringify([{ jsonrpc: '2.0', id: 2, method: 'ping', params: {} }]), {
			'Mcp-Session-Id': sessionId,
		});
		expect(response.status).toBe(200);
		expect(response.headers.get('mcp-session-id')).toBeNull();
	});
});
