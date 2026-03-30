import { env, createExecutionContext, waitOnExecutionContext, SELF } from 'cloudflare:test';
import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import worker from '../src';
import { resetQuotaCoordinatorState } from '../src/lib/quota-coordinator';
import { resetAllRateLimits } from '../src/lib/rate-limiter';
import { resetLegacySseState } from '../src/lib/legacy-sse';
import { resetSessions } from '../src/lib/session';

const TEST_API_KEY = 'test-api-key';

function parseSseMessage<T>(body: string): T {
	const dataLine = body
		.split('\n')
		.find((line) => line.startsWith('data: '));
	if (!dataLine) throw new Error(`Expected SSE data line in response: ${body}`);
	return JSON.parse(dataLine.slice('data: '.length)) as T;
}

function parseSseEvent(body: string, eventName: string): string {
	const lines = body.split('\n');
	const eventLineIndex = lines.findIndex((line) => line === `event: ${eventName}`);
	if (eventLineIndex === -1) {
		throw new Error(`Expected SSE event ${eventName} in response: ${body}`);
	}

	const dataLine = lines.slice(eventLineIndex + 1).find((line) => line.startsWith('data: '));
	if (!dataLine) {
		throw new Error(`Expected SSE data line for event ${eventName}: ${body}`);
	}

	return dataLine.slice('data: '.length);
}

async function readSseChunk(response: Response): Promise<string> {
	const reader = response.body?.getReader();
	if (!reader) throw new Error('Expected response body stream');
	const { value, done } = await reader.read();
	reader.releaseLock();
	if (done || !value) throw new Error('Expected SSE chunk');
	return new TextDecoder().decode(value);
}

/** Helper: initialize a session and return the Mcp-Session-Id */
async function initSession(options?: { authToken?: string; targetEnv?: Env }): Promise<string> {
	const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			...(options?.authToken ? { Authorization: `Bearer ${options.authToken}` } : {}),
		},
		body: JSON.stringify({ jsonrpc: '2.0', id: 0, method: 'initialize', params: {} }),
	});
	const ctx = createExecutionContext();
	const response = await worker.fetch(request, options?.targetEnv ?? env, ctx);
	await waitOnExecutionContext(ctx);
	const sessionId = response.headers.get('mcp-session-id');
	if (!sessionId) throw new Error('initSession: no Mcp-Session-Id returned');
	return sessionId;
}

describe('DNS Security MCP Server', () => {
	describe('POST /mcp - body size limit', () => {
		it('returns 413 Payload Too Large for requests over 10KB', async () => {
			const bigString = 'a'.repeat(10 * 1024);
			const payload = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { big: bigString } });
			expect(Buffer.byteLength(payload)).toBeGreaterThan(10 * 1024);
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: payload,
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(413);
			const body = await response.text();
			expect(body).toMatch(/too large|payload/i);
		});
	});

	beforeEach(async () => {
		resetAllRateLimits();
		resetSessions();
		resetLegacySseState();
		await resetQuotaCoordinatorState(env.QUOTA_COORDINATOR);
	});

		afterEach(() => {
			vi.restoreAllMocks();
		});

	describe('POST /mcp - Content-Type validation', () => {
		it('accepts application/json', async () => {
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(200);
		});

		it('accepts application/json with charset parameter', async () => {
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json; charset=utf-8' },
				body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(200);
		});

		it('accepts missing Content-Type for client compatibility', async () => {
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
			});
			// Fetch API defaults string body to text/plain — strip it to simulate no Content-Type
			request.headers.delete('content-type');
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(200);
		});

		it('rejects text/plain with 415', async () => {
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: { 'Content-Type': 'text/plain' },
				body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(415);
			const body = await response.text();
			expect(body).toContain('Unsupported Media Type');
		});

		it('rejects multipart/form-data with 415', async () => {
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: { 'Content-Type': 'multipart/form-data' },
				body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(415);
		});

		it('rejects application/xml with 415', async () => {
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: { 'Content-Type': 'application/xml' },
				body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(415);
		});
	});

	describe('POST /mcp - optional bearer auth', () => {
		it('runs unauthenticated when BV_API_KEY is unset/empty', async () => {
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(200);
		});

		it('allows missing bearer token through as unauthenticated when auth is configured', async () => {
			const authEnv = { ...env, BV_API_KEY: TEST_API_KEY } as Env;
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, authEnv, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(200);
			expect(response.headers.get('mcp-session-id')).toBeTruthy();
		});

		it('returns 401 JSON-RPC error when auth token is invalid', async () => {
			const authEnv = { ...env, BV_API_KEY: TEST_API_KEY } as Env;
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					Authorization: 'Bearer wrong-token',
				},
				body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, authEnv, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(401);
			const body = (await response.json()) as { error: { code: number } };
			expect(body.error.code).toBe(-32001);
		});

		it('accepts valid bearer token when auth is required', async () => {
			const authEnv = { ...env, BV_API_KEY: TEST_API_KEY } as Env;
			const sessionId = await initSession({ authToken: TEST_API_KEY, targetEnv: authEnv });
			expect(sessionId).toBeTruthy();
		});
	});

	describe('GET /health', () => {
		it('returns status ok (unit style)', async () => {
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/health');
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(200);
			const body = (await response.json()) as { status: string; service: string };
			expect(body.status).toBe('ok');
			expect(body.service).toBe('bv-dns-security-mcp');
		});

		it('returns status ok (integration style)', async () => {
			const response = await SELF.fetch('http://example.com/health');
			expect(response.status).toBe(200);
			const body = (await response.json()) as { status: string; service: string };
			expect(body.status).toBe('ok');
			expect(body.service).toBe('bv-dns-security-mcp');
		});
	});

	describe('POST /mcp - initialize', () => {
		it('returns server info, capabilities, and Mcp-Session-Id header', async () => {
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(200);
			const body = (await response.json()) as {
				jsonrpc: string;
				id: number;
				result: {
					protocolVersion: string;
					serverInfo: { name: string; description: string };
					instructions: string;
					capabilities: { prompts: { listChanged: boolean } };
				};
			};
			expect(body.jsonrpc).toBe('2.0');
			expect(body.id).toBe(1);
			expect(body.result.serverInfo.name).toBe('Blackveil DNS');
			expect(body.result.serverInfo.description).toBeTruthy();
			expect(body.result.protocolVersion).toBe('2025-03-26');
			expect(typeof body.result.instructions).toBe('string');
			expect(body.result.instructions.length).toBeGreaterThan(0);
			expect(body.result.capabilities.prompts).toEqual({ listChanged: false });
			const sessionId = response.headers.get('mcp-session-id');
			expect(sessionId).toBeTruthy();
			expect(sessionId!.length).toBeGreaterThanOrEqual(32);
		});

		it('throttles excessive initialize calls from one IP', async () => {
			let lastResponse: Response | undefined;
			for (let i = 0; i < 31; i++) {
				const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
					method: 'POST',
					headers: {
						'Content-Type': 'application/json',
						'cf-connecting-ip': '198.51.100.200',
					},
					body: JSON.stringify({ jsonrpc: '2.0', id: i + 1000, method: 'initialize', params: {} }),
				});
				const ctx = createExecutionContext();
				lastResponse = await worker.fetch(request, env, ctx);
				await waitOnExecutionContext(ctx);
			}

			expect(lastResponse).toBeDefined();
			expect(lastResponse!.status).toBe(200);
			expect(lastResponse!.headers.get('retry-after')).toBeTruthy();
		});
	});

	describe('POST /mcp - tools/list', () => {
		it('returns all tools', async () => {
			const sessionId = await initSession();
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', 'Mcp-Session-Id': sessionId },
				body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			const body = (await response.json()) as { result: { tools: Array<{ name: string }> } };
			expect(body.result.tools).toHaveLength(41);
			const toolNames = body.result.tools.map((t) => t.name);
			expect(toolNames).toContain('check_spf');
			expect(toolNames).toContain('check_dmarc');
			expect(toolNames).toContain('check_bimi');
			expect(toolNames).toContain('check_tlsrpt');
			expect(toolNames).toContain('check_lookalikes');
			expect(toolNames).toContain('scan_domain');
			expect(toolNames).toContain('compare_baseline');
			expect(toolNames).toContain('explain_finding');
		});
	});

	describe('POST /mcp - resources/list', () => {
		it('returns resource list', async () => {
			const sessionId = await initSession();
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', 'Mcp-Session-Id': sessionId },
				body: JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'resources/list', params: {} }),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			const body = (await response.json()) as { result: { resources: Array<{ uri: string }> } };
			expect(body.result.resources.length).toBeGreaterThan(0);
		});
	});

	describe('POST /mcp - resources/read', () => {
		it('returns resource content for valid URI', async () => {
			const sessionId = await initSession();
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', 'Mcp-Session-Id': sessionId },
				body: JSON.stringify({
					jsonrpc: '2.0',
					id: 20,
					method: 'resources/read',
					params: { uri: 'dns-security://guides/security-checks' },
				}),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(200);
			const body = (await response.json()) as { result: { contents: Array<{ uri: string; text: string }> } };
			expect(body.result.contents).toBeDefined();
			expect(body.result.contents.length).toBeGreaterThan(0);
			expect(body.result.contents[0].uri).toBe('dns-security://guides/security-checks');
		});
	});

	describe('POST /mcp - ping', () => {
		it('returns empty result for ping method', async () => {
			const sessionId = await initSession();
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', 'Mcp-Session-Id': sessionId },
				body: JSON.stringify({ jsonrpc: '2.0', id: 21, method: 'ping', params: {} }),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(200);
			const body = (await response.json()) as { jsonrpc: string; id: number; result: Record<string, never> };
			expect(body.jsonrpc).toBe('2.0');
			expect(body.id).toBe(21);
			expect(body.result).toEqual({});
		});
	});

	describe('POST /mcp - notifications', () => {
		it('returns 202 for notifications/initialized (no id)', async () => {
			const sessionId = await initSession();
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', 'Mcp-Session-Id': sessionId },
				body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(202);
		});

		it('returns 202 for other notifications (no id)', async () => {
			const sessionId = await initSession();
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', 'Mcp-Session-Id': sessionId },
				body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/some_event' }),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(202);
		});

		it('returns 202 for notification with null id', async () => {
			const sessionId = await initSession();
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', 'Mcp-Session-Id': sessionId },
				body: JSON.stringify({ jsonrpc: '2.0', id: null, method: 'notifications/initialized' }),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(202);
		});
	});

	describe('POST /mcp - JSON-RPC id validation', () => {
		it('rejects non-string/number/null id (object)', async () => {
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ jsonrpc: '2.0', id: { invalid: true }, method: 'initialize', params: {} }),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(400);
			const body = (await response.json()) as { error: { code: number; message: string } };
			expect(body.error.code).toBe(-32600);
			expect(body.error.message).toContain('Invalid JSON-RPC id');
		});

		it('rejects boolean id', async () => {
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ jsonrpc: '2.0', id: true, method: 'initialize', params: {} }),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(400);
			const body = (await response.json()) as { error: { code: number; message: string } };
			expect(body.error.code).toBe(-32600);
		});
	});

	describe('POST /mcp - invalid requests', () => {
		it('rejects invalid JSON', async () => {
			const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: '{"secret":"should-not-appear',
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(400);
			const body = (await response.json()) as { error: { code: number } };
			expect(body.error.code).toBe(-32700);
			const logged = consoleSpy.mock.calls.map((call) => String(call[0])).join('\n');
			expect(logged).not.toContain('should-not-appear');
			expect(logged).toContain('bodyPreviewRedacted');
		});

		it('rejects invalid JSON-RPC', async () => {
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ method: 'test' }),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(400);
			const body = (await response.json()) as { error: { code: number } };
			expect(body.error.code).toBe(-32600);
		});

		it('returns method not found for unknown methods', async () => {
			const sessionId = await initSession();
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', 'Mcp-Session-Id': sessionId },
				body: JSON.stringify({ jsonrpc: '2.0', id: 4, method: 'unknown/method', params: {} }),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			const body = (await response.json()) as { error: { code: number } };
			expect(body.error.code).toBe(-32601);
		});

		it('rejects non-initialize requests without session ID', async () => {
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ jsonrpc: '2.0', id: 10, method: 'tools/list', params: {} }),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(400);
			const body = (await response.json()) as { error: { message: string } };
			expect(body.error.message).toContain('session');
		});
	});

	describe('POST /mcp - batch requests', () => {
		it('returns a JSON array for mixed request and notification batches', async () => {
			const sessionId = await initSession();
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', 'Mcp-Session-Id': sessionId },
				body: JSON.stringify([
					{ jsonrpc: '2.0', id: 41, method: 'ping', params: {} },
					{ jsonrpc: '2.0', method: 'notifications/initialized' },
					{ jsonrpc: '2.0', id: 42, method: 'tools/list', params: {} },
				]),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(200);
			const body = (await response.json()) as Array<{ id: number; result?: unknown }>;
			expect(body).toHaveLength(2);
			expect(body.map((entry) => entry.id)).toEqual([41, 42]);
			expect(body[0]?.result).toEqual({});
			expect(body[1]?.result).toHaveProperty('tools');
		});

		it('returns 202 for notification-only batches', async () => {
			const sessionId = await initSession();
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', 'Mcp-Session-Id': sessionId },
				body: JSON.stringify([
					{ jsonrpc: '2.0', method: 'notifications/initialized' },
					{ jsonrpc: '2.0', method: 'notifications/some_event' },
				]),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(202);
		});

		it('returns an SSE event for batch responses when the client accepts event-stream', async () => {
			const sessionId = await initSession();
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					Accept: 'application/json, text/event-stream',
					'Mcp-Session-Id': sessionId,
				},
				body: JSON.stringify([
					{ jsonrpc: '2.0', id: 51, method: 'ping', params: {} },
					{ jsonrpc: '2.0', id: 52, method: 'tools/list', params: {} },
				]),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(200);
			expect(response.headers.get('content-type')).toBe('text/event-stream');
			const body = parseSseMessage<Array<{ id: number }>>(await response.text());
			expect(body.map((entry) => entry.id)).toEqual([51, 52]);
		});

		it('returns an error payload when initialize is batched with other messages', async () => {
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify([
					{ jsonrpc: '2.0', id: 61, method: 'initialize', params: {} },
					{ jsonrpc: '2.0', id: 62, method: 'ping', params: {} },
				]),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(200);
			const body = (await response.json()) as Array<{ id: number; error?: { code: number; message: string } }>;
			expect(body[0]?.id).toBe(61);
			expect(body[0]?.error?.code).toBe(-32600);
			expect(body[0]?.error?.message).toContain('initialize cannot be batched');
			expect(body[1]?.id).toBe(62);
			expect(body[1]?.error?.message).toContain('session');
		});
	});

	describe('POST /mcp - tools/call domain validation', () => {
		it('accepts scan alias and runs scan_domain', async () => {
			const sessionId = await initSession();
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', 'Mcp-Session-Id': sessionId },
				body: JSON.stringify({
					jsonrpc: '2.0',
					id: 4.5,
					method: 'tools/call',
					params: { name: 'scan', arguments: { domain: 'example.com' } },
				}),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(200);
			const body = (await response.json()) as { result: { content: Array<{ text: string }>; isError?: boolean } };
			expect(body.result.isError).toBeUndefined();
			expect(body.result.content[0].text).toContain('DNS Security Scan');
		});

		it('rejects localhost domains', async () => {
			const sessionId = await initSession();
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', 'Mcp-Session-Id': sessionId },
				body: JSON.stringify({
					jsonrpc: '2.0',
					id: 5,
					method: 'tools/call',
					params: { name: 'check_spf', arguments: { domain: 'localhost' } },
				}),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			const body = (await response.json()) as { result: { content: Array<{ text: string }>; isError: boolean } };
			expect(body.result.isError).toBe(true);
			expect(body.result.content[0].text).toContain('Error');
		});

		it('rejects .local domains', async () => {
			const sessionId = await initSession();
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', 'Mcp-Session-Id': sessionId },
				body: JSON.stringify({
					jsonrpc: '2.0',
					id: 6,
					method: 'tools/call',
					params: { name: 'check_spf', arguments: { domain: 'test.local' } },
				}),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			const body = (await response.json()) as { result: { content: Array<{ text: string }>; isError: boolean } };
			expect(body.result.isError).toBe(true);
		});

		it('rejects short-form loopback literals', async () => {
			const sessionId = await initSession();
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', 'Mcp-Session-Id': sessionId },
				body: JSON.stringify({
					jsonrpc: '2.0',
					id: 6.1,
					method: 'tools/call',
					params: { name: 'check_spf', arguments: { domain: '127.1' } },
				}),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(200);
			const body = (await response.json()) as { result: { content: Array<{ text: string }>; isError: boolean } };
			expect(body.result.isError).toBe(true);
			expect(body.result.content[0].text).toContain('Domain validation failed');
		});

		it('rejects octal loopback literals', async () => {
			const sessionId = await initSession();
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', 'Mcp-Session-Id': sessionId },
				body: JSON.stringify({
					jsonrpc: '2.0',
					id: 6.2,
					method: 'tools/call',
					params: { name: 'check_spf', arguments: { domain: '0177.0.0.1' } },
				}),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(200);
			const body = (await response.json()) as { result: { content: Array<{ text: string }>; isError: boolean } };
			expect(body.result.isError).toBe(true);
			expect(body.result.content[0].text).toContain('Domain validation failed');
		});

		it('rejects public IPv4 literals', async () => {
			const sessionId = await initSession();
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', 'Mcp-Session-Id': sessionId },
				body: JSON.stringify({
					jsonrpc: '2.0',
					id: 6.3,
					method: 'tools/call',
					params: { name: 'check_ssl', arguments: { domain: '8.8.8.8' } },
				}),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(200);
			const body = (await response.json()) as { result: { content: Array<{ text: string }>; isError: boolean } };
			expect(body.result.isError).toBe(true);
			expect(body.result.content[0].text).toContain('Domain validation failed');
		});

		it('rejects alternate numeric forms of public IPv4 literals', async () => {
			const sessionId = await initSession();
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', 'Mcp-Session-Id': sessionId },
				body: JSON.stringify({
					jsonrpc: '2.0',
					id: 6.4,
					method: 'tools/call',
					params: { name: 'check_ssl', arguments: { domain: '0x8.0x8.0x8.0x8' } },
				}),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(200);
			const body = (await response.json()) as { result: { content: Array<{ text: string }>; isError: boolean } };
			expect(body.result.isError).toBe(true);
			expect(body.result.content[0].text).toContain('Domain validation failed');
		});

		it('rejects domains longer than 253 characters', async () => {
			const sessionId = await initSession();
			const domain254 = ['a'.repeat(63), 'b'.repeat(63), 'c'.repeat(63), 'd'.repeat(62)].join('.');
			expect(domain254.length).toBe(254);

			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', 'Mcp-Session-Id': sessionId },
				body: JSON.stringify({
					jsonrpc: '2.0',
					id: 11,
					method: 'tools/call',
					params: { name: 'check_spf', arguments: { domain: domain254 } },
				}),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(200);
			const body = (await response.json()) as { result: { content: Array<{ text: string }>; isError: boolean } };
			expect(body.result.isError).toBe(true);
			expect(body.result.content[0].text).toContain('Error');
		});
	});

	describe('POST /mcp - explain_finding', () => {
		it('returns explanation for known finding', async () => {
			const sessionId = await initSession();
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', 'Mcp-Session-Id': sessionId },
				body: JSON.stringify({
					jsonrpc: '2.0',
					id: 7,
					method: 'tools/call',
					params: { name: 'explain_finding', arguments: { checkType: 'SPF', status: 'fail' } },
				}),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			const body = (await response.json()) as { result: { content: Array<{ text: string }> } };
			expect(body.result.content[0].text).toContain('SPF');
			expect(body.result.content[0].text).toContain('Recommendation');
		});
	});

	describe('Streamable HTTP transport - SSE', () => {
		it('POST with Accept: text/event-stream returns SSE', async () => {
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					Accept: 'text/event-stream, application/json',
				},
				body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(200);
			expect(response.headers.get('content-type')).toBe('text/event-stream');
			expect(response.headers.get('mcp-session-id')).toBeTruthy();
			const text = await response.text();
			expect(text).toContain('event: message');
			expect(text).toContain('"protocolVersion":"2025-03-26"');
		});

		it('GET /mcp returns SSE stream with valid session', async () => {
			const sessionId = await initSession();
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'GET',
				headers: {
					Accept: 'text/event-stream',
					'Mcp-Session-Id': sessionId,
				},
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(200);
			expect(response.headers.get('content-type')).toBe('text/event-stream');
		});

		it('GET /mcp rejects invalid session ID', async () => {
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'GET',
				headers: {
					Accept: 'text/event-stream',
					'Mcp-Session-Id': 'nonexistent-session-id',
				},
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(404);
			const body = (await response.json()) as { error: { message: string } };
			expect(body.error.message).toContain('session expired or terminated');
		});

		it('GET /mcp returns 406 when Accept does not include text/event-stream', async () => {
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'GET',
				headers: {
					Accept: 'application/json',
				},
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(406);
		});

		it('GET /mcp requires an existing session header', async () => {
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'GET',
				headers: {
					Accept: 'text/event-stream',
				},
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(400);
			const body = (await response.json()) as { error: { message: string } };
			expect(body.error.message).toContain('missing session');
		});
	});

	describe('Claude Desktop compatibility', () => {
		it('supports the Claude Desktop remote connector lifecycle over Streamable HTTP', async () => {
			const initializeRequest = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					Accept: 'application/json, text/event-stream',
					'User-Agent': 'Claude-Desktop/1.0',
				},
				body: JSON.stringify({
					jsonrpc: '2.0',
					id: 1,
					method: 'initialize',
					params: {
						protocolVersion: '2025-03-26',
						capabilities: {},
						clientInfo: {
							name: 'Claude Desktop',
							version: '1.0.0',
						},
					},
				}),
			});
			const initCtx = createExecutionContext();
			const initializeResponse = await worker.fetch(initializeRequest, env, initCtx);
			await waitOnExecutionContext(initCtx);

			expect(initializeResponse.status).toBe(200);
			expect(initializeResponse.headers.get('content-type')).toBe('text/event-stream');
			const sessionId = initializeResponse.headers.get('mcp-session-id');
			expect(sessionId).toBeTruthy();

			const initializeBody = parseSseMessage<{
				result: { protocolVersion: string; serverInfo: { name: string } };
			}>(await initializeResponse.text());
			expect(initializeBody.result.protocolVersion).toBe('2025-03-26');
			expect(initializeBody.result.serverInfo.name).toBe('Blackveil DNS');

			const initializedNotification = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					Accept: 'application/json, text/event-stream',
					'Mcp-Session-Id': sessionId!,
					'User-Agent': 'Claude-Desktop/1.0',
				},
				body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }),
			});
			const initializedCtx = createExecutionContext();
			const initializedResponse = await worker.fetch(initializedNotification, env, initializedCtx);
			await waitOnExecutionContext(initializedCtx);
			expect(initializedResponse.status).toBe(202);

			const toolsListRequest = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					Accept: 'application/json, text/event-stream',
					'Mcp-Session-Id': sessionId!,
					'User-Agent': 'Claude-Desktop/1.0',
				},
				body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }),
			});
			const toolsListCtx = createExecutionContext();
			const toolsListResponse = await worker.fetch(toolsListRequest, env, toolsListCtx);
			await waitOnExecutionContext(toolsListCtx);

			expect(toolsListResponse.status).toBe(200);
			expect(toolsListResponse.headers.get('content-type')).toBe('text/event-stream');
			const toolsListBody = parseSseMessage<{
				result: { tools: Array<{ name: string }> };
			}>(await toolsListResponse.text());
			expect(toolsListBody.result.tools.some((tool) => tool.name === 'scan_domain')).toBe(true);
			expect(toolsListBody.result.tools.some((tool) => tool.name === 'explain_finding')).toBe(true);

			const notificationsRequest = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'GET',
				headers: {
					Accept: 'text/event-stream',
					'Mcp-Session-Id': sessionId!,
					'User-Agent': 'Claude-Desktop/1.0',
				},
			});
			const notificationsCtx = createExecutionContext();
			const notificationsResponse = await worker.fetch(notificationsRequest, env, notificationsCtx);
			await waitOnExecutionContext(notificationsCtx);
			expect(notificationsResponse.status).toBe(200);
			expect(notificationsResponse.headers.get('content-type')).toBe('text/event-stream');
		});

		it('streams Claude Desktop style tools/call responses over SSE', async () => {
			const sessionId = await initSession();

			const initializedNotification = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					Accept: 'application/json, text/event-stream',
					'Mcp-Session-Id': sessionId,
					'User-Agent': 'Claude-Desktop/1.0',
				},
				body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }),
			});
			const initializedCtx = createExecutionContext();
			const initializedResponse = await worker.fetch(initializedNotification, env, initializedCtx);
			await waitOnExecutionContext(initializedCtx);
			expect(initializedResponse.status).toBe(202);

			const toolCallRequest = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					Accept: 'application/json, text/event-stream',
					'Mcp-Session-Id': sessionId,
					'User-Agent': 'Claude-Desktop/1.0',
				},
				body: JSON.stringify({
					jsonrpc: '2.0',
					id: 3,
					method: 'tools/call',
					params: {
						name: 'explain_finding',
						arguments: { checkType: 'SPF', status: 'fail' },
					},
				}),
			});
			const toolCallCtx = createExecutionContext();
			const toolCallResponse = await worker.fetch(toolCallRequest, env, toolCallCtx);
			await waitOnExecutionContext(toolCallCtx);

			expect(toolCallResponse.status).toBe(200);
			expect(toolCallResponse.headers.get('content-type')).toBe('text/event-stream');
			const toolCallBody = parseSseMessage<{
				result: { content: Array<{ text: string }> };
			}>(await toolCallResponse.text());
			expect(toolCallBody.result.content[0].text).toContain('SPF');
			expect(toolCallBody.result.content[0].text).toContain('Recommendation');
		});
	});

	describe('Legacy HTTP+SSE transport', () => {
		it('opens a legacy SSE stream on /mcp/sse and emits the endpoint event', async () => {
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp/sse', {
				method: 'GET',
				headers: {
					Accept: 'text/event-stream',
				},
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);

			expect(response.status).toBe(200);
			expect(response.headers.get('content-type')).toBe('text/event-stream');
			expect(response.headers.get('mcp-session-id')).toBeTruthy();

			const firstChunk = await readSseChunk(response);
			const endpoint = parseSseEvent(firstChunk, 'endpoint');
			expect(endpoint).toContain('/mcp/messages?sessionId=');
		});

		it('delivers initialize responses over the legacy SSE stream', async () => {
			const openRequest = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp/sse', {
				method: 'GET',
				headers: {
					Accept: 'text/event-stream',
				},
			});
			const openCtx = createExecutionContext();
			const streamResponse = await worker.fetch(openRequest, env, openCtx);
			await waitOnExecutionContext(openCtx);

			const endpointChunk = await readSseChunk(streamResponse);
			const endpoint = parseSseEvent(endpointChunk, 'endpoint');
			const sessionId = streamResponse.headers.get('mcp-session-id');
			expect(sessionId).toBeTruthy();

			const initializeRequest = new Request<unknown, IncomingRequestCfProperties>(endpoint, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
				},
				body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
			});
			const initializeCtx = createExecutionContext();
			const initializeResponse = await worker.fetch(initializeRequest, env, initializeCtx);
			await waitOnExecutionContext(initializeCtx);

			expect(initializeResponse.status).toBe(202);

			const messageChunk = await readSseChunk(streamResponse);
			const payload = parseSseMessage<{
				result: { protocolVersion: string; serverInfo: { name: string } };
			}>(messageChunk);
			expect(payload.result.protocolVersion).toBe('2025-03-26');
			expect(payload.result.serverInfo.name).toBe('Blackveil DNS');

			const deleteRequest = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'DELETE',
				headers: { 'Mcp-Session-Id': sessionId! },
			});
			const deleteCtx = createExecutionContext();
			const deleteResponse = await worker.fetch(deleteRequest, env, deleteCtx);
			await waitOnExecutionContext(deleteCtx);
			expect(deleteResponse.status).toBe(204);
		});
	});

	describe('Streamable HTTP transport - DELETE session', () => {
		it('DELETE /mcp terminates session', async () => {
			const sessionId = await initSession();
			const delReq = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'DELETE',
				headers: { 'Mcp-Session-Id': sessionId },
			});
			const ctx1 = createExecutionContext();
			const delRes = await worker.fetch(delReq, env, ctx1);
			await waitOnExecutionContext(ctx1);
			expect(delRes.status).toBe(204);

			const postReq = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', 'Mcp-Session-Id': sessionId },
				body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
			});
			const ctx2 = createExecutionContext();
			const postRes = await worker.fetch(postReq, env, ctx2);
			await waitOnExecutionContext(ctx2);
			expect(postRes.status).toBe(404);
		});

		it('DELETE /mcp rejects invalid session', async () => {
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'DELETE',
				headers: { 'Mcp-Session-Id': 'nonexistent' },
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(404);
		});
	});

	describe('Rate limiting', () => {
		it('authenticated tools/call requests bypass rate limiting', async () => {
			const authEnv = { ...env, BV_API_KEY: TEST_API_KEY } as Env;
			const sessionId = await initSession({ authToken: TEST_API_KEY, targetEnv: authEnv });
			// Send 15 tools/call requests with valid auth — all should succeed
			for (let i = 0; i < 15; i++) {
				const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
					method: 'POST',
					headers: {
						'Content-Type': 'application/json',
						Authorization: `Bearer ${TEST_API_KEY}`,
						'Mcp-Session-Id': sessionId,
					},
					body: JSON.stringify({
						jsonrpc: '2.0',
						id: i + 1,
						method: 'tools/call',
						params: { name: 'explain_finding', arguments: { checkType: 'SPF', status: 'fail' } },
					}),
				});
				const ctx = createExecutionContext();
				const response = await worker.fetch(request, authEnv, ctx);
				await waitOnExecutionContext(ctx);
				expect(response.status).toBe(200);
				expect(response.headers.has('x-ratelimit-limit')).toBe(false);
			}
		});

		it('unauthenticated tools/call requests are rate-limited', async () => {
			const sessionId = await initSession();
			let rateLimited = false;
			for (let i = 0; i < 51; i++) {
				const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
					method: 'POST',
					headers: {
						'Content-Type': 'application/json',
						'Mcp-Session-Id': sessionId,
					},
					body: JSON.stringify({
						jsonrpc: '2.0',
						id: i + 1,
						method: 'tools/call',
						params: { name: 'explain_finding', arguments: { checkType: 'SPF', status: 'fail' } },
					}),
				});
				const ctx = createExecutionContext();
				const response = await worker.fetch(request, env, ctx);
				await waitOnExecutionContext(ctx);
				const body = (await response.json()) as { error?: { code: number } };
				if (body.error?.code === -32029) {
					rateLimited = true;
					break;
				}
			}
			expect(rateLimited).toBe(true);
		});

		it('tools/call notifications consume exactly one rate-limit unit per request', async () => {
			const sessionId = await initSession();

			for (let i = 0; i < 50; i++) {
				const notificationRequest = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
					method: 'POST',
					headers: {
						'Content-Type': 'application/json',
						'Mcp-Session-Id': sessionId,
					},
					body: JSON.stringify({
						jsonrpc: '2.0',
						method: 'tools/call',
						params: { name: 'explain_finding', arguments: { checkType: 'SPF', status: 'fail' } },
					}),
				});
				const ctx = createExecutionContext();
				const response = await worker.fetch(notificationRequest, env, ctx);
				await waitOnExecutionContext(ctx);
				expect(response.status).toBe(202);
			}

			const blockedRequest = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'Mcp-Session-Id': sessionId,
				},
				body: JSON.stringify({
					jsonrpc: '2.0',
					method: 'tools/call',
					params: { name: 'explain_finding', arguments: { checkType: 'SPF', status: 'fail' } },
				}),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(blockedRequest, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(200);
		});

		it('unauthenticated scan_domain requests are capped at 75/day', async () => {
			vi.useFakeTimers();
			vi.setSystemTime(new Date('2026-03-07T00:00:00Z'));

			try {
			const sessionId = await initSession();

			for (let i = 0; i < 75; i++) {
				const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
					method: 'POST',
					headers: {
						'Content-Type': 'application/json',
						'Mcp-Session-Id': sessionId,
						'cf-connecting-ip': '203.0.113.77',
					},
					body: JSON.stringify({
						jsonrpc: '2.0',
						id: i + 200,
						method: 'tools/call',
						params: { name: 'scan_domain', arguments: { domain: 'example.com' } },
					}),
				});
				const ctx = createExecutionContext();
				const response = await worker.fetch(request, env, ctx);
				await waitOnExecutionContext(ctx);
				expect(response.status).toBe(200);
				vi.advanceTimersByTime(61_000);
			}

			const blockedRequest = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'Mcp-Session-Id': sessionId,
					'cf-connecting-ip': '203.0.113.77',
				},
				body: JSON.stringify({
					jsonrpc: '2.0',
					id: 210,
					method: 'tools/call',
					params: { name: 'scan_domain', arguments: { domain: 'example.com' } },
				}),
			});
			const ctx = createExecutionContext();
			const blockedResponse = await worker.fetch(blockedRequest, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(blockedResponse.status).toBe(200);
			expect(blockedResponse.headers.get('x-quota-limit')).toBe('75');
			expect(blockedResponse.headers.get('x-quota-remaining')).toBe('0');

			const body = (await blockedResponse.json()) as { error: { code: number; message: string } };
			expect(body.error.code).toBe(-32029);
			expect(body.error.message).toContain('scan_domain');
			expect(body.error.message).toContain('75 requests per day');
			} finally {
				vi.useRealTimers();
			}
		});

		it('authenticated scan_domain requests are not subject to free daily cap', async () => {
			const authEnv = { ...env, BV_API_KEY: TEST_API_KEY } as Env;
			const sessionId = await initSession({ authToken: TEST_API_KEY, targetEnv: authEnv });

			for (let i = 0; i < 6; i++) {
				const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
					method: 'POST',
					headers: {
						'Content-Type': 'application/json',
						Authorization: `Bearer ${TEST_API_KEY}`,
						'Mcp-Session-Id': sessionId,
						'cf-connecting-ip': '203.0.113.88',
					},
					body: JSON.stringify({
						jsonrpc: '2.0',
						id: i + 300,
						method: 'tools/call',
						params: { name: 'scan_domain', arguments: { domain: 'example.com' } },
					}),
				});
				const ctx = createExecutionContext();
				const response = await worker.fetch(request, authEnv, ctx);
				await waitOnExecutionContext(ctx);
				expect(response.status).toBe(200);
				expect(response.headers.get('x-quota-tier')).toBe('owner');
				expect(response.headers.get('x-quota-limit')).toBe('Infinity');
			}
		});

		it('protocol methods use a separate control-plane budget from tools/call', async () => {
			// Exhaust the rate limit with tools/call requests first
			const sessionId = await initSession();
			for (let i = 0; i < 51; i++) {
				const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
					method: 'POST',
					headers: {
						'Content-Type': 'application/json',
						'Mcp-Session-Id': sessionId,
					},
					body: JSON.stringify({
						jsonrpc: '2.0',
						id: i + 100,
						method: 'tools/call',
						params: { name: 'explain_finding', arguments: { checkType: 'SPF', status: 'fail' } },
					}),
				});
				const ctx = createExecutionContext();
				await worker.fetch(request, env, ctx);
				await waitOnExecutionContext(ctx);
			}

			// Protocol methods should still work because they no longer share the tools/call budget.

			const protocolMethods = [
				{ method: 'initialize', params: {} },
				{ method: 'tools/list', params: {} },
				{ method: 'ping', params: {} },
				{ method: 'resources/list', params: {} },
			];
			for (const { method, params } of protocolMethods) {
				const headers: Record<string, string> = { 'Content-Type': 'application/json' };
				if (method !== 'initialize') headers['Mcp-Session-Id'] = sessionId;
				const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
					method: 'POST',
					headers,
					body: JSON.stringify({ jsonrpc: '2.0', id: 50, method, params }),
				});
				const ctx = createExecutionContext();
				const response = await worker.fetch(request, env, ctx);
				await waitOnExecutionContext(ctx);
				expect(response.status, `${method} should use a separate control-plane budget`).toBe(200);
			}
		});

		it('does not rate-limit protocol methods (initialize, ping, tools/list, etc.)', async () => {
			const sessionId = await initSession();

			// Send 65 ping requests — all should succeed since protocol methods are exempt
			// from control plane rate limiting to prevent mcp-remote reconnection storms
			for (let i = 0; i < 65; i++) {
				const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
					method: 'POST',
					headers: {
						'Content-Type': 'application/json',
						'Mcp-Session-Id': sessionId,
						'cf-connecting-ip': '203.0.113.55',
					},
					body: JSON.stringify({ jsonrpc: '2.0', id: i + 500, method: 'ping', params: {} }),
				});
				const ctx = createExecutionContext();
				const response = await worker.fetch(request, env, ctx);
				await waitOnExecutionContext(ctx);
				expect(response.status).toBe(200);
			}
		});
	});

	describe('Session recovery', () => {
		/** Helper: terminate a session via DELETE so subsequent requests see it as expired */
		async function terminateSession(sessionId: string): Promise<void> {
			const delReq = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'DELETE',
				headers: { 'Mcp-Session-Id': sessionId },
			});
			const ctx = createExecutionContext();
			const delRes = await worker.fetch(delReq, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(delRes.status).toBe(204);
		}

		it('returns HTTP 404 (not 200) for expired sessions when client accepts SSE', async () => {
			const sessionId = await initSession();
			await terminateSession(sessionId);

			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					Accept: 'application/json, text/event-stream',
					'Mcp-Session-Id': sessionId,
				},
				body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);

			// Must be HTTP 404 so MCP clients detect session expiry and re-initialize
			expect(response.status).toBe(404);
		});

		it('auto-recovers expired sessions for tools/call and returns a fresh session header', async () => {
			const sessionId = await initSession();
			await terminateSession(sessionId);

			const toolRequest = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'Mcp-Session-Id': sessionId,
				},
				body: JSON.stringify({
					jsonrpc: '2.0',
					id: 101,
					method: 'tools/call',
					params: {
						name: 'explain_finding',
						arguments: { checkType: 'SPF', status: 'fail' },
					},
				}),
			});
			const toolCtx = createExecutionContext();
			const toolResponse = await worker.fetch(toolRequest, env, toolCtx);
			await waitOnExecutionContext(toolCtx);

			expect(toolResponse.status).toBe(200);
			const recoveredSessionId = toolResponse.headers.get('mcp-session-id');
			expect(recoveredSessionId).toBeTruthy();
			expect(recoveredSessionId).not.toBe(sessionId);

			const toolBody = (await toolResponse.json()) as {
				result?: { content?: Array<{ type: string; text: string }> };
				error?: { message?: string };
			};
			expect(toolBody.error).toBeUndefined();
			expect(Array.isArray(toolBody.result?.content)).toBe(true);

			const followupRequest = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'Mcp-Session-Id': recoveredSessionId!,
				},
				body: JSON.stringify({ jsonrpc: '2.0', id: 102, method: 'tools/list', params: {} }),
			});
			const followupCtx = createExecutionContext();
			const followupResponse = await worker.fetch(followupRequest, env, followupCtx);
			await waitOnExecutionContext(followupCtx);

			expect(followupResponse.status).toBe(200);
		});

		it('allows notifications/initialized without a valid session', async () => {
			// Notifications are fire-and-forget per MCP spec — no session required
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
				},
				body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);

			// Notifications return 202 (accepted, no response body)
			expect(response.status).toBe(202);
		});

		it('allows notifications with terminated session ID', async () => {
			const sessionId = await initSession();
			await terminateSession(sessionId);

			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'Mcp-Session-Id': sessionId,
				},
				body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);

			expect(response.status).toBe(202);
		});

		it('completes full re-initialization after session termination (Claude Desktop flow)', async () => {
			// Step 1: Initialize and get session
			const sessionId = await initSession();

			// Step 2: Terminate the session (simulates expiry)
			await terminateSession(sessionId);

			// Step 3: tools/list with terminated session → 404
			const expiredRequest = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					Accept: 'application/json, text/event-stream',
					'Mcp-Session-Id': sessionId,
				},
				body: JSON.stringify({ jsonrpc: '2.0', id: 10, method: 'tools/list', params: {} }),
			});
			const ctx1 = createExecutionContext();
			const expiredResponse = await worker.fetch(expiredRequest, env, ctx1);
			await waitOnExecutionContext(ctx1);
			expect(expiredResponse.status).toBe(404);

			// Step 4: Re-initialize with fresh session
			const reInitRequest = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					Accept: 'application/json, text/event-stream',
				},
				body: JSON.stringify({ jsonrpc: '2.0', id: 11, method: 'initialize', params: {} }),
			});
			const ctx2 = createExecutionContext();
			const reInitResponse = await worker.fetch(reInitRequest, env, ctx2);
			await waitOnExecutionContext(ctx2);
			expect(reInitResponse.status).toBe(200);
			const newSessionId = reInitResponse.headers.get('mcp-session-id');
			expect(newSessionId).toBeTruthy();
			expect(newSessionId).not.toBe(sessionId);

			// Step 5: notifications/initialized with new session → 202
			const notifRequest = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'Mcp-Session-Id': newSessionId!,
				},
				body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }),
			});
			const ctx3 = createExecutionContext();
			const notifResponse = await worker.fetch(notifRequest, env, ctx3);
			await waitOnExecutionContext(ctx3);
			expect(notifResponse.status).toBe(202);

			// Step 6: tools/list with new session → 200
			const toolsRequest = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					Accept: 'application/json, text/event-stream',
					'Mcp-Session-Id': newSessionId!,
				},
				body: JSON.stringify({ jsonrpc: '2.0', id: 12, method: 'tools/list', params: {} }),
			});
			const ctx4 = createExecutionContext();
			const toolsResponse = await worker.fetch(toolsRequest, env, ctx4);
			await waitOnExecutionContext(ctx4);
			expect(toolsResponse.status).toBe(200);
		});

		it('returns HTTP 404 for legacy SSE POST with terminated session', async () => {
			// Open legacy SSE stream
			const openRequest = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp/sse', {
				method: 'GET',
				headers: { Accept: 'text/event-stream' },
			});
			const openCtx = createExecutionContext();
			const streamResponse = await worker.fetch(openRequest, env, openCtx);
			await waitOnExecutionContext(openCtx);
			const endpointChunk = await readSseChunk(streamResponse);
			const endpoint = parseSseEvent(endpointChunk, 'endpoint');
			const sessionId = streamResponse.headers.get('mcp-session-id');
			expect(sessionId).toBeTruthy();

			// Terminate the session
			await terminateSession(sessionId!);

			// POST to legacy endpoint with terminated session → must get HTTP 404 directly
			const request = new Request<unknown, IncomingRequestCfProperties>(endpoint, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);

			// Must be HTTP 404 directly, not HTTP 202 with undeliverable SSE message
			expect(response.status).toBe(404);
			const body = (await response.json()) as { error: { message: string } };
			expect(body.error.message).toContain('session expired or terminated');
		});
	});

	describe('404 fallback', () => {
		it('returns 404 for unknown routes', async () => {
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/unknown');
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(404);
		});
	});
});
