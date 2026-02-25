import { env, createExecutionContext, waitOnExecutionContext, SELF } from 'cloudflare:test';
import { describe, it, expect, beforeEach } from 'vitest';
import worker from '../src';
import { resetAllRateLimits } from '../src/lib/rate-limiter';

const TEST_API_KEY = 'test-api-key';

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
				// Create a JSON-RPC payload just over 10KB
				const bigString = 'a'.repeat(10 * 1024); // 10KB
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
	beforeEach(() => {
		resetAllRateLimits();
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

		it('returns 401 JSON-RPC error when auth is required and token is missing', async () => {
			const authEnv = { ...env, BV_API_KEY: TEST_API_KEY } as Env;
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, authEnv, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(401);
			const body = (await response.json()) as { error: { code: number; message: string } };
			expect(body.error.code).toBe(-32001);
			expect(body.error.message).toContain('Unauthorized');
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
				result: { protocolVersion: string; serverInfo: { name: string } };
			};
			expect(body.jsonrpc).toBe('2.0');
			expect(body.id).toBe(1);
			expect(body.result.serverInfo.name).toBe('bv-dns-security-mcp');
			expect(body.result.protocolVersion).toBe('2025-03-26');
			// Session ID must be returned
			const sessionId = response.headers.get('mcp-session-id');
			expect(sessionId).toBeTruthy();
			expect(sessionId!.length).toBeGreaterThanOrEqual(32);
		});
	});

	describe('POST /mcp - tools/list', () => {
		it('returns all 10 tools', async () => {
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
			expect(body.result.tools).toHaveLength(10);
			const toolNames = body.result.tools.map((t) => t.name);
			expect(toolNames).toContain('check_spf');
			expect(toolNames).toContain('check_dmarc');
			expect(toolNames).toContain('scan_domain');
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

	describe('POST /mcp - invalid requests', () => {
		it('rejects invalid JSON', async () => {
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: 'not json',
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(400);
			const body = (await response.json()) as { error: { code: number } };
			expect(body.error.code).toBe(-32700);
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

	describe('POST /mcp - tools/call domain validation', () => {
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

		it('GET /mcp initiates SSE session when no session header is provided', async () => {
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
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
		});
	});

	describe('Streamable HTTP transport - DELETE session', () => {
		it('DELETE /mcp terminates session', async () => {
			const sessionId = await initSession();
			// Delete the session
			const delReq = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'DELETE',
				headers: { 'Mcp-Session-Id': sessionId },
			});
			const ctx1 = createExecutionContext();
			const delRes = await worker.fetch(delReq, env, ctx1);
			await waitOnExecutionContext(ctx1);
			expect(delRes.status).toBe(204);

			// Subsequent request with deleted session should fail
			const postReq = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', 'Mcp-Session-Id': sessionId },
				body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
			});
			const ctx2 = createExecutionContext();
			const postRes = await worker.fetch(postReq, env, ctx2);
			await waitOnExecutionContext(ctx2);
			expect(postRes.status).toBe(400);
		});

		it('DELETE /mcp rejects invalid session', async () => {
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'DELETE',
				headers: { 'Mcp-Session-Id': 'nonexistent' },
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(400);
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
