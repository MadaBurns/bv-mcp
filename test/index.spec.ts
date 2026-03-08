import { env, createExecutionContext, waitOnExecutionContext, SELF } from 'cloudflare:test';
import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import worker from '../src';
import { resetAllRateLimits } from '../src/lib/rate-limiter';
import { resetSessions } from '../src/lib/session';

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

	beforeEach(() => {
		resetAllRateLimits();
		resetSessions();
	});

		afterEach(() => {
			vi.restoreAllMocks();
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

	describe('POST /mcp - Origin header validation', () => {
		it('rejects requests with unauthorized Origin header', async () => {
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					Origin: 'http://evil.com',
				},
				body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(403);
		});

		it('allows requests without Origin header (non-browser clients)', async () => {
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

		it('allows requests with same-origin Origin header', async () => {
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					Origin: 'http://example.com',
				},
				body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(200);
		});

		it('allows requests with explicitly allowed Origin', async () => {
			const allowedEnv = { ...env, ALLOWED_ORIGINS: 'http://myapp.com,http://other.com' } as Env;
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					Origin: 'http://myapp.com',
				},
				body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, allowedEnv, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(200);
		});
	});

	describe('POST /mcp - JSON-RPC batch rejection', () => {
		it('rejects JSON-RPC batch arrays with clear error message', async () => {
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify([
					{ jsonrpc: '2.0', id: 1, method: 'ping' },
					{ jsonrpc: '2.0', id: 2, method: 'ping' },
				]),
			});
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(400);
			const body = (await response.json()) as { error: { code: number; message: string } };
			expect(body.error.code).toBe(-32600);
			expect(body.error.message).toContain('batch');
		});
	});

	describe('GET /health', () => {
		it('returns status ok (unit style)', async () => {
			const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/health');
			const ctx = createExecutionContext();
			const response = await worker.fetch(request, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(200);
			const body = (await response.json()) as { status: string; service: string; analytics: { enabled: boolean } };
			expect(body.status).toBe('ok');
			expect(body.service).toBe('bv-dns-security-mcp');
			expect(typeof body.analytics.enabled).toBe('boolean');
		});

		it('returns status ok (integration style)', async () => {
			const response = await SELF.fetch('http://example.com/health');
			expect(response.status).toBe(200);
			const body = (await response.json()) as { status: string; service: string; analytics: { enabled: boolean } };
			expect(body.status).toBe('ok');
			expect(body.service).toBe('bv-dns-security-mcp');
			expect(typeof body.analytics.enabled).toBe('boolean');
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
			expect(body.result.serverInfo.name).toBe('Blackveil DNS');
			expect(body.result.protocolVersion).toBe('2025-03-26');
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
			expect(lastResponse!.status).toBe(429);
			expect(lastResponse!.headers.get('retry-after')).toBeTruthy();
		});
	});

	describe('POST /mcp - tools/list', () => {
		it('returns all 11 tools', async () => {
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
			expect(body.result.tools).toHaveLength(14);
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
			expect(body.result.content[0].text).toContain('Error: An unexpected error occurred');
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
			expect(body.result.content[0].text).toContain('Error: An unexpected error occurred');
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
			expect(body.result.content[0].text).toContain('Error: An unexpected error occurred');
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
			expect(body.result.content[0].text).toContain('Error: An unexpected error occurred');
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
		it('POST with Accept: text/event-stream returns SSE with event ID', async () => {
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
			// Fix 5: SSE events must include an id for resumability
			expect(text).toContain('id: 1');
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

		it('GET /mcp returns 404 for expired/invalid session ID', async () => {
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

		it('GET /mcp returns 400 when no session header is provided', async () => {
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
		});
	});

	describe('Streamable HTTP transport - DELETE session', () => {
		it('DELETE /mcp terminates session and subsequent requests get 404', async () => {
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

		it('DELETE /mcp returns 404 for invalid session', async () => {
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
			for (let i = 0; i < 15; i++) {
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
				if (response.status === 429) {
					rateLimited = true;
					break;
				}
			}
			expect(rateLimited).toBe(true);
		});

		it('tools/call notifications consume exactly one rate-limit unit per request', async () => {
			const sessionId = await initSession();

			for (let i = 0; i < 10; i++) {
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

			const eleventhRequest = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
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
			const response = await worker.fetch(eleventhRequest, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(response.status).toBe(429);
		});

		it('unauthenticated scan_domain requests are capped at 10/day', async () => {
			vi.useFakeTimers();
			vi.setSystemTime(new Date('2026-03-07T00:00:00Z'));

			try {
			const sessionId = await initSession();

			for (let i = 0; i < 10; i++) {
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
			expect(blockedResponse.status).toBe(429);
			expect(blockedResponse.headers.get('x-quota-limit')).toBe('10');
			expect(blockedResponse.headers.get('x-quota-remaining')).toBe('0');

			const body = (await blockedResponse.json()) as { error: { code: number; message: string } };
			expect(body.error.code).toBe(-32029);
			expect(body.error.message).toContain('scan_domain');
			expect(body.error.message).toContain('10 requests per day');
			} finally {
				vi.useRealTimers();
			}
		});

		it('unauthenticated check_lookalikes requests are capped at 5/day', async () => {
			vi.useFakeTimers();
			vi.setSystemTime(new Date('2026-03-07T00:00:00Z'));

			try {
			const sessionId = await initSession();

			for (let i = 0; i < 5; i++) {
				const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
					method: 'POST',
					headers: {
						'Content-Type': 'application/json',
						'Mcp-Session-Id': sessionId,
						'cf-connecting-ip': '203.0.113.79',
					},
					body: JSON.stringify({
						jsonrpc: '2.0',
						id: i + 400,
						method: 'tools/call',
						params: { name: 'check_lookalikes', arguments: { domain: 'example.com' } },
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
					'cf-connecting-ip': '203.0.113.79',
				},
				body: JSON.stringify({
					jsonrpc: '2.0',
					id: 405,
					method: 'tools/call',
					params: { name: 'check_lookalikes', arguments: { domain: 'example.com' } },
				}),
			});
			const ctx = createExecutionContext();
			const blockedResponse = await worker.fetch(blockedRequest, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(blockedResponse.status).toBe(429);
			expect(blockedResponse.headers.get('x-quota-limit')).toBe('5');
			expect(blockedResponse.headers.get('x-quota-remaining')).toBe('0');

			const body = (await blockedResponse.json()) as { error: { code: number; message: string } };
			expect(body.error.code).toBe(-32029);
			expect(body.error.message).toContain('check_lookalikes');
			expect(body.error.message).toContain('5 requests per day');
			} finally {
				vi.useRealTimers();
			}
		});

		it('authenticated check_lookalikes requests bypass daily cap', async () => {
			const authEnv = { ...env, BV_API_KEY: TEST_API_KEY } as Env;
			const sessionId = await initSession({ authToken: TEST_API_KEY, targetEnv: authEnv });

			for (let i = 0; i < 6; i++) {
				const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
					method: 'POST',
					headers: {
						'Content-Type': 'application/json',
						Authorization: `Bearer ${TEST_API_KEY}`,
						'Mcp-Session-Id': sessionId,
						'cf-connecting-ip': '203.0.113.89',
					},
					body: JSON.stringify({
						jsonrpc: '2.0',
						id: i + 500,
						method: 'tools/call',
						params: { name: 'check_lookalikes', arguments: { domain: 'example.com' } },
					}),
				});
				const ctx = createExecutionContext();
				const response = await worker.fetch(request, authEnv, ctx);
				await waitOnExecutionContext(ctx);
				expect(response.status).toBe(200);
				expect(response.headers.has('x-quota-limit')).toBe(false);
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
				expect(response.headers.has('x-quota-limit')).toBe(false);
			}
		});

		it('protocol methods use a separate control-plane budget from tools/call', async () => {
			// Exhaust the rate limit with tools/call requests first
			const sessionId = await initSession();
			for (let i = 0; i < 15; i++) {
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

		it('throttles unauthenticated control-plane traffic separately', async () => {
			const sessionId = await initSession();

			for (let i = 0; i < 30; i++) {
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

			const blockedRequest = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'Mcp-Session-Id': sessionId,
					'cf-connecting-ip': '203.0.113.55',
				},
				body: JSON.stringify({ jsonrpc: '2.0', id: 999, method: 'ping', params: {} }),
			});
			const ctx = createExecutionContext();
			const blockedResponse = await worker.fetch(blockedRequest, env, ctx);
			await waitOnExecutionContext(ctx);
			expect(blockedResponse.status).toBe(429);
			expect(blockedResponse.headers.get('x-ratelimit-limit')).toBe('30');
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
