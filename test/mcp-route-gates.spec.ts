import { afterEach, describe, expect, it, vi } from 'vitest';

afterEach(() => {
	vi.restoreAllMocks();
	vi.resetModules();
});

describe('mcp-route-gates', () => {
	it('builds a 429 control-plane rate-limit response', async () => {
		vi.doMock('../src/lib/rate-limiter', () => ({
			checkControlPlaneRateLimit: vi.fn().mockResolvedValue({
				allowed: false,
				minuteRemaining: 0,
				retryAfterMs: 1500,
			}),
		}));

		const { buildControlPlaneRateLimitResponse } = await import('../src/mcp/route-gates');
		const response = await buildControlPlaneRateLimitResponse('203.0.113.9', undefined, 'tools/list', false, 7);

		expect(response).toBeInstanceOf(Response);
		expect(response?.status).toBe(429);
		expect(response?.headers.get('retry-after')).toBe('2');

		const body = (await response?.json()) as { error: { code: number; message: string } };
		expect(body.error.code).toBe(-32029);
		expect(body.error.message).toContain('Retry after 2s');
	});

	it('meters anonymous protocol traffic and every SSE connection while ordinary authenticated traffic remains exempt', async () => {
		const checkControlPlaneRateLimit = vi.fn().mockResolvedValue({
			allowed: true,
			minuteRemaining: 59,
			hourRemaining: 599,
		});
		vi.doMock('../src/lib/rate-limiter', () => ({ checkControlPlaneRateLimit }));

		const { buildControlPlaneRateLimitResponse } = await import('../src/mcp/route-gates');
		for (const method of [
			'tools/list',
			'resources/list',
			'prompts/list',
			'prompts/get',
			'ping',
			'notifications/initialized',
			'sse/stream',
			'sse/connect',
		]) {
			expect(await buildControlPlaneRateLimitResponse('203.0.113.10', undefined, method, false, 1)).toBeUndefined();
		}
		expect(checkControlPlaneRateLimit).toHaveBeenCalledTimes(8);

		expect(await buildControlPlaneRateLimitResponse('203.0.113.10', undefined, 'tools/list', true, 2)).toBeUndefined();
		expect(await buildControlPlaneRateLimitResponse('203.0.113.10', undefined, 'initialize', false, 3)).toBeUndefined();
		expect(await buildControlPlaneRateLimitResponse('key:abc123', undefined, 'sse/stream', true, null)).toBeUndefined();
		expect(await buildControlPlaneRateLimitResponse('key:abc123', undefined, 'sse/connect', true, null)).toBeUndefined();
		expect(checkControlPlaneRateLimit).toHaveBeenCalledTimes(10);
		expect(checkControlPlaneRateLimit).toHaveBeenLastCalledWith('key:abc123', undefined, undefined, {
			enabled: false,
			salt: '',
		});
	});

	it('returns 404 with JSON-RPC error for invalid session headers', async () => {
		vi.doMock('../src/lib/session', () => ({
			checkSessionCreateRateLimit: vi.fn(),
			createSession: vi.fn(),
			validateSession: vi.fn().mockResolvedValue(false),
		}));

		const { validateSessionRequest } = await import('../src/mcp/route-gates');
		const result = await validateSessionRequest(
			'bad-session',
			undefined,
			3,
			'Bad Request: missing session. Send an initialize request first to create a session.',
		);

		expect(result).toBeTruthy();
		expect(result?.status).toBe(404);
		expect(result?.payload.error.code).toBe(-32600);
		expect(result?.payload.error.message).toContain('session expired or terminated');
	});

	it('returns 400 for missing session header', async () => {
		const { validateSessionRequest } = await import('../src/mcp/route-gates');
		const result = await validateSessionRequest(
			undefined,
			undefined,
			3,
			'Bad Request: missing session. Send an initialize request first to create a session.',
		);

		expect(result).toBeTruthy();
		expect(result?.status).toBe(400);
		expect(result?.payload.error.code).toBe(-32600);
		expect(result?.payload.error.message).toContain('Bad Request: missing session');
	});

	it('returns 400 for SSE when no session is provided', async () => {
		const { resolveSseSession } = await import('../src/mcp/route-gates');
		const result = await resolveSseSession({
			sessionId: undefined,
			ip: '203.0.113.10',
			rateLimitKv: undefined,
			sessionStore: undefined,
		});

		expect(result.response).toBeInstanceOf(Response);
		expect(result.response?.status).toBe(400);
	});

	it('returns 404 for SSE when session is invalid', async () => {
		vi.doMock('../src/lib/session', () => ({
			checkSessionCreateRateLimit: vi.fn(),
			createSession: vi.fn(),
			validateSession: vi.fn().mockResolvedValue(false),
		}));

		const { resolveSseSession } = await import('../src/mcp/route-gates');
		const result = await resolveSseSession({
			sessionId: 'expired-session',
			ip: '203.0.113.10',
			rateLimitKv: undefined,
			sessionStore: undefined,
		});

		expect(result.response).toBeInstanceOf(Response);
		expect(result.response?.status).toBe(404);
	});
});
