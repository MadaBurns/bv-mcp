import { afterEach, describe, expect, it, vi } from 'vitest';

afterEach(() => {
	vi.restoreAllMocks();
	vi.resetModules();
});

describe('mcp-dispatch', () => {
	it('returns initialize success with a new session id', async () => {
		const auditSessionCreated = vi.fn();

		vi.doMock('../src/lib/session', () => ({
			checkSessionCreateRateLimit: vi.fn().mockResolvedValue({ allowed: true }),
			createSession: vi.fn().mockResolvedValue('session-abc'),
		}));
		vi.doMock('../src/lib/audit', () => ({
			auditSessionCreated,
		}));

		const { dispatchMcpMethod } = await import('../src/mcp/dispatch');
		const result = await dispatchMcpMethod({
			id: 1,
			method: 'initialize',
			params: {},
			ip: '203.0.113.11',
			isAuthenticated: false,
			rateHeaders: {},
			serverVersion: '1.0.0',
		});

		expect(result.kind).toBe('success');
		if (result.kind !== 'success') throw new Error('expected success result');
		expect(result.newSessionId).toBe('session-abc');
		expect(result.payload.result.serverInfo.version).toBe('1.0.0');
		expect(result.payload.result.serverInfo.description).toBeTruthy();
		expect(typeof result.payload.result.instructions).toBe('string');
		expect(result.payload.result.instructions.length).toBeGreaterThan(0);
		expect(result.payload.result.capabilities.prompts).toEqual({ listChanged: false });
		expect(auditSessionCreated).toHaveBeenCalledWith('203.0.113.11', 'session-abc');
	});

	it('returns an early 429 initialize error when session creation is rate limited', async () => {
		vi.doMock('../src/lib/session', () => ({
			checkSessionCreateRateLimit: vi.fn().mockResolvedValue({ allowed: false, retryAfterMs: 1000 }),
			createSession: vi.fn(),
		}));
		vi.doMock('../src/lib/audit', () => ({
			auditSessionCreated: vi.fn(),
		}));

		const { dispatchMcpMethod } = await import('../src/mcp/dispatch');
		const result = await dispatchMcpMethod({
			id: 2,
			method: 'initialize',
			params: {},
			ip: '203.0.113.12',
			isAuthenticated: false,
			rateHeaders: { 'x-ratelimit-limit': '50' },
			serverVersion: '1.0.0',
		});

		expect(result.kind).toBe('early-error');
		if (result.kind !== 'early-error') throw new Error('expected early-error result');
		expect(result.status).toBe(429);
		expect(result.headers['retry-after']).toBe('1');
		expect(result.payload.error.code).toBe(-32029);
	});

	it('dispatches prompts/list and returns prompts array', async () => {
		const { dispatchMcpMethod } = await import('../src/mcp/dispatch');
		const result = await dispatchMcpMethod({
			id: 10,
			method: 'prompts/list',
			params: {},
			ip: '203.0.113.14',
			isAuthenticated: true,
			rateHeaders: {},
			serverVersion: '1.0.0',
		});

		expect(result.kind).toBe('success');
		if (result.kind !== 'success') throw new Error('expected success result');
		expect(result.payload.result.prompts).toBeDefined();
		expect(Array.isArray(result.payload.result.prompts)).toBe(true);
		expect(result.logCategory).toBe('prompts');
	});

	it('dispatches prompts/get and returns prompt messages', async () => {
		const { dispatchMcpMethod } = await import('../src/mcp/dispatch');
		const result = await dispatchMcpMethod({
			id: 11,
			method: 'prompts/get',
			params: { name: 'full-security-audit', arguments: { domain: 'example.com' } },
			ip: '203.0.113.15',
			isAuthenticated: true,
			rateHeaders: {},
			serverVersion: '1.0.0',
		});

		expect(result.kind).toBe('success');
		if (result.kind !== 'success') throw new Error('expected success result');
		expect(result.payload.result.messages).toBeDefined();
		expect(result.logCategory).toBe('prompts');
	});

	it('returns a method-not-found error for unsupported methods', async () => {
		const { dispatchMcpMethod } = await import('../src/mcp/dispatch');
		const result = await dispatchMcpMethod({
			id: 9,
			method: 'unknown/method',
			params: {},
			ip: '203.0.113.13',
			isAuthenticated: true,
			rateHeaders: {},
			serverVersion: '1.0.0',
		});

		expect(result.kind).toBe('success');
		if (result.kind !== 'success') throw new Error('expected success result');
		expect(result.payload.error.code).toBe(-32601);
		expect(result.logResult).toBe('method_not_found');
	});
});