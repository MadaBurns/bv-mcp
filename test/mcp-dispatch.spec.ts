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

		// `JsonRpcPayload` is the success|error union and `jsonRpcSuccess` types its `result`
		// as `unknown`, so narrow with an `in` check rather than reaching straight through.
		const { payload } = result;
		if (!('result' in payload)) throw new Error('expected a success payload');
		const initResult = payload.result as {
			serverInfo: { version: string; description: string };
			instructions: string;
			capabilities: { prompts: { listChanged: boolean } };
		};

		expect(initResult.serverInfo.version).toBe('1.0.0');
		expect(initResult.serverInfo.description).toBeTruthy();
		expect(typeof initResult.instructions).toBe('string');
		expect(initResult.instructions.length).toBeGreaterThan(0);
		expect(initResult.capabilities.prompts).toEqual({ listChanged: false });
		expect(auditSessionCreated).toHaveBeenCalledWith('203.0.113.11', 'session-abc');
	});

	it('derives serverInfo.description from the resources module constants, not an independent literal', async () => {
		// Drift guard for the "80+ checks across 20 categories" defect: dispatch.ts must read
		// TOOL_COUNT / CHECK_TOOL_COUNT / SCAN_CATEGORY_COUNT from ../handlers/resources rather
		// than hand-typing its own numbers. Mocking those exports to sentinel values and asserting
		// they surface in the description proves dispatch.ts actually imports and interpolates
		// them — a test that only pinned the current output string would still pass if dispatch.ts
		// went back to a hardcoded literal that happened to match today's counts, and would
		// silently stop catching the bug the moment either side's real count changed.
		vi.doMock('../src/lib/session', () => ({
			checkSessionCreateRateLimit: vi.fn().mockResolvedValue({ allowed: true }),
			createSession: vi.fn().mockResolvedValue('session-drift'),
		}));
		vi.doMock('../src/lib/audit', () => ({
			auditSessionCreated: vi.fn(),
		}));
		vi.doMock('../src/handlers/resources', () => ({
			handleResourcesList: vi.fn(),
			handleResourcesRead: vi.fn(),
			TOOL_COUNT: 111,
			CHECK_TOOL_COUNT: 222,
			SCAN_CATEGORY_COUNT: 333,
		}));

		const { dispatchMcpMethod } = await import('../src/mcp/dispatch');
		const result = await dispatchMcpMethod({
			id: 19,
			method: 'initialize',
			params: {},
			ip: '203.0.113.19',
			isAuthenticated: false,
			rateHeaders: {},
			serverVersion: '1.0.0',
		});

		expect(result.kind).toBe('success');
		if (result.kind !== 'success') throw new Error('expected success result');

		// `JsonRpcPayload` is the success|error union and `jsonRpcSuccess` types its `result`
		// as `unknown`, so narrow with an `in` check rather than reaching straight through.
		// The other tests in this file now follow the same shape (SQ-30, `test/typecheck-baseline.json`
		// is 0 for this file) — do not "simplify" any of them back to a bare reach-through.
		const { payload } = result;
		if (!('result' in payload)) throw new Error('expected a success payload');
		const { description } = (payload.result as { serverInfo: { description: string } })
			.serverInfo;

		// Each figure is named with its own unit — tools, check_* checks, and scan
		// categories are different counts and must not be interchangeable in the string.
		expect(description).toContain('111 MCP tools');
		expect(description).toContain('222 check_* checks');
		expect(description).toContain('333 scan categories');
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

	it('rate limits authenticated initialize requests too', async () => {
		const checkSessionCreateRateLimit = vi.fn().mockResolvedValue({ allowed: false, retryAfterMs: 2_000 });
		const createSession = vi.fn();
		vi.doMock('../src/lib/session', () => ({ checkSessionCreateRateLimit, createSession }));
		vi.doMock('../src/lib/audit', () => ({ auditSessionCreated: vi.fn() }));

		const { dispatchMcpMethod } = await import('../src/mcp/dispatch');
		const result = await dispatchMcpMethod({
			id: 3,
			method: 'initialize',
			params: {},
			ip: '203.0.113.13',
			isAuthenticated: true,
			rateHeaders: {},
			serverVersion: '1.0.0',
		});

		expect(result.kind).toBe('early-error');
		if (result.kind !== 'early-error') throw new Error('expected early-error result');
		expect(result.status).toBe(429);
		expect(result.headers['retry-after']).toBe('2');
		expect(checkSessionCreateRateLimit).toHaveBeenCalledOnce();
		expect(createSession).not.toHaveBeenCalled();
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
		const { payload } = result;
		if (!('result' in payload)) throw new Error('expected a success payload');
		const { prompts } = payload.result as { prompts: unknown[] };
		expect(prompts).toBeDefined();
		expect(Array.isArray(prompts)).toBe(true);
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
		const { payload } = result;
		if (!('result' in payload)) throw new Error('expected a success payload');
		const { messages } = payload.result as { messages: unknown[] };
		expect(messages).toBeDefined();
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
		const { payload } = result;
		if (!('error' in payload)) throw new Error('expected an error payload');
		expect(payload.error.code).toBe(-32601);
		expect(result.logResult).toBe('method_not_found');
	});
});
