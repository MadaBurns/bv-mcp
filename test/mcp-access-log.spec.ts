// SPDX-License-Identifier: BUSL-1.1

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { resetAllRateLimits, resetConcurrencyLimits, resetGlobalDailyLimit } from '../src/lib/rate-limiter';
import { resetSessions } from '../src/lib/session';
import { fireAndForget, getLogger } from '../src/lib/log';
import type { JsonRpcRequest } from '../src/lib/json-rpc';

const sourceFiles = import.meta.glob('../src/mcp/execute.ts', { query: '?raw', import: 'default', eager: true }) as Record<string, string>;
const executeSource = sourceFiles['../src/mcp/execute.ts'];

function createFakeD1() {
	const run = vi.fn(async () => ({ success: true }));
	const bind = vi.fn(() => ({ run }));
	const prepare = vi.fn(() => ({ bind }));
	return { db: { prepare } as unknown as D1Database, prepare, bind, run };
}

async function waitForDeferredLog(waitUntil?: ReturnType<typeof vi.fn>): Promise<void> {
	const deferred = waitUntil?.mock.calls[0]?.[0] as Promise<unknown> | undefined;
	if (deferred) {
		await deferred;
		return;
	}
	await new Promise((resolve) => setTimeout(resolve, 0));
}

beforeEach(() => {
	resetAllRateLimits();
	resetGlobalDailyLimit();
	resetConcurrencyLimits();
	resetSessions();
});

afterEach(() => {
	vi.restoreAllMocks();
	vi.resetModules();
});

describe('MCP access logging helpers', () => {
	it('fireAndForget logs rejected work without throwing synchronously', async () => {
		const spy = vi.spyOn(console, 'log').mockImplementation(() => undefined);
		const logger = getLogger();

		fireAndForget(Promise.reject(new Error('d1 unavailable')), logger, 'mcp_access_log_insert');
		await new Promise((resolve) => setTimeout(resolve, 0));

		expect(spy.mock.calls.some((call) => String(call[0]).includes('mcp_access_log_insert'))).toBe(true);
		spy.mockRestore();
	});
});

describe('MCP client IP resolution', () => {
	it('returns "unknown" when CF-Connecting-IP is absent and ignores attacker-controlled forwarding headers', async () => {
		// CLAUDE.md security convention: cf-connecting-ip ONLY for IP-source decisions.
		// x-forwarded-for / x-real-ip / true-client-ip are attacker-controlled and must
		// never be trusted for owner-tier gating, rate limits, or per-IP quotas.
		const { resolveClientIpFromHeaders } = await import('../src/index');

		expect(
			resolveClientIpFromHeaders({
				'x-forwarded-for': '198.51.100.20, 203.0.113.30',
				'x-real-ip': '203.0.113.50',
				'true-client-ip': '203.0.113.60',
			}),
		).toBe('unknown');
	});

	it('returns CF-Connecting-IP when present, ignoring any forwarding headers', async () => {
		const { resolveClientIpFromHeaders } = await import('../src/index');

		expect(
			resolveClientIpFromHeaders({
				'cf-connecting-ip': '192.0.2.10',
				'x-forwarded-for': '198.51.100.20',
				'x-real-ip': '203.0.113.50',
			}),
		).toBe('192.0.2.10');
	});
});

describe('MCP access logging execution path', () => {
	it('defers a masked access-log insert after a tools/call response', async () => {
		vi.doMock('../src/mcp/dispatch', () => ({
			dispatchMcpMethod: vi.fn().mockResolvedValue({
				kind: 'success',
				payload: { jsonrpc: '2.0', id: 1, result: { content: [] } },
				headers: {},
				newSessionId: undefined,
				logTool: 'check_spf',
				logCategory: 'tool',
				logResult: 'ok',
				logDetails: {},
			}),
		}));

		const { executeMcpRequest } = await import('../src/mcp/execute');
		const fake = createFakeD1();
		const waitUntil = vi.fn();

		const result = await executeMcpRequest({
			body: {
				jsonrpc: '2.0',
				id: 1,
				method: 'tools/call',
				params: { name: 'check_spf', arguments: { domain: 'example.com' } },
			} as JsonRpcRequest,
			allowStreaming: false,
			batchMode: false,
			batchSize: 1,
			responseTransport: 'json',
			startTime: Date.now(),
			ip: '203.0.113.30',
			ipHash: 'i_testhash',
			isAuthenticated: true,
			validateSession: false,
			serverVersion: 'test',
			intelligenceDb: fake.db,
			waitUntil,
			country: 'NZ',
			userAgent: 'test-agent',
		});

		expect(result.kind).toBe('response');
		expect(waitUntil).toHaveBeenCalledWith(expect.any(Promise));
		await waitForDeferredLog(waitUntil);
		expect(fake.prepare.mock.calls[0]?.[0]).toContain('INSERT INTO mcp_access_log');
		expect(fake.bind).toHaveBeenCalledWith(
			'i_testhash',
			'203.0.113.xxx',
			'check_spf',
			'example.com',
			'NZ',
			null, // user_agent (gated at coarse default)
			expect.any(Number),
			0,
			null,
			null,
			null, // city
			null, // region
			null, // latitude
			null, // longitude
			null, // asn
			null, // as_org
			null, // ptr_hostname
			null, // key_hash
			null, // client_type
			null, // colo
			null, // session_hash
			'tools/call',
			'json',
			'pass',
			'public', // source
		);
	});

	it('keeps user_agent at bind position 6 when the PII level is standard', async () => {
		vi.doMock('../src/mcp/dispatch', () => ({
			dispatchMcpMethod: vi.fn().mockResolvedValue({
				kind: 'success',
				payload: { jsonrpc: '2.0', id: 1, result: { content: [] } },
				headers: {},
				newSessionId: undefined,
				logTool: 'check_spf',
				logCategory: 'tool',
				logResult: 'ok',
				logDetails: {},
			}),
		}));

		const { executeMcpRequest } = await import('../src/mcp/execute');
		const fake = createFakeD1();
		const waitUntil = vi.fn();

		await executeMcpRequest({
			body: {
				jsonrpc: '2.0',
				id: 1,
				method: 'tools/call',
				params: { name: 'check_spf', arguments: { domain: 'example.com' } },
			} as JsonRpcRequest,
			allowStreaming: false,
			batchMode: false,
			batchSize: 1,
			responseTransport: 'json',
			startTime: Date.now(),
			ip: '203.0.113.30',
			ipHash: 'i_testhash',
			isAuthenticated: true,
			validateSession: false,
			serverVersion: 'test',
			intelligenceDb: fake.db,
			waitUntil,
			country: 'NZ',
			userAgent: 'test-agent',
			analyticsPiiLevel: 'standard',
		});

		await waitForDeferredLog(waitUntil);
		const bindArgs = fake.bind.mock.calls[0] ?? [];
		expect(bindArgs[5]).toBe('test-agent'); // user_agent preserved at standard
	});

	it('stores encrypted IP evidence when an encryption key is configured', async () => {
		vi.doMock('../src/mcp/dispatch', () => ({
			dispatchMcpMethod: vi.fn().mockResolvedValue({
				kind: 'success',
				payload: { jsonrpc: '2.0', id: 1, result: { content: [] } },
				headers: {},
				newSessionId: undefined,
				logTool: 'check_spf',
				logCategory: 'tool',
				logResult: 'ok',
				logDetails: {},
			}),
		}));

		const { executeMcpRequest } = await import('../src/mcp/execute');
		const fake = createFakeD1();
		const waitUntil = vi.fn();
		const key = 'MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=';

		await executeMcpRequest({
			body: {
				jsonrpc: '2.0',
				id: 1,
				method: 'tools/call',
				params: { name: 'check_spf', arguments: { domain: 'example.com' } },
			} as JsonRpcRequest,
			allowStreaming: false,
			batchMode: false,
			batchSize: 1,
			responseTransport: 'json',
			startTime: Date.now(),
			ip: '203.0.113.30',
			ipHash: 'i_testhash',
			isAuthenticated: true,
			validateSession: false,
			serverVersion: 'test',
			intelligenceDb: fake.db,
			waitUntil,
			analyticsPiiLevel: 'standard',
			ipEncryptionKey: key,
			ipEncryptionKeyVersion: 'test-v1',
		});

		await waitForDeferredLog(waitUntil);

		const sql = String(fake.prepare.mock.calls[0]?.[0]);
		const bindArgs = fake.bind.mock.calls[0] ?? [];
		expect(sql).toContain('ip_ciphertext');
		expect(sql).toContain('ip_key_version');
		expect(bindArgs).toContain('test-v1');
		expect(bindArgs).not.toContain('203.0.113.30');
		expect(bindArgs.some((value) => typeof value === 'string' && value.startsWith('v1:'))).toBe(true);
	});

	it('uses the first domains[] entry for multi-domain tools', async () => {
		vi.doMock('../src/mcp/dispatch', () => ({
			dispatchMcpMethod: vi.fn().mockResolvedValue({
				kind: 'success',
				payload: { jsonrpc: '2.0', id: 1, result: { content: [] } },
				headers: {},
				newSessionId: undefined,
				logTool: 'compare_domains',
				logCategory: 'tool',
				logResult: 'ok',
				logDetails: {},
			}),
		}));

		const { executeMcpRequest } = await import('../src/mcp/execute');
		const fake = createFakeD1();
		const waitUntil = vi.fn();

		await executeMcpRequest({
			body: {
				jsonrpc: '2.0',
				id: 1,
				method: 'tools/call',
				params: { name: 'compare_domains', arguments: { domains: ['example.com', 'example.net'] } },
			} as JsonRpcRequest,
			allowStreaming: false,
			batchMode: false,
			batchSize: 1,
			responseTransport: 'json',
			startTime: Date.now(),
			ip: '203.0.113.30',
			ipHash: 'i_testhash',
			isAuthenticated: true,
			validateSession: false,
			serverVersion: 'test',
			intelligenceDb: fake.db,
			waitUntil,
		});

		await waitForDeferredLog(waitUntil);
		expect(fake.bind).toHaveBeenCalledWith(
			'i_testhash',
			'203.0.113.xxx',
			'compare_domains',
			'example.com',
			null,
			null,
			expect.any(Number),
			0,
			null,
			null,
			null, // city
			null, // region
			null, // latitude
			null, // longitude
			null, // asn
			null, // as_org
			null, // ptr_hostname
			null, // key_hash
			null, // client_type
			null, // colo
			null, // session_hash
			'tools/call',
			'json',
			'pass',
			'public', // source
		);
	});

	it('does not insert for tools without domain-bearing arguments', async () => {
		vi.doMock('../src/mcp/dispatch', () => ({
			dispatchMcpMethod: vi.fn().mockResolvedValue({
				kind: 'success',
				payload: { jsonrpc: '2.0', id: 1, result: { content: [] } },
				headers: {},
				newSessionId: undefined,
				logTool: 'explain_finding',
				logCategory: 'tool',
				logResult: 'ok',
				logDetails: {},
			}),
		}));

		const { executeMcpRequest } = await import('../src/mcp/execute');
		const fake = createFakeD1();

		await executeMcpRequest({
			body: {
				jsonrpc: '2.0',
				id: 1,
				method: 'tools/call',
				params: { name: 'explain_finding', arguments: { finding: 'spf_missing' } },
			} as JsonRpcRequest,
			allowStreaming: false,
			batchMode: false,
			batchSize: 1,
			responseTransport: 'json',
			startTime: Date.now(),
			ip: '203.0.113.30',
			ipHash: 'i_testhash',
			isAuthenticated: true,
			validateSession: false,
			serverVersion: 'test',
			intelligenceDb: fake.db,
		});

		expect(fake.prepare).not.toHaveBeenCalled();
	});

	it('defers a rate_limited access-log row when tool quota denies the call', async () => {
		vi.doMock('../src/lib/rate-limiter', async (importOriginal) => {
			const actual = await importOriginal<typeof import('../src/lib/rate-limiter')>();
			return {
				...actual,
				checkGlobalDailyLimit: vi.fn().mockResolvedValue({ allowed: true, remaining: 499_999, limit: 500_000 }),
				checkRateLimit: vi.fn().mockResolvedValue({ allowed: true, minuteRemaining: 49, hourRemaining: 999 }),
				checkToolDailyRateLimit: vi.fn().mockResolvedValue({
					allowed: false,
					retryAfterMs: 86_400_000,
					remaining: 0,
					limit: 5,
				}),
			};
		});

		const { executeMcpRequest } = await import('../src/mcp/execute');
		const fake = createFakeD1();
		const waitUntil = vi.fn();

		const result = await executeMcpRequest({
			body: {
				jsonrpc: '2.0',
				id: 1,
				method: 'tools/call',
				params: { name: 'check_shadow_domains', arguments: { domain: 'example.com' } },
			} as JsonRpcRequest,
			allowStreaming: false,
			batchMode: false,
			batchSize: 1,
			responseTransport: 'json',
			startTime: Date.now(),
			ip: '203.0.113.30',
			ipHash: 'i_testhash',
			isAuthenticated: false,
			validateSession: false,
			serverVersion: 'test',
			intelligenceDb: fake.db,
			waitUntil,
		});

		expect(result.kind).toBe('response');
		await waitForDeferredLog(waitUntil);
		expect(fake.bind).toHaveBeenCalledWith(
			'i_testhash',
			'203.0.113.xxx',
			'check_shadow_domains',
			'example.com',
			null,
			null,
			expect.any(Number),
			1,
			null,
			null,
			null, // city
			null, // region
			null, // latitude
			null, // longitude
			null, // asn
			null, // as_org
			null, // ptr_hostname
			null, // key_hash
			null, // client_type
			null, // colo
			null, // session_hash
			'tools/call',
			'json',
			'unknown',
			'public', // source
		);
	});
});

describe('MCP access log retention', () => {
	it('scheduled cleanup deletes MCP access log rows older than 90 days', async () => {
		const run = vi.fn(async () => ({ success: true }));
		const bind = vi.fn(() => ({ run }));
		const prepare = vi.fn(() => ({ bind }));
		const env = {
			INTELLIGENCE_DB: { prepare },
		} as unknown as import('../src/scheduled').ScheduledEnv;
		const { handleScheduled } = await import('../src/scheduled');

		await handleScheduled(env);

		expect(prepare.mock.calls.some((call) => String(call[0]).includes('DELETE FROM mcp_access_log'))).toBe(true);
		expect(prepare.mock.calls.some((call) => String(call[0]).includes("strftime('%s', 'now') - ?"))).toBe(true);
		expect(bind).toHaveBeenCalledWith(90 * 24 * 3600);
	});
});

describe('MCP access log privacy guardrails', () => {
	it('does not define or insert raw ip_address for MCP access logging', () => {
		expect(executeSource).not.toContain('ip_address');
		expect(executeSource).not.toMatch(/\.bind\(\s*options\.ip\b/);
	});
});

describe('recordMcpAccessLog routing', () => {
	it('enqueues an AccessLogEvent when analyticsQueue is bound (no inline insert)', async () => {
		const mod = await import('../src/mcp/execute');
		const sent: unknown[] = [];
		const analyticsQueue = {
			send: async (m: unknown) => {
				sent.push(m);
			},
		};
		const prepare = vi.fn();
		const options = {
			intelligenceDb: { prepare } as unknown as D1Database,
			analyticsQueue,
			analyticsPiiLevel: 'full' as const,
			ip: '192.0.2.9',
			ipHash: 'i_x',
			country: 'NZ',
			region: 'AKL',
			city: 'Auckland',
			latitude: '-36.8',
			longitude: '174.7',
			asn: 13335,
			asOrg: 'Cloudflare',
			keyHash: 'abc',
			clientType: 'cursor',
			colo: 'AKL',
			sessionHash: 'none',
			userAgent: 'ua',
			responseTransport: 'json',
			startTime: Date.now(),
			waitUntil: (p: Promise<unknown>) => {
				void p;
			},
		};
		// @ts-expect-error — exercising the internal helper via the exported recorder
		mod.__recordMcpAccessLogForTest(options, { toolName: 'check_spf', domain: 'example.com', rateLimited: false, method: 'tools/call', status: 'pass' });
		await new Promise((r) => setTimeout(r, 0));
		expect(prepare).not.toHaveBeenCalled();
		expect(sent).toHaveLength(1);
		const ev = sent[0] as { ip: string; city: string | null; ptrHostname: string | null; source: string };
		expect(ev.ip).toBe('192.0.2.9');
		expect(ev.city).toBe('Auckland'); // full level keeps city
		expect(ev.ptrHostname).toBeNull(); // consumer fills it
		expect(ev.source).toBe('public'); // public default on the queue path
	});

	it('falls back to inline insert when analyticsQueue is absent', async () => {
		const mod = await import('../src/mcp/execute');
		const run = vi.fn(async () => ({ success: true }));
		const bind = vi.fn(() => ({ run }));
		const prepare = vi.fn(() => ({ bind }));
		const options = {
			intelligenceDb: { prepare } as unknown as D1Database,
			analyticsPiiLevel: 'coarse' as const,
			ip: '192.0.2.9',
			ipHash: 'i_x',
			country: 'NZ',
			responseTransport: 'json',
			startTime: Date.now(),
			waitUntil: (p: Promise<unknown>) => {
				void p;
			},
		};
		// @ts-expect-error — internal helper
		mod.__recordMcpAccessLogForTest(options, { toolName: 'check_spf', domain: 'example.com', rateLimited: true, method: 'tools/call', status: 'unknown' });
		await new Promise((r) => setTimeout(r, 0));
		expect(prepare).toHaveBeenCalledTimes(1);
		expect(String(prepare.mock.calls[0][0])).toContain('INSERT INTO mcp_access_log');
	});
});

describe('recordInternalAccessLog', () => {
	it('inline-inserts an internal-source row with unknown ip + null key_hash', async () => {
		const { recordInternalAccessLog } = await import('../src/mcp/execute');
		const fake = createFakeD1();
		const promises: Promise<unknown>[] = [];

		recordInternalAccessLog({
			toolName: 'check_spf',
			domain: 'example.com',
			status: 'pass',
			clientType: 'admin-analytics',
			intelligenceDb: fake.db,
			analyticsPiiLevel: 'coarse',
			startTime: Date.now(),
			waitUntil: (p: Promise<unknown>) => promises.push(p),
		});

		await Promise.all(promises);
		expect(fake.prepare.mock.calls[0]?.[0]).toContain('INSERT INTO mcp_access_log');
		expect(fake.bind).toHaveBeenCalledWith(
			'unknown', // ip_hash
			'unknown', // ip_masked
			'check_spf',
			'example.com',
			null, // country
			null, // user_agent
			expect.any(Number),
			0, // rate_limited
			null, // ip_ciphertext
			null, // ip_key_version
			null, // city
			null, // region
			null, // latitude
			null, // longitude
			null, // asn
			null, // as_org
			null, // ptr_hostname
			null, // key_hash
			'admin-analytics', // client_type ← x-bv-caller
			null, // colo
			null, // session_hash
			'tools/call',
			'internal', // transport
			'pass',
			'internal', // source
		);
	});
});
