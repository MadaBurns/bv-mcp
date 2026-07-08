// SPDX-License-Identifier: BUSL-1.1

/**
 * P1 security gate: the four identity_secops M365 tools (query_signins,
 * query_ual, get_ca_policies, assess_coverage) must NOT be reachable by an
 * unauthenticated public /mcp caller.
 *
 * Layer 1 (primary): executeMcpRequest rejects an unauthenticated tools/call
 *   for any AUTH_REQUIRED_TOOLS member BEFORE dispatch (HTTP 401, UNAUTHORIZED
 *   code, allowlisted "Invalid" message prefix), never forwarding to the bv-web
 *   M365 proxy with the trusted internal bearer.
 *
 * Layer 2 (defense-in-depth): the registry execute path hard-rejects when there
 *   is no real principal (no keyHash), so even an internal/bypass caller cannot
 *   forward keyHash:undefined alongside the internal bearer. The proxy fetch is
 *   never invoked.
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { resetAllRateLimits, resetGlobalDailyLimit, resetConcurrencyLimits } from '../src/lib/rate-limiter';
import { resetSessions } from '../src/lib/session';
import { AUTH_REQUIRED_TOOLS, isAuthRequiredTool } from '../src/lib/config';
import { TOOLS } from '../src/schemas/tool-definitions';
import type { ExecuteMcpRequestOptions } from '../src/mcp/execute';
import type { JsonRpcRequest } from '../src/lib/json-rpc';

const IDENTITY_SECOPS_TOOLS = ['query_signins', 'query_ual', 'get_ca_policies', 'assess_coverage'] as const;

// Derived from the REAL registry, not a hardcoded literal: every tool whose
// group is `identity_secops` forwards to bv-web's internal M365 proxy and MUST
// be auth-gated. This is the tripwire — a new identity_secops tool added to
// TOOL_DEFS without being added to AUTH_REQUIRED_TOOLS in config.ts ships
// UNGATED, and this derivation makes CI fail instead of staying green.
const REGISTRY_IDENTITY_SECOPS_TOOLS = TOOLS.filter((t) => t.group === 'identity_secops')
	.map((t) => t.name)
	.sort();

function baseOptions(overrides: Partial<ExecuteMcpRequestOptions> = {}): ExecuteMcpRequestOptions {
	return {
		body: { jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} } as JsonRpcRequest,
		allowStreaming: false,
		batchMode: false,
		batchSize: 1,
		responseTransport: 'json',
		startTime: Date.now(),
		ip: '203.0.113.7',
		isAuthenticated: false,
		validateSession: false,
		serverVersion: '2.3.0',
		...overrides,
	};
}

beforeEach(() => {
	resetAllRateLimits();
	resetGlobalDailyLimit();
	resetConcurrencyLimits();
	resetSessions();
});

afterEach(() => {
	// Dynamic imports inside each test provide isolation; no cross-test module mocks.
});

// ---------------------------------------------------------------------------
// SSOT
// ---------------------------------------------------------------------------

describe('AUTH_REQUIRED_TOOLS SSOT', () => {
	it('equals the set of identity_secops tools DERIVED from the registry (TOOL_DEFS)', () => {
		// Tripwire: if someone adds a new `group: identity_secops` tool to
		// TOOL_DEFS but forgets AUTH_REQUIRED_TOOLS in config.ts, the derived
		// registry set diverges and this assertion fails — the ungated tool
		// cannot ship green. Compared to the real registry, NOT a local literal.
		expect([...AUTH_REQUIRED_TOOLS].sort()).toEqual(REGISTRY_IDENTITY_SECOPS_TOOLS);
	});

	it('the registry currently has exactly the four known identity_secops tools', () => {
		// Anchors the derivation so a registry that loses its group labels can't
		// silently make the tripwire above trivially pass against an empty set.
		expect(REGISTRY_IDENTITY_SECOPS_TOOLS).toEqual([...IDENTITY_SECOPS_TOOLS].sort());
	});

	it('isAuthRequiredTool returns true for each identity_secops tool and false for a hygiene tool', () => {
		for (const t of IDENTITY_SECOPS_TOOLS) {
			expect(isAuthRequiredTool(t)).toBe(true);
		}
		expect(isAuthRequiredTool('check_spf')).toBe(false);
	});
});

// ---------------------------------------------------------------------------
// Layer 1: execute-level gate (primary)
// ---------------------------------------------------------------------------

describe('executeMcpRequest — identity_secops auth gate', () => {
	for (const tool of IDENTITY_SECOPS_TOOLS) {
		it(`rejects an unauthenticated tools/call for ${tool} BEFORE dispatch (HTTP 401)`, async () => {
			const { executeMcpRequest } = await import('../src/mcp/execute');
			const result = await executeMcpRequest(
				baseOptions({
					body: {
						jsonrpc: '2.0',
						id: 200,
						method: 'tools/call',
						params: { name: tool, arguments: { ms_tenant_id: 'tenant-abc' } },
					} as JsonRpcRequest,
					isAuthenticated: false,
				}),
			);

			expect(result.kind).toBe('response');
			if (result.kind !== 'response') throw new Error('expected response');
			expect(result.httpStatus).toBe(401);
			const payload = result.payload as { error: { code: number; message: string } };
			expect(payload.error.code).toBe(-32001);
			// Allowlisted prefix per sanitizeErrorMessage.
			expect(payload.error.message).toMatch(/^Invalid/);
			expect(result.useErrorEnvelope).toBe(true);
		});
	}

	it('does NOT reject an authenticated developer-tier caller for query_signins', async () => {
		const { executeMcpRequest } = await import('../src/mcp/execute');
		const result = await executeMcpRequest(
			baseOptions({
				body: {
					jsonrpc: '2.0',
					id: 201,
					method: 'tools/call',
					params: { name: 'query_signins', arguments: { ms_tenant_id: 'tenant-abc' } },
				} as JsonRpcRequest,
				isAuthenticated: true,
				tierAuthResult: { authenticated: true, tier: 'developer', keyHash: 'k_dev' },
				authTier: 'developer',
			}),
		);

		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		expect(result.httpStatus).not.toBe(401);
		const payload = result.payload as { error?: { code: number } } | undefined;
		expect(payload?.error?.code).not.toBe(-32001);
		expect(result.headers['x-quota-limit']).toBe('100');
	});

	it('rejects an authenticated free-tier identity-secops caller with upgrade required', async () => {
		const { executeMcpRequest } = await import('../src/mcp/execute');
		const result = await executeMcpRequest(
			baseOptions({
				body: {
					jsonrpc: '2.0',
					id: 202,
					method: 'tools/call',
					params: { name: 'query_signins', arguments: { ms_tenant_id: 'tenant-abc' } },
				} as JsonRpcRequest,
				isAuthenticated: true,
				tierAuthResult: { authenticated: true, tier: 'free', keyHash: 'k_free' },
				authTier: 'free',
			}),
		);

		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		expect(result.httpStatus).toBe(403);
		const payload = result.payload as { error?: { code: number; message: string } } | undefined;
		expect(payload?.error?.code).toBe(-32003);
		expect(payload?.error?.message).toContain('Upgrade required');
	});
});

// ---------------------------------------------------------------------------
// Layer 1 (regression): authenticated public caller must REACH the tool.
//
// This is the end-to-end integration test the prior coverage missed: it goes
// through executeMcpRequest (NOT handleToolsCall directly) and does NOT mock
// dispatch, so it exercises the real execute → dispatch → handleToolsCall
// keyHash wiring. With an authenticated principal (top-level options.keyHash
// set) and m365Proxy bound, the Layer-2 guard
// (`isAuthRequiredTool && m365Proxy && !keyHash`) MUST NOT fire — the missing
// `keyHash: options.keyHash` forward in execute.ts's dispatch option objects
// regressed this (live in prod), rejecting EVERY authenticated caller.
// ---------------------------------------------------------------------------

describe('executeMcpRequest — authenticated identity_secops caller reaches the tool (regression)', () => {
	it('does NOT return the m365_proxy_unauthenticated rejection for an authenticated query_signins call (real dispatch)', async () => {
		const { vi } = await import('vitest');
		// CRITICAL: do not let the line-103 test's dispatch mock leak in — a mocked
		// dispatch would return success regardless of the keyHash bug, masking RED.
		vi.resetModules();
		vi.doUnmock('../src/mcp/dispatch');
		// Real path crosses rate-limit + concurrency for a developer tier; mock only
		// those (NOT dispatch) so the call reaches the registry.
		vi.doMock('../src/lib/rate-limiter', async (importOriginal) => {
			const actual = await importOriginal<typeof import('../src/lib/rate-limiter')>();
			return {
				...actual,
				checkToolDailyRateLimit: vi.fn().mockResolvedValue({ allowed: true, remaining: 499, limit: 500 }),
				acquireConcurrencySlot: vi.fn().mockReturnValue({ allowed: true, active: 1, limit: 10 }),
				releaseConcurrencySlot: vi.fn(),
			};
		});

		let proxyInvoked = false;
		const m365Proxy = {
			fetch: async () => {
				proxyInvoked = true;
				return new Response(JSON.stringify({ signIns: [] }), { status: 200 });
			},
		};

		const { executeMcpRequest } = await import('../src/mcp/execute');
		const result = await executeMcpRequest(
			baseOptions({
				body: {
					jsonrpc: '2.0',
					id: 300,
					method: 'tools/call',
					params: { name: 'query_signins', arguments: { ms_tenant_id: 'tenant-abc' } },
				} as JsonRpcRequest,
				isAuthenticated: true,
				tierAuthResult: { authenticated: true, tier: 'developer', keyHash: 'k_dev_full' },
				authTier: 'developer',
				// Top-level keyHash is caller-populated (index.ts); executeMcpRequest
				// does NOT derive it from tierAuthResult — it must be forwarded into
				// dispatch's options so the Layer-2 guard sees a real principal.
				keyHash: 'k_dev_full',
				m365Proxy,
				m365ProxyAuthToken: 'internal-bearer',
			}),
		);

		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		// The tool/proxy must have been reached — the guard must NOT have rejected.
		const serialized = JSON.stringify(result.payload);
		expect(serialized).not.toContain('m365_proxy_unauthenticated');
		// Stronger assertion: the proxy fetch was actually invoked, proving keyHash
		// reached the registry and the call flowed all the way through.
		expect(proxyInvoked).toBe(true);

		vi.doUnmock('../src/lib/rate-limiter');
		vi.resetModules();
	});
});

// ---------------------------------------------------------------------------
// Layer 2: registry defense-in-depth (no principal → never forward)
// ---------------------------------------------------------------------------

describe('handleToolsCall — identity_secops no-principal hard reject', () => {
	function spyProxy(): { proxy: { fetch: typeof fetch }; called: () => boolean } {
		let invoked = false;
		return {
			proxy: {
				fetch: async () => {
					invoked = true;
					return new Response(JSON.stringify({ signIns: [] }), { status: 200 });
				},
			},
			called: () => invoked,
		};
	}

	for (const tool of IDENTITY_SECOPS_TOOLS) {
		it(`${tool}: returns an error and never calls the proxy fetch when keyHash is absent`, async () => {
			const { handleToolsCall } = await import('../src/handlers/tools');
			const { proxy, called } = spyProxy();

			const result = await handleToolsCall(
				{ name: tool, arguments: { ms_tenant_id: 'tenant-abc' } },
				undefined,
				{
					m365Proxy: proxy,
					m365ProxyAuthToken: 'internal-bearer',
					// keyHash intentionally omitted — no real principal.
				},
			);

			expect(called()).toBe(false);
			expect(result.isError).toBe(true);
			const text = result.content?.[0]?.type === 'text' ? result.content[0].text : '';
			expect(text).toContain('m365_proxy_unauthenticated');
		});
	}

	it('query_signins: forwards to the proxy when a real keyHash IS present', async () => {
		const { handleToolsCall } = await import('../src/handlers/tools');
		const { proxy, called } = spyProxy();

		const result = await handleToolsCall(
			{ name: 'query_signins', arguments: { ms_tenant_id: 'tenant-abc' } },
			undefined,
			{
				m365Proxy: proxy,
				m365ProxyAuthToken: 'internal-bearer',
				keyHash: 'k_real',
			},
		);

		expect(called()).toBe(true);
		expect(result.isError).toBeFalsy();
	});
});
