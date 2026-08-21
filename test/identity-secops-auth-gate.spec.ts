// SPDX-License-Identifier: BUSL-1.1

/**
 * P1 security gate: the four identity_secops M365 tools (query_signins,
 * query_ual, get_ca_policies, assess_coverage) must NOT be reachable by an
 * unauthenticated public /mcp caller.
 *
 * Layer 1 (primary): executeMcpRequest never forwards a PUBLIC tools/call for
 *   an AUTH_REQUIRED_TOOLS member to the bv-web M365 proxy. Since 3.63.0 these
 *   tools are also in INTERNAL_ONLY_TOOLS (withdrawn from the catalog alongside
 *   the fail-closed tenant-read kill switch), and that gate short-circuits
 *   BEFORE tier branching — so the rejection is now the unknown-tool result for
 *   every caller, rather than the 401 the auth gate would have produced.
 *   The 401 gate is shadowed, not removed: it is what protects these tools if
 *   they are ever re-listed, and the SSOT block below keeps it pinned.
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
		it(`withholds ${tool} from an unauthenticated public caller and never dispatches`, async () => {
			let proxyInvoked = false;
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
					// Bind a proxy so "never reached" is a MEASURED fact, not an
					// artifact of there being nothing to reach.
					m365Proxy: {
						fetch: async () => {
							proxyInvoked = true;
							return new Response('{}', { status: 200 });
						},
					},
					m365ProxyAuthToken: 'internal-bearer',
				}),
			);

			expect(result.kind).toBe('response');
			if (result.kind !== 'response') throw new Error('expected response');
			// The P1 security property is unchanged and is what this pins: an
			// unauthenticated caller NEVER reaches bv-web's M365 proxy.
			expect(proxyInvoked).toBe(false);
			// Since 3.63.0 the rejection arrives EARLIER than the 401 auth gate —
			// INTERNAL_ONLY_TOOLS short-circuits first (execute.ts, before tier
			// branching), returning the unknown-tool result. Blocked sooner, and
			// without the 401's implicit "this tool exists" disclosure.
			expect(JSON.stringify(result.payload)).toContain('Unknown tool');
		});
	}

	// No existence leak: every tier gets the SAME answer. Previously the tiers
	// were distinguishable (401 unauthenticated / 403 "Upgrade required" free /
	// dispatch for developer), which told an unprivileged caller the tool exists.
	// Withdrawn from the catalog, they are indistinguishable from a typo.
	it('answers identically for unauthenticated, free and developer callers (no existence leak)', async () => {
		const { executeMcpRequest } = await import('../src/mcp/execute');

		async function callAs(overrides: Partial<ExecuteMcpRequestOptions>): Promise<string> {
			const result = await executeMcpRequest(
				baseOptions({
					body: {
						jsonrpc: '2.0',
						id: 201,
						method: 'tools/call',
						params: { name: 'query_signins', arguments: { ms_tenant_id: 'tenant-abc' } },
					} as JsonRpcRequest,
					...overrides,
				}),
			);
			if (result.kind !== 'response') throw new Error('expected response');
			return JSON.stringify(result.payload);
		}

		const anonymous = await callAs({ isAuthenticated: false });
		const free = await callAs({
			isAuthenticated: true,
			tierAuthResult: { authenticated: true, tier: 'free', keyHash: 'k_free' },
			authTier: 'free',
		});
		const developer = await callAs({
			isAuthenticated: true,
			tierAuthResult: { authenticated: true, tier: 'developer', keyHash: 'k_dev' },
			authTier: 'developer',
		});

		expect(anonymous).toContain('Unknown tool');
		expect(free).toBe(anonymous);
		expect(developer).toBe(anonymous);
	});

	// The 401 auth gate is now SHADOWED for these tools (internal-only rejects
	// first), so it can no longer be exercised through the public path. It is
	// deliberately NOT deleted: re-listing the tools restores it. This invariant
	// is the tripwire for that future — a tool may leave INTERNAL_ONLY_TOOLS only
	// while it is still auth-required, so it can never become publicly reachable
	// AND unauthenticated in one edit.
	it('every auth-required tool is currently withheld from the public catalog', async () => {
		const { INTERNAL_ONLY_TOOLS } = await import('../src/lib/config');
		for (const tool of AUTH_REQUIRED_TOOLS) {
			expect(INTERNAL_ONLY_TOOLS.has(tool), `${tool} is auth-required but publicly listed`).toBe(true);
		}
	});
});

// ---------------------------------------------------------------------------
// Layer 1: the PUBLIC path reaches nothing, at any privilege level.
//
// This was previously the inverse assertion — that an authenticated caller
// REACHED the proxy — guarding a prod regression where execute.ts failed to
// forward `keyHash` into dispatch and so rejected every authenticated caller.
// Since 3.63.0 the tools are withdrawn from the public catalog, so the public
// path must reach the proxy for NOBODY. The keyHash-forwarding regression stays
// covered one layer down, by the Layer-2 handleToolsCall test below
// ("forwards to the proxy when a real keyHash IS present"), which is also the
// path that comes back to life if the tools are ever re-listed.
//
// Kept end-to-end and UNMOCKED (real dispatch): a mocked dispatch could hide a
// public path that still reaches the registry.
// ---------------------------------------------------------------------------

describe('executeMcpRequest — the public path reaches no identity_secops tool', () => {
	it('does not invoke the M365 proxy for a fully authenticated developer-tier query_signins call (real dispatch)', async () => {
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
		// Everything that would have let this call through is present — a real
		// principal (keyHash), a bound proxy, an internal bearer, a paid tier —
		// so a green here is the catalog withdrawal doing the work, nothing else.
		expect(proxyInvoked).toBe(false);
		expect(JSON.stringify(result.payload)).toContain('Unknown tool');

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
