// SPDX-License-Identifier: BUSL-1.1
//
// Security hotfix: map_csc_products is INTERNAL-ONLY. It stays registered in
// TOOL_DEFS/TOOLS (so it is callable on the /internal/tools/* path and usable
// internally by prioritize_csc_leads), but is hidden from and rejected on the
// PUBLIC /mcp surface. These tests pin all four halves of that contract:
//   1. isInternalOnlyTool / INTERNAL_ONLY_TOOLS membership.
//   2. handleToolsList (public) hides it → 80 tools; scan_domain still present.
//   3. TOOLS registry still contains it (length 81) — internal callability.
//   4. Public executeMcpRequest tools/call → unknown-tool result (NOT 403, NOT
//      executed), for both an unauthenticated and an authenticated owner caller.
//   5. handleToolsCall (the internal-path entrypoint) still executes it.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { resetAllRateLimits, resetGlobalDailyLimit, resetConcurrencyLimits } from '../src/lib/rate-limiter';
import { resetSessions } from '../src/lib/session';
import { handleToolsList } from '../src/handlers/tools';
import { TOOLS } from '../src/schemas/tool-definitions';
import { INTERNAL_ONLY_TOOLS, isInternalOnlyTool } from '../src/lib/config';
import type { ExecuteMcpRequestOptions } from '../src/mcp/execute';
import type { JsonRpcRequest } from '../src/lib/json-rpc';

const PUBLIC_TOOL_COUNT = TOOLS.length - INTERNAL_ONLY_TOOLS.size;

// Keep the internal-path execution assertion fast: stub scan + RDAP so
// mapCscProducts resolves without live DNS. (Mirrors map-csc-products.integration.test.ts.)
const mockScanDomain = vi.fn();
const mockCheckRdap = vi.fn();
vi.mock('../src/tools/scan-domain', () => ({ scanDomain: (...a: unknown[]) => mockScanDomain(...a) }));
vi.mock('../src/tools/check-rdap-lookup', async (importOriginal) => {
	const orig = await importOriginal<typeof import('../src/tools/check-rdap-lookup')>();
	return { ...orig, checkRdapLookup: (...a: unknown[]) => mockCheckRdap(...a) };
});

function baseOptions(overrides: Partial<ExecuteMcpRequestOptions> = {}): ExecuteMcpRequestOptions {
	return {
		body: { jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} } as JsonRpcRequest,
		allowStreaming: false,
		batchMode: false,
		batchSize: 1,
		responseTransport: 'json',
		startTime: Date.now(),
		ip: '203.0.113.9',
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
	mockScanDomain.mockReset();
	mockCheckRdap.mockReset();
});

describe('INTERNAL_ONLY_TOOLS membership', () => {
	it('map_csc_products is internal-only; scan_domain is not', () => {
		expect(isInternalOnlyTool('map_csc_products')).toBe(true);
		expect(isInternalOnlyTool('scan_domain')).toBe(false);
		expect(INTERNAL_ONLY_TOOLS.has('map_csc_products')).toBe(true);
	});
});

describe('tool registry vs public surface', () => {
	it('TOOLS still includes map_csc_products (internal callability preserved) — length 81', () => {
		expect(TOOLS.some((t) => t.name === 'map_csc_products')).toBe(true);
		expect(TOOLS.length).toBe(81);
	});

	it('handleToolsList hides map_csc_products and returns the public count (80)', () => {
		const { tools } = handleToolsList();
		const names = tools.map((t) => t.name);
		expect(names).not.toContain('map_csc_products');
		expect(names).toContain('scan_domain');
		expect(tools.length).toBe(PUBLIC_TOOL_COUNT);
		expect(tools.length).toBe(80);
	});
});

describe('executeMcpRequest — internal-only tool rejected on public /mcp', () => {
	it('unauthenticated public map_csc_products → unknown-tool result (200, not 403, not executed)', async () => {
		const { executeMcpRequest } = await import('../src/mcp/execute');
		const result = await executeMcpRequest(
			baseOptions({
				body: {
					jsonrpc: '2.0',
					id: 200,
					method: 'tools/call',
					params: { name: 'map_csc_products', arguments: { domain: 'example.com' } },
				} as JsonRpcRequest,
				isAuthenticated: false,
			}),
		);

		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		expect(result.httpStatus).toBe(200);
		expect(result.httpStatus).not.toBe(403);
		const payload = result.payload as {
			result?: { isError?: boolean; content?: { text?: string }[] };
			error?: { code?: number };
		};
		expect(payload.error).toBeUndefined();
		expect(payload.result?.isError).toBe(true);
		expect(payload.result?.content?.[0]?.text ?? '').toContain('Unknown tool');
		expect(mockScanDomain).not.toHaveBeenCalled();
	});

	it('authenticated OWNER-tier public map_csc_products is also rejected (removed from surface entirely)', async () => {
		const { executeMcpRequest } = await import('../src/mcp/execute');
		const result = await executeMcpRequest(
			baseOptions({
				body: {
					jsonrpc: '2.0',
					id: 201,
					method: 'tools/call',
					params: { name: 'map_csc_products', arguments: { domain: 'example.com' } },
				} as JsonRpcRequest,
				isAuthenticated: true,
				tierAuthResult: { authenticated: true, tier: 'owner', keyHash: 'k_owner' },
				authTier: 'owner',
			}),
		);

		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		expect(result.httpStatus).not.toBe(403);
		const payload = result.payload as {
			result?: { isError?: boolean; content?: { text?: string }[] };
			error?: { code?: number };
		};
		expect(payload.result?.isError).toBe(true);
		expect(payload.result?.content?.[0]?.text ?? '').toContain('Unknown tool');
		expect(mockScanDomain).not.toHaveBeenCalled();
	});
});

describe('handleToolsCall — internal path still executes map_csc_products', () => {
	it('resolves map_csc_products (does NOT return an unknown-tool error)', async () => {
		mockScanDomain.mockResolvedValue({ checks: [], score: { overall: 90, grade: 'A' } });
		mockCheckRdap.mockResolvedValue({ category: 'rdap', passed: true, score: 100, findings: [] });

		const { handleToolsCall } = await import('../src/handlers/tools');
		const result = await handleToolsCall({ name: 'map_csc_products', arguments: { domain: 'example.com' } });

		const text = result.content?.[0]?.text ?? '';
		expect(text).not.toContain('Unknown tool');
		expect(result.isError).not.toBe(true);
		expect(mockScanDomain).toHaveBeenCalled();
	});
});
