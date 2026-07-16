// SPDX-License-Identifier: BUSL-1.1

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { resetAllRateLimits, resetGlobalDailyLimit, resetConcurrencyLimits } from '../src/lib/rate-limiter';
import { resetSessions } from '../src/lib/session';
import {
	CONTRACT_FLAGGED_TOOLS,
	ENUMERABLE_RECON_UPGRADE_TOOLS,
	CONTRACT_FLAG_BYPASS_TIERS,
	isContractFlagGateEnabled,
	isContractFlaggedTool,
	contractFlagBlocks,
} from '../src/lib/config';
import type { ExecuteMcpRequestOptions } from '../src/mcp/execute';
import type { JsonRpcRequest } from '../src/lib/json-rpc';

function baseOptions(overrides: Partial<ExecuteMcpRequestOptions> = {}): ExecuteMcpRequestOptions {
	return {
		body: { jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} } as JsonRpcRequest,
		allowStreaming: false,
		batchMode: false,
		batchSize: 1,
		responseTransport: 'json',
		startTime: Date.now(),
		ip: '203.0.113.1',
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
	vi.restoreAllMocks();
	vi.resetModules();
});

// ---------------------------------------------------------------------------
// Pure decision-function unit tests
// ---------------------------------------------------------------------------

describe('contract-flag gate — primitives', () => {
	it('CONTRACT_FLAGGED_TOOLS is exactly the enumerable-recon set', () => {
		expect(CONTRACT_FLAGGED_TOOLS).toBe(ENUMERABLE_RECON_UPGRADE_TOOLS);
		expect(isContractFlaggedTool('discover_subdomains')).toBe(true);
		expect(isContractFlaggedTool('batch_scan')).toBe(false); // self-serve, not flagged
		expect(isContractFlaggedTool('scan_domain')).toBe(false); // free, not gated
	});

	it('isContractFlagGateEnabled defaults OFF unless the env is exactly "true"', () => {
		expect(isContractFlagGateEnabled(undefined)).toBe(false);
		expect(isContractFlagGateEnabled('')).toBe(false);
		expect(isContractFlagGateEnabled('false')).toBe(false);
		expect(isContractFlagGateEnabled('1')).toBe(false);
		expect(isContractFlagGateEnabled('TRUE')).toBe(false);
		expect(isContractFlagGateEnabled('true')).toBe(true);
	});

	it('only owner bypasses the gate', () => {
		expect(CONTRACT_FLAG_BYPASS_TIERS.has('owner')).toBe(true);
		for (const tier of ['developer', 'enterprise', 'partner', 'agent', 'free']) {
			expect(CONTRACT_FLAG_BYPASS_TIERS.has(tier)).toBe(false);
		}
	});

	it('gate OFF never blocks (true no-op)', () => {
		expect(
			contractFlagBlocks({ gateEnabled: false, tier: 'developer', tool: 'discover_subdomains', hasContractFlag: false }),
		).toBe(false);
	});

	it('gate ON blocks a paid tier hitting a flagged tool without the flag', () => {
		expect(
			contractFlagBlocks({ gateEnabled: true, tier: 'developer', tool: 'discover_subdomains', hasContractFlag: false }),
		).toBe(true);
	});

	it('gate ON allows when the caller carries the contract flag', () => {
		expect(
			contractFlagBlocks({ gateEnabled: true, tier: 'developer', tool: 'discover_subdomains', hasContractFlag: true }),
		).toBe(false);
	});

	it('gate ON allows a bypass tier (owner) without the flag', () => {
		expect(
			contractFlagBlocks({ gateEnabled: true, tier: 'owner', tool: 'discover_subdomains', hasContractFlag: false }),
		).toBe(false);
	});

	it('gate ON allows a non-flagged tool (self-serve / free) regardless', () => {
		expect(contractFlagBlocks({ gateEnabled: true, tier: 'developer', tool: 'batch_scan', hasContractFlag: false })).toBe(false);
		expect(contractFlagBlocks({ gateEnabled: true, tier: 'developer', tool: 'scan_domain', hasContractFlag: false })).toBe(false);
	});
});

// ---------------------------------------------------------------------------
// Integration through executeMcpRequest
// ---------------------------------------------------------------------------

function mockAllowedDownstream() {
	vi.doMock('../src/mcp/dispatch', () => ({
		dispatchMcpMethod: vi.fn().mockResolvedValue({
			kind: 'success',
			payload: { jsonrpc: '2.0', id: 1, result: { content: [] } },
			headers: {},
			newSessionId: undefined,
			logTool: 'discover_subdomains',
			logCategory: 'tool',
			logResult: 'ok',
			logDetails: {},
		}),
	}));
	vi.doMock('../src/lib/rate-limiter', async (importOriginal) => {
		const actual = await importOriginal<typeof import('../src/lib/rate-limiter')>();
		return {
			...actual,
			checkToolDailyRateLimit: vi.fn().mockResolvedValue({ allowed: true, remaining: 499, limit: 500 }),
			acquireConcurrencySlot: vi.fn().mockReturnValue({ allowed: true, active: 1, limit: 10 }),
			releaseConcurrencySlot: vi.fn(),
		};
	});
}

function callDeveloper(overrides: Partial<ExecuteMcpRequestOptions>, tool = 'discover_subdomains', contractFlag = false, tier = 'developer') {
	return baseOptions({
		body: {
			jsonrpc: '2.0',
			id: 1,
			method: 'tools/call',
			params: { name: tool, arguments: { domain: 'example.com' } },
		} as JsonRpcRequest,
		isAuthenticated: true,
		tierAuthResult: { authenticated: true, tier: tier as never, keyHash: 'k_dev', contractFlag },
		authTier: tier as never,
		...overrides,
	});
}

describe('contract-flag gate — executeMcpRequest', () => {
	it('gate OFF (default): developer reaches a flagged tool (no 403) — proves the merge is inert', async () => {
		mockAllowedDownstream();
		const { executeMcpRequest } = await import('../src/mcp/execute');
		// contractFlagGateEnabled omitted → undefined → OFF
		const result = await executeMcpRequest(callDeveloper({}));
		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		expect(result.httpStatus).not.toBe(403);
		expect((result.payload as { error?: { code: number } }).error?.code).not.toBe(-32003);
	});

	it('gate ON: developer without the flag hitting a flagged tool → 403 sales channel', async () => {
		const { executeMcpRequest } = await import('../src/mcp/execute');
		const result = await executeMcpRequest(callDeveloper({ contractFlagGateEnabled: true }));
		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		expect(result.httpStatus).toBe(403);
		const payload = result.payload as {
			error: { code: number; data?: { upgrade?: { channel: string; url: string } } };
		};
		expect(payload.error.code).toBe(-32003);
		expect(payload.error.data?.upgrade).toMatchObject({ channel: 'sales', url: 'https://blackveilsecurity.com/contact' });
	});

	it('gate ON: developer WITH the contract flag reaches the flagged tool (no 403)', async () => {
		mockAllowedDownstream();
		const { executeMcpRequest } = await import('../src/mcp/execute');
		const result = await executeMcpRequest(callDeveloper({ contractFlagGateEnabled: true }, 'discover_subdomains', true));
		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		expect(result.httpStatus).not.toBe(403);
	});

	it('gate ON: developer hitting a NON-flagged self-serve tool (batch_scan) is unaffected', async () => {
		mockAllowedDownstream();
		const { executeMcpRequest } = await import('../src/mcp/execute');
		const result = await executeMcpRequest(callDeveloper({ contractFlagGateEnabled: true }, 'batch_scan'));
		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		expect(result.httpStatus).not.toBe(403);
	});
});
