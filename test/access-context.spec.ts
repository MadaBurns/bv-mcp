// SPDX-License-Identifier: BUSL-1.1

import { afterEach, describe, expect, it, vi } from 'vitest';
import type { JsonRpcRequest } from '../src/lib/json-rpc';
import type { ExecuteMcpRequestOptions } from '../src/mcp/execute';

const body = (args: unknown = {}): JsonRpcRequest => ({
	jsonrpc: '2.0',
	id: 1,
	method: 'tools/call',
	params: { name: 'get_access_context', arguments: args },
});
const owner = { authenticated: true, tier: 'owner' as const, keyHash: 'a'.repeat(64), ownerIpGate: 'allowed' as const };
const secret = 'receipt-test-secret-not-a-real-credential';
const options = { serverVersion: 'test-build', pseudonymSecret: secret };

afterEach(() => {
	vi.restoreAllMocks();
});

describe('access-context receipt', () => {
	it('returns keyed domain-separated pseudonyms without revealing raw identity or credential', async () => {
		const { handleAccessContextRequest } = await import('../src/mcp/access-context');
		const result = await handleAccessContextRequest(body(), owner, options);
		const payload = result.payload as { result: { structuredContent: Record<string, unknown> } };
		const receipt = payload.result.structuredContent;
		expect(receipt).toMatchObject({
			available: true,
			authenticated: true,
			effectiveTier: 'owner',
			ownerVerified: true,
			serverVersion: 'test-build',
		});
		expect(receipt.principalReference).toMatch(/^acp_v1_[a-f0-9]{64}$/);
		const again = await handleAccessContextRequest(body(), owner, options);
		expect((again.payload as typeof payload).result.structuredContent.principalReference).toBe(receipt.principalReference);
		const rotated = await handleAccessContextRequest(body(), owner, { ...options, pseudonymSecret: secret + '-rotated' });
		expect((rotated.payload as typeof payload).result.structuredContent.principalReference).not.toBe(receipt.principalReference);
		expect(JSON.stringify(result)).not.toContain(owner.keyHash);
		expect(JSON.stringify(result)).not.toContain(secret);
		expect(result.headers['cache-control']).toBe('no-store');
	});

	it('does not promote downgraded or absent gate evidence into owner verification', async () => {
		const { handleAccessContextRequest } = await import('../src/mcp/access-context');
		for (const auth of [
			{ ...owner, tier: 'partner' as const, ownerIpGate: 'denied' as const },
			{ ...owner, ownerIpGate: undefined },
		]) {
			const response = await handleAccessContextRequest(body(), auth, options);
			expect(
				(response.payload as { result: { structuredContent: { ownerVerified: boolean } } }).result.structuredContent.ownerVerified,
			).toBe(false);
		}
	});

	it('keeps unknown authentication unavailable and missing pseudonym inputs explicit', async () => {
		const { handleAccessContextRequest } = await import('../src/mcp/access-context');
		const response = await handleAccessContextRequest(body(), { authenticated: false, storageUnavailable: true }, options);
		expect(response.httpStatus).toBe(503);
		expect((response.payload as { result: { structuredContent: unknown } }).result.structuredContent).toMatchObject({
			available: false,
			authenticated: null,
		});
		const noSecret = await handleAccessContextRequest(body(), owner, { serverVersion: 'test-build' });
		expect((noSecret.payload as { result: { structuredContent: unknown } }).result.structuredContent).toMatchObject({
			principalReference: null,
			principalReferenceStatus: 'unavailable',
		});
	});

	it('rejects target/credential arguments and notifications without invoking outbound fetch', async () => {
		const fetchSpy = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('unexpected outbound request'));
		const { handleAccessContextRequest } = await import('../src/mcp/access-context');
		for (const args of [null, [], { domain: 'example.com' }, { tier: 'owner' }, { api_key: 'caller-value' }]) {
			expect((await handleAccessContextRequest(body(args), owner, options)).httpStatus).toBe(400);
		}
		const notification = { ...body() };
		delete notification.id;
		expect((await handleAccessContextRequest(notification, owner, options)).httpStatus).toBe(400);
		expect(fetchSpy).not.toHaveBeenCalled();
	});
});

describe('access-context ordered execution seam', () => {
	it('keeps the non-HTTP fallback unavailable without reading runtime storage or session options', async () => {
		const { handleToolsCall } = await import('../src/handlers/tools');
		const trap = new Proxy(
			{},
			{
				get: () => {
					throw new Error('unexpected runtime access');
				},
			},
		);
		const response = await handleToolsCall({ name: 'get_access_context', arguments: {} }, trap as never, trap as never);
		expect(response.structuredContent).toMatchObject({ available: false, authenticated: null, ownerVerified: false });
	});

	it('returns before quota/session/cache/job/storage/dispatch operations, and rejects batches', async () => {
		const { executeMcpRequest } = await import('../src/mcp/execute');
		const trap = new Proxy(
			{},
			{
				get: () => {
					throw new Error('unexpected stateful operation');
				},
			},
		);
		const base = {
			body: body(),
			allowStreaming: false,
			batchMode: false,
			batchSize: 1,
			responseTransport: 'json',
			startTime: Date.now(),
			ip: '203.0.113.5',
			isAuthenticated: true,
			validateSession: true,
			serverVersion: 'test-build',
			accessContext: { auth: owner, pseudonymSecret: secret },
			rateLimitKv: trap,
			sessionStore: trap,
			scanCache: trap,
			quotaCoordinator: trap,
			analytics: trap,
			brandAuditDb: trap,
			brandAuditQueue: trap,
		} as unknown as ExecuteMcpRequestOptions;
		const result = await executeMcpRequest(base);
		expect(result.kind === 'response' && result.httpStatus).toBe(200);
		const batch = await executeMcpRequest({ ...base, batchMode: true });
		expect(batch.kind === 'response' && batch.httpStatus).toBe(400);
		const unavailable = await executeMcpRequest({ ...base, accessContext: undefined });
		expect(unavailable.kind === 'response' && unavailable.httpStatus).toBe(503);
	});
});
