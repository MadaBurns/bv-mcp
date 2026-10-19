// SPDX-License-Identifier: BUSL-1.1

/**
 * The brand-audit queue consumer receives an `internalCall` closure from `src/index.ts`
 * that wraps `handleToolsCall` for the registrar deep-scan job. These specs drive the
 * Worker's `queue` entry point, capture the deps handed to the consumer, and run the
 * closure to prove it forwards the tool name, arguments and the queue invocation's env.
 *
 * `handleBrandAuditQueue` and `handleToolsCall` are replaced (hoisted vi.mock — the Workers
 * pool caches module namespaces) so no D1 / DNS work happens: only the wiring is under test.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { BrandAuditConsumerDeps } from '../src/queue/brand-audit-consumer';

const mocks = vi.hoisted(() => ({
	handleToolsCall: vi.fn(),
	handleBrandAuditQueue: vi.fn(),
}));

vi.mock('../src/handlers/tools', async (importOriginal) => {
	const orig = await importOriginal<typeof import('../src/handlers/tools')>();
	return { ...orig, handleToolsCall: mocks.handleToolsCall };
});

vi.mock('../src/queue/brand-audit-consumer', async (importOriginal) => {
	const orig = await importOriginal<typeof import('../src/queue/brand-audit-consumer')>();
	return { ...orig, handleBrandAuditQueue: mocks.handleBrandAuditQueue };
});

function executionContext(): ExecutionContext {
	return { waitUntil: vi.fn(), passThroughOnException: vi.fn() } as unknown as ExecutionContext;
}

function brandAuditBatch(): MessageBatch<unknown> {
	return {
		queue: 'brand-audit-queue',
		messages: [],
		retryAll: vi.fn(),
		ackAll: vi.fn(),
	} as unknown as MessageBatch<unknown>;
}

async function capturedDeps(envOverrides: Record<string, unknown>): Promise<BrandAuditConsumerDeps> {
	const { default: worker } = await import('../src');
	const env = { BRAND_AUDIT_DB: { prepare: vi.fn() }, ...envOverrides } as unknown as Parameters<NonNullable<typeof worker.queue>>[1];
	await worker.queue!(brandAuditBatch(), env, executionContext());
	expect(mocks.handleBrandAuditQueue).toHaveBeenCalledTimes(1);
	return mocks.handleBrandAuditQueue.mock.calls[0]![1] as BrandAuditConsumerDeps;
}

describe('Worker queue entry — brand-audit internalCall closure', () => {
	beforeEach(() => {
		mocks.handleToolsCall.mockReset();
		mocks.handleBrandAuditQueue.mockReset();
	});

	it('forwards the tool name and arguments to handleToolsCall with the queue env bindings', async () => {
		const scanCache = { get: vi.fn() } as unknown as KVNamespace;
		const whois = { fetch: vi.fn() };
		const infraProbe = { fetch: vi.fn() };
		const envelope = { content: [{ type: 'text', text: 'ok' }], structuredContent: { domain: 'contoso.com' } };
		mocks.handleToolsCall.mockResolvedValue(envelope);

		const deps = await capturedDeps({
			SCAN_CACHE: scanCache,
			PROVIDER_SIGNATURES_URL: 'https://signatures.example/sigs.json',
			SCAN_TIMEOUT_MS: '9000',
			PER_CHECK_TIMEOUT_MS: '4000',
			BV_DOH_ENDPOINT: 'https://doh.example/dns-query',
			BV_DOH_TOKEN: 'doh-token',
			BV_WHOIS: whois,
			BV_INFRA_PROBE: infraProbe,
		});
		expect(typeof deps.internalCall).toBe('function');

		const returned = await deps.internalCall!('scan_domain', { domain: 'contoso.com' });

		expect(returned).toBe(envelope);
		expect(mocks.handleToolsCall).toHaveBeenCalledTimes(1);
		const [request, kv, options] = mocks.handleToolsCall.mock.calls[0]!;
		expect(request).toEqual({ name: 'scan_domain', arguments: { domain: 'contoso.com' } });
		expect(kv).toBe(scanCache);
		expect(options).toMatchObject({
			providerSignaturesUrl: 'https://signatures.example/sigs.json',
			scanTimeoutMs: 9000,
			perCheckTimeoutMs: 4000,
			secondaryDoh: { endpoint: 'https://doh.example/dns-query', token: 'doh-token' },
			whoisBinding: whois,
			infraProbe,
		});
	});

	it('omits the secondary DoH resolver when BV_DOH_ENDPOINT is unset and propagates tool failures', async () => {
		mocks.handleToolsCall.mockRejectedValue(new Error('discover_subdomains exploded'));

		const deps = await capturedDeps({});

		await expect(deps.internalCall!('discover_subdomains', { domain: 'contoso.com' })).rejects.toThrow('discover_subdomains exploded');
		const [request, , options] = mocks.handleToolsCall.mock.calls[0]!;
		expect(request).toEqual({ name: 'discover_subdomains', arguments: { domain: 'contoso.com' } });
		expect(options.secondaryDoh).toBeUndefined();
	});
});
