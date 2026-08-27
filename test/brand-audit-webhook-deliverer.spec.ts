// SPDX-License-Identifier: BUSL-1.1

import { afterEach, describe, expect, it, vi } from 'vitest';
import { BRAND_WEBHOOK_PEER_SECRET_KEYS, defaultDeliverWebhook } from '../src/queue/brand-audit-consumer';
import { BRAND_AUDIT_WATCH_CHANGE_ROWS_MAX, BRAND_AUDIT_WATCH_WEBHOOK_MAX_BODY_BYTES } from '../src/schemas/brand-audit-watch-webhook';

const savedFetch = globalThis.fetch;

afterEach(() => {
	globalThis.fetch = savedFetch;
	vi.restoreAllMocks();
});

describe('defaultDeliverWebhook', () => {
	it('uses public safeFetch without an internal credential for customer URLs', async () => {
		const cancelled = vi.fn();
		const fetchMock = vi.fn().mockResolvedValue(new Response(new ReadableStream<Uint8Array>({ cancel: cancelled }), { status: 200 }));
		globalThis.fetch = fetchMock as unknown as typeof fetch;

		const delivered = await defaultDeliverWebhook('https://hooks.example.com/brand-audit', { auditId: 'audit-1' });

		expect(delivered).toBe(true);
		expect(cancelled).toHaveBeenCalledOnce();
		expect(fetchMock).toHaveBeenCalledOnce();
		const init = fetchMock.mock.calls[0]![1] as RequestInit;
		expect(init.redirect).toBe('manual');
		expect(init.signal).toBeInstanceOf(AbortSignal);
		expect(new Headers(init.headers).has('Authorization')).toBe(false);
	});

	it('uses the BV_WEB service binding and dedicated bearer only for the exact BlackVeil receiver', async () => {
		const authToken = 'w'.repeat(32);
		const bindingFetch = vi.fn().mockResolvedValue(new Response(null, { status: 204 }));
		const publicFetch = vi.fn();
		globalThis.fetch = publicFetch as unknown as typeof fetch;

		const delivered = await defaultDeliverWebhook(
			'https://www.blackveilsecurity.com/api/webhooks/brand-drift?t=watch-token',
			{ auditId: 'audit-1' },
			5_000,
			{
				blackVeilBinding: { fetch: bindingFetch as unknown as typeof fetch },
				authToken,
				peerAuthTokens: [],
			},
		);

		expect(delivered).toBe(true);
		expect(publicFetch).not.toHaveBeenCalled();
		expect(bindingFetch).toHaveBeenCalledOnce();
		const [requestUrl, init] = bindingFetch.mock.calls[0] as [string, RequestInit];
		expect(requestUrl).toBe('https://bv-web-internal/api/webhooks/brand-drift?t=watch-token');
		expect(new Headers(init.headers).get('Authorization')).toBe(`Bearer ${authToken}`);
		expect(init.redirect).toBe('manual');
	});

	it('delivers the full 200-row first-party contract through the trusted service binding', async () => {
		const bindingFetch = vi.fn().mockResolvedValue(new Response(null, { status: 204 }));
		const payload = {
			schemaVersion: 1,
			watchId: 'watch-max',
			auditId: 'audit-max',
			target: 'example.com',
			interval: 'daily',
			detectedAt: 1_750_000_000_000,
			previousHash: 'a'.repeat(64),
			currentHash: 'b'.repeat(64),
			changes: {
				added: Array.from({ length: BRAND_AUDIT_WATCH_CHANGE_ROWS_MAX }, (_, index) => ({
					domain: `candidate-${index}.example`,
					bucket: 'impersonation',
				})),
				removed: [],
				modified: [],
			},
		};

		await expect(
			defaultDeliverWebhook(
				'https://www.blackveilsecurity.com/api/webhooks/brand-drift?t=watch-token',
				payload,
				5_000,
				{
					blackVeilBinding: { fetch: bindingFetch as unknown as typeof fetch },
					authToken: 'w'.repeat(32),
					peerAuthTokens: [],
				},
			),
		).resolves.toBe(true);
		const init = bindingFetch.mock.calls[0]?.[1] as RequestInit;
		expect(JSON.parse(String(init.body)).changes.added).toHaveLength(BRAND_AUDIT_WATCH_CHANGE_ROWS_MAX);
	});

	it('rejects an encoded body above the explicit cross-worker limit before fetch', async () => {
		const publicFetch = vi.fn();
		globalThis.fetch = publicFetch as unknown as typeof fetch;

		await expect(
			defaultDeliverWebhook('https://hooks.example.com/brand-audit', {
				padding: 'x'.repeat(BRAND_AUDIT_WATCH_WEBHOOK_MAX_BODY_BYTES),
			}),
		).resolves.toBe(false);
		expect(publicFetch).not.toHaveBeenCalled();
	});

	it('fails trusted delivery closed when the binding or strong dedicated key is absent', async () => {
		const publicFetch = vi.fn();
		globalThis.fetch = publicFetch as unknown as typeof fetch;
		const target = 'https://www.blackveilsecurity.com/api/webhooks/brand-drift?t=watch-token';

		expect(await defaultDeliverWebhook(target, {}, 5_000)).toBe(false);
		expect(
			await defaultDeliverWebhook(target, {}, 5_000, {
				blackVeilBinding: { fetch: vi.fn() as unknown as typeof fetch },
				authToken: 'too-short',
				peerAuthTokens: [],
			}),
		).toBe(false);
		expect(
			await defaultDeliverWebhook(target, {}, 5_000, {
				blackVeilBinding: { fetch: vi.fn() as unknown as typeof fetch },
				authToken: 'w'.repeat(32),
			}),
		).toBe(false);
		expect(publicFetch).not.toHaveBeenCalled();
	});

	it('fails closed when the webhook bearer aliases any other MCP-held secret', async () => {
		const shared = 'shared-mcp-capability-value-32-bytes-minimum';
		const bindingFetch = vi.fn();
		const publicFetch = vi.fn();
		globalThis.fetch = publicFetch as unknown as typeof fetch;

		expect(BRAND_WEBHOOK_PEER_SECRET_KEYS).toEqual(
			expect.arrayContaining([
				'BV_API_KEY',
				'BV_WEB_INTERNAL_KEY',
				'BV_MCP_M365_KEY',
				'BV_MCP_OAUTH_MINT_KEY',
				'BV_MCP_OAUTH_REVOKE_KEY',
				'BV_MCP_TOOL_DELEGATION_KEY',
				'BV_MCP_WATCH_CLEANUP_KEY',
				'BV_MCP_TENANT_KEY',
				'BV_MOBILE_INTERNAL_KEY',
				'BV_INTERNAL_DEV_KEY',
				'BV_INTERNAL_DEV_KEY_2',
				'CERTSPOTTER_TOKEN',
				'CF_ANALYTICS_TOKEN',
			]),
		);
		expect(
			await defaultDeliverWebhook('https://www.blackveilsecurity.com/api/webhooks/brand-drift?t=watch-token', {}, 5_000, {
				blackVeilBinding: { fetch: bindingFetch as unknown as typeof fetch },
				authToken: shared,
				peerAuthTokens: [undefined, shared],
			}),
		).toBe(false);
		expect(bindingFetch).not.toHaveBeenCalled();
		expect(publicFetch).not.toHaveBeenCalled();
	});

	it('never sends the capability to lookalike or customer hosts', async () => {
		const publicFetch = vi.fn().mockResolvedValue(new Response(null, { status: 204 }));
		const bindingFetch = vi.fn();
		globalThis.fetch = publicFetch as unknown as typeof fetch;
		const authToken = 'w'.repeat(32);

		// The lookalike is rejected by outbound URL policy before fetch; the
		// ordinary customer host is delivered publicly without the capability.
		expect(
			await defaultDeliverWebhook('https://www.blackveilsecurity.com.evil.example/api/webhooks/brand-drift?t=x', {}, 5_000, {
				blackVeilBinding: { fetch: bindingFetch as unknown as typeof fetch },
				authToken,
			}),
		).toBe(false);
		expect(
			await defaultDeliverWebhook('https://hooks.example.com/api/webhooks/brand-drift?t=x', {}, 5_000, {
				blackVeilBinding: { fetch: bindingFetch as unknown as typeof fetch },
				authToken,
			}),
		).toBe(true);

		expect(bindingFetch).not.toHaveBeenCalled();
		for (const [, init] of publicFetch.mock.calls as Array<[string, RequestInit]>) {
			expect(new Headers(init.headers).has('Authorization')).toBe(false);
			expect(init.redirect).toBe('manual');
		}
	});

	it('does not follow a trusted receiver redirect or fall back to public fetch', async () => {
		const cancelled = vi.fn();
		const bindingFetch = vi.fn().mockResolvedValue(
			new Response(new ReadableStream<Uint8Array>({ cancel: cancelled }), {
				status: 302,
				headers: { Location: 'https://attacker.example/collect' },
			}),
		);
		const publicFetch = vi.fn();
		globalThis.fetch = publicFetch as unknown as typeof fetch;

		const delivered = await defaultDeliverWebhook('https://www.blackveilsecurity.com/api/webhooks/brand-drift?t=watch-token', {}, 5_000, {
			blackVeilBinding: { fetch: bindingFetch as unknown as typeof fetch },
			authToken: 'w'.repeat(32),
			peerAuthTokens: [],
		});

		expect(delivered).toBe(false);
		expect(bindingFetch).toHaveBeenCalledOnce();
		expect(publicFetch).not.toHaveBeenCalled();
		expect(cancelled).toHaveBeenCalledOnce();
	});

	it('aborts a stalled delivery and returns false', async () => {
		let requestSignal: AbortSignal | null | undefined;
		globalThis.fetch = vi.fn().mockImplementation((_input: RequestInfo | URL, init?: RequestInit) => {
			requestSignal = init?.signal;
			return new Promise<Response>((_resolve, reject) => {
				init?.signal?.addEventListener('abort', () => reject(init.signal?.reason), { once: true });
			});
		}) as unknown as typeof fetch;

		const delivered = await defaultDeliverWebhook('https://hooks.example.com/brand-audit', { auditId: 'audit-1' }, 5);

		expect(delivered).toBe(false);
		expect(requestSignal?.aborted).toBe(true);
	});
});
