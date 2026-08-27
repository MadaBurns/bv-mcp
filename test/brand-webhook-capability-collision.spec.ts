// SPDX-License-Identifier: BUSL-1.1

import { createExecutionContext } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';

import worker from '../src/index';
import { brandWebhookCapabilityCollision } from '../src/queue/brand-audit-consumer';

const BRAND_KEY = 'b'.repeat(48);

function mcpRequest(): Request {
	return new Request('https://mcp.example.test/mcp', {
		method: 'POST',
		headers: {
			Authorization: `Bearer ${BRAND_KEY}`,
			'Content-Type': 'application/json',
		},
		body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
	});
}

describe('Brand Drift capability separation at the public fetch boundary', () => {
	it.each(['BV_API_KEY', 'BV_INTERNAL_DEV_KEY', 'OAUTH_SIGNING_SECRET'] as const)(
		'fails closed before public authentication when the brand key aliases %s',
		async (peerKey) => {
			const targetEnv = {
				BV_MCP_BRAND_WEBHOOK_KEY: BRAND_KEY,
				[peerKey]: BRAND_KEY,
			} as unknown as Parameters<typeof worker.fetch>[1];

			const response = await worker.fetch(mcpRequest(), targetEnv, createExecutionContext());

			expect(response.status).toBe(503);
			expect(response.headers.get('cache-control')).toBe('no-store');
			await expect(response.json()).resolves.toEqual({ error: 'Service authentication configuration invalid' });
		},
	);

	it('does not take the public Worker down when the dedicated capability is absent or distinct', () => {
		expect(brandWebhookCapabilityCollision({ BV_API_KEY: BRAND_KEY })).toBeNull();
		expect(
			brandWebhookCapabilityCollision({
				BV_MCP_BRAND_WEBHOOK_KEY: BRAND_KEY,
				BV_API_KEY: 'a'.repeat(48),
				BV_INTERNAL_DEV_KEY: 'c'.repeat(48),
				OAUTH_SIGNING_SECRET: 'd'.repeat(48),
			}),
		).toBeNull();
	});
});
