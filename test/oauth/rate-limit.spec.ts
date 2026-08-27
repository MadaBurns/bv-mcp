// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it, vi } from 'vitest';
import { consumeOAuthRateLimit } from '../../src/oauth/rate-limit';
import type { QuotaCoordinator } from '../../src/lib/quota-coordinator';

function createKv() {
	const store = new Map<string, string>();
	return {
		store,
		kv: {
			get: vi.fn(async (key: string) => store.get(key) ?? null),
			put: vi.fn(async (key: string, value: string) => {
				store.set(key, value);
			}),
			delete: vi.fn(async (key: string) => {
				store.delete(key);
			}),
			list: vi.fn(),
		} as unknown as KVNamespace,
	};
}

describe('OAuth endpoint rate-limit coordinator', () => {
	it('preserves a bounded KV fallback when the coordinator is unbound', async () => {
		const { kv } = createKv();
		const options = {
			kv,
			coordinationScope: 'test',
			kvKey: 'oauth:test-rate',
			principal: '198.51.100.10',
			limit: 2,
			windowSeconds: 60,
			nowMs: 1_000_000,
		};

		await expect(consumeOAuthRateLimit(options)).resolves.toMatchObject({ exceeded: false });
		await expect(consumeOAuthRateLimit(options)).resolves.toMatchObject({ exceeded: false });
		await expect(consumeOAuthRateLimit(options)).resolves.toMatchObject({ exceeded: true });
	});

	it('fails closed instead of falling through to KV when a configured coordinator is unavailable', async () => {
		const { kv } = createKv();
		const quotaCoordinator = {
			getByName: vi.fn(() => ({
				dispatch: vi.fn(async () => {
					throw new Error('coordinator unavailable');
				}),
			})),
		} as unknown as DurableObjectNamespace<QuotaCoordinator>;

		await expect(
			consumeOAuthRateLimit({
				kv,
				quotaCoordinator,
				coordinationScope: 'test',
				kvKey: 'oauth:test-rate',
				principal: '198.51.100.11',
				limit: 2,
				windowSeconds: 60,
				nowMs: 1_000_000,
			}),
		).resolves.toMatchObject({ exceeded: true, unavailable: true });
		expect(kv.put).not.toHaveBeenCalled();
	});

	it('fails closed on a malformed coordinator success response', async () => {
		const { kv } = createKv();
		const quotaCoordinator = {
			getByName: vi.fn(() => ({
				dispatch: vi.fn(async () => ({ allowed: true })),
			})),
		} as unknown as DurableObjectNamespace<QuotaCoordinator>;

		await expect(
			consumeOAuthRateLimit({
				kv,
				quotaCoordinator,
				coordinationScope: 'test',
				kvKey: 'oauth:test-rate',
				principal: '198.51.100.12',
				limit: 2,
				windowSeconds: 60,
				nowMs: 1_000_000,
			}),
		).resolves.toMatchObject({ exceeded: true, unavailable: true });
		expect(kv.put).not.toHaveBeenCalled();
	});
});
