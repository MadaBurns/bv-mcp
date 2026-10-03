// SPDX-License-Identifier: BUSL-1.1

/**
 * Cleanup alarm: production Durable Object storage caps `delete(keys[])` at 128
 * keys per call, so an alarm that hands every expired key to one `delete()`
 * throws permanently once more than 128 keys have expired. The alarm must chunk.
 *
 * The local workerd used by the Workers test pool does NOT enforce that cap, so
 * the spy below re-imposes it (same failure the production runtime raises).
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { env, runInDurableObject } from 'cloudflare:test';
import { resetQuotaCoordinatorState } from '../src/lib/quota-coordinator';

const DO_DELETE_KEY_CAP = 128;

afterEach(async () => {
	vi.restoreAllMocks();
	await resetQuotaCoordinatorState(env.QUOTA_COORDINATOR);
});

describe('QuotaCoordinator cleanup alarm — >128 expired keys', () => {
	it('deletes every expired key in chunks of at most 128 and keeps live keys', async () => {
		const stub = env.QUOTA_COORDINATOR.getByName('cleanup-alarm-over-128');
		const expiredCount = 300;
		const now = Date.now();

		const { remaining, deleteSizes } = await runInDurableObject(stub, async (instance, state) => {
			for (let i = 0; i < expiredCount; i++) {
				await state.storage.put(`quota:expired:${i}`, { count: 1, expiresAt: now - 1_000 });
			}
			await state.storage.put('quota:live:0', { count: 1, expiresAt: now + 3_600_000 });

			const realDelete = state.storage.delete.bind(state.storage) as (keys: string[]) => Promise<number>;
			const sizes: number[] = [];
			vi.spyOn(state.storage, 'delete').mockImplementation(((keys: string | string[]) => {
				if (Array.isArray(keys)) {
					sizes.push(keys.length);
					if (keys.length > DO_DELETE_KEY_CAP) {
						throw new Error('Too many keys: a maximum of 128 keys can be deleted in a single call');
					}
					return realDelete(keys);
				}
				return realDelete([keys]);
			}) as never);

			await instance.alarm();

			const left = await state.storage.list({ prefix: 'quota:' });
			return { remaining: [...left.keys()], deleteSizes: sizes };
		});

		expect(remaining).toEqual(['quota:live:0']);
		expect(deleteSizes.reduce((a, b) => a + b, 0)).toBe(expiredCount);
		expect(Math.max(...deleteSizes)).toBeLessThanOrEqual(DO_DELETE_KEY_CAP);
	});
});
