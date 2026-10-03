// SPDX-License-Identifier: BUSL-1.1

/**
 * When the function wrapped by `withStrongRequestIdempotency` THROWS, the
 * idempotency claim must not stay `in_progress` for the 7-day replay horizon:
 * a retry with the same Idempotency-Key must be allowed to execute.
 */
import { env } from 'cloudflare:test';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { resetQuotaCoordinatorState } from '../src/lib/quota-coordinator';
import { withStrongRequestIdempotency } from '../src/lib/request-dedup';

afterEach(async () => {
	await resetQuotaCoordinatorState(env.QUOTA_COORDINATOR);
});

const params = (args: Record<string, unknown> = { target: 'example.com' }) => ({
	toolName: 'scan_buckets_start',
	principal: 'internal:web',
	idempotencyKey: 'recon-start:throw-operation-id',
	args,
	coordinator: env.QUOTA_COORDINATOR,
});

describe('withStrongRequestIdempotency — wrapped function throws', () => {
	it('rethrows, releases the claim, and lets a same-key retry execute', async () => {
		const failing = vi.fn(async () => {
			throw new Error('boom');
		});
		await expect(withStrongRequestIdempotency(params(), failing)).rejects.toThrow('boom');

		const retry = vi.fn(async () => ({ content: [{ type: 'text', text: 'operationId=op-2' }], isError: false }));
		const result = await withStrongRequestIdempotency(params(), retry);

		expect(retry).toHaveBeenCalledTimes(1);
		expect(result).toEqual({ content: [{ type: 'text', text: 'operationId=op-2' }], isError: false });
	});

	it('a completed key is still replayed after an earlier throw was released (no double execution)', async () => {
		await expect(
			withStrongRequestIdempotency(params(), async () => {
				throw new Error('boom');
			}),
		).rejects.toThrow('boom');

		const ok = vi.fn(async () => ({ content: [{ type: 'text', text: 'operationId=op-3' }], isError: false }));
		await withStrongRequestIdempotency(params(), ok);
		const replay = await withStrongRequestIdempotency(params(), ok);

		expect(ok).toHaveBeenCalledTimes(1);
		expect(replay).toEqual({ content: [{ type: 'text', text: 'operationId=op-3' }], isError: false });
	});
});
