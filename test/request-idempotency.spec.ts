// SPDX-License-Identifier: BUSL-1.1

// @ts-expect-error cloudflare:test exports are injected by the Workers Vitest pool at runtime.
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
	idempotencyKey: 'recon-start:fixed-operation-id',
	args,
	coordinator: env.QUOTA_COORDINATOR,
});

describe('withStrongRequestIdempotency', () => {
	it('executes one of many concurrent retries and later replays the exact response', async () => {
		const fn = vi.fn(async () => {
			await new Promise((resolve) => setTimeout(resolve, 20));
			return { content: [{ type: 'text', text: 'operationId=op-1' }], isError: false };
		});

		const concurrent = await Promise.all(
			Array.from({ length: 20 }, () => withStrongRequestIdempotency(params(), fn)),
		);
		expect(fn).toHaveBeenCalledTimes(1);
		expect(concurrent.some((result) => result.isError === false)).toBe(true);

		const replay = await withStrongRequestIdempotency(params(), fn);
		expect(replay).toEqual({ content: [{ type: 'text', text: 'operationId=op-1' }], isError: false });
		expect(fn).toHaveBeenCalledTimes(1);
	});

	it('rejects the same key with different arguments without re-executing', async () => {
		const fn = vi.fn(async () => ({ content: [{ type: 'text', text: 'operationId=op-1' }], isError: false }));
		await withStrongRequestIdempotency(params(), fn);
		const conflict = await withStrongRequestIdempotency(params({ target: 'other.example' }), fn);

		expect(conflict.isError).toBe(true);
		expect(conflict.content?.[0]?.text).toContain('different request');
		expect(fn).toHaveBeenCalledTimes(1);
	});

	it('fails closed without strong state', async () => {
		const fn = vi.fn(async () => ({ content: [], isError: false }));
		const result = await withStrongRequestIdempotency({ ...params(), coordinator: undefined }, fn);
		expect(result.isError).toBe(true);
		expect(fn).not.toHaveBeenCalled();
	});
});
