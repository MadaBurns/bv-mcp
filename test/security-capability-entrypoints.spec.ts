// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it, vi } from 'vitest';

import worker from '../src';

const SHARED = 'scheduled-signing-token-alias-32-bytes-minimum';

function executionContext(): ExecutionContext {
	return {
		waitUntil: vi.fn(),
		passThroughOnException: vi.fn(),
	} as unknown as ExecutionContext;
}

describe('security capability separation across Worker entrypoints', () => {
	it('stops scheduled routing before any handler can transmit an aliased credential', async () => {
		const ctx = executionContext();
		const waitUntil = vi.spyOn(ctx, 'waitUntil');
		const env = {
			CF_ANALYTICS_TOKEN: SHARED,
			OAUTH_SIGNING_SECRET: SHARED,
		} as unknown as Parameters<NonNullable<typeof worker.scheduled>>[1];

		await worker.scheduled!(
			{ cron: '*/15 * * * *', scheduledTime: Date.now(), noRetry: vi.fn() } as unknown as ScheduledController,
			env,
			ctx,
		);

		expect(waitUntil).not.toHaveBeenCalled();
	});

	it('retries the whole queue with delay and performs no work under an alias', async () => {
		const retryAll = vi.fn();
		const ackAll = vi.fn();
		const ack = vi.fn();
		const retry = vi.fn();
		const analyticsWrite = vi.fn();
		const batch = {
			queue: 'brand-audit-queue',
			messages: [{ id: 'm1', timestamp: new Date(), attempts: 1, body: {}, ack, retry }],
			retryAll,
			ackAll,
		} as unknown as MessageBatch<unknown>;
		const env = {
			CF_ANALYTICS_TOKEN: SHARED,
			OAUTH_SIGNING_SECRET: SHARED,
			BRAND_AUDIT_DB: { prepare: vi.fn() },
			MCP_ANALYTICS: { writeDataPoint: analyticsWrite },
		} as unknown as Parameters<NonNullable<typeof worker.queue>>[1];

		await worker.queue!(batch, env, executionContext());

		expect(retryAll).toHaveBeenCalledWith({ delaySeconds: 300 });
		expect(ackAll).not.toHaveBeenCalled();
		expect(ack).not.toHaveBeenCalled();
		expect(retry).not.toHaveBeenCalled();
		expect((env as unknown as { BRAND_AUDIT_DB: { prepare: ReturnType<typeof vi.fn> } }).BRAND_AUDIT_DB.prepare).not.toHaveBeenCalled();
		expect(analyticsWrite).not.toHaveBeenCalled();
	});
});
