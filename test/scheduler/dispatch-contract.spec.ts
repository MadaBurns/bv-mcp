// test/scheduler/dispatch-contract.spec.ts
// SPDX-License-Identifier: BUSL-1.1
//
// SQ-558 — producer/consumer contract for the Phase 2 dispatcher.
//
// The dispatcher enqueues {tenant_id, domain, lane, scheduled_at}; the scanner
// queue's default consumer (handleScanQueue) parses with the strict
// ScanQueueMessageSchema ({cycle_id, sub_tenant_id, domain, ...}) and
// dead-letters anything else as poison. claimDue has already advanced
// next_scan_at by then, so an armed dispatcher silently lost every scan.
//
// The dispatcher must therefore (a) never send a message the receiving
// consumer's schema rejects, and (b) fail closed — log an error and claim
// NOTHING — while no compatible consumer is wired.

import { afterEach, describe, expect, it, vi } from 'vitest';
import { z } from 'zod';
import { ScanQueueMessageSchema } from '../../src/schemas/tenant-internal';
import { makeScanScheduleDb, makeSlowQueue } from '../helpers/scan-schedule-d1';

const NOW = 1_750_000_000_000;

afterEach(() => {
	vi.restoreAllMocks();
	vi.resetModules();
});

function armedEnv() {
	const fake = makeScanScheduleDb([
		{ id: 1, tenant_id: 'tenant_a', domain: 'fast.com', lane: 'fast', next_scan_at: NOW - 1 },
		{ id: 2, tenant_id: 'tenant_a', domain: 'slow.com', lane: 'slow', next_scan_at: NOW - 1 },
	]);
	const { queue, send, sent } = makeSlowQueue();
	const env = {
		SCAN_DISPATCH_ENABLED: 'true',
		SCAN_DISPATCH_BATCH_SIZE: '50',
		SCAN_SCHEDULE_DB: fake.db,
		BV_SCANNER_QUEUE: queue,
		BV_SCANNER_SLOW_QUEUE: queue,
	} as unknown as import('../../src/scheduler/dispatch').ScanDispatchEnv;
	return { env, fake, send, sent };
}

function structuredLogs(spy: ReturnType<typeof vi.fn>): Record<string, unknown>[] {
	const logs: Record<string, unknown>[] = [];
	for (const call of spy.mock.calls) {
		if (typeof call[0] !== 'string') continue;
		try {
			logs.push(JSON.parse(call[0]) as Record<string, unknown>);
		} catch {
			// not JSON
		}
	}
	return logs;
}

describe('dispatchDueScans — message contract with the scanner-queue consumer', () => {
	it('every message sent parses against the real consumer schema (ScanQueueMessageSchema)', async () => {
		const { env, sent } = armedEnv();
		const { dispatchDueScans } = await import('../../src/scheduler/dispatch');
		await dispatchDueScans(env, { now: NOW });

		for (const { message } of sent) {
			expect(ScanQueueMessageSchema.safeParse(message).success, JSON.stringify(message)).toBe(true);
		}
	});

	it('armed with no compatible consumer: claims NOTHING, sends nothing, logs an error', async () => {
		const { env, fake, send } = armedEnv();
		const consoleSpy = vi.spyOn(console, 'log');
		const { dispatchDueScans } = await import('../../src/scheduler/dispatch');
		await dispatchDueScans(env, { now: NOW });

		expect(fake.prepare).not.toHaveBeenCalled(); // claimDue never ran
		expect(send).not.toHaveBeenCalled();
		expect(fake.rows.map((r) => r.next_scan_at)).toEqual([NOW - 1, NOW - 1]); // schedule untouched

		const errors = structuredLogs(consoleSpy).filter((l) => l.severity === 'error');
		expect(errors).toHaveLength(1);
		expect((errors[0].details as { message: string }).message).toBe('scan_dispatch_no_compatible_consumer');
	});

	it('the guard opens when the consumer schema accepts the message, and the sent object satisfies it', async () => {
		const consumerSchema = z.object({ tenant_id: z.string(), domain: z.string(), lane: z.string(), scheduled_at: z.number() }).strict();
		const { env, send, sent } = armedEnv();
		const { dispatchDueScans } = await import('../../src/scheduler/dispatch');
		await dispatchDueScans(env, { now: NOW, consumerSchema });

		expect(send).toHaveBeenCalledTimes(2);
		for (const { message } of sent) {
			expect(consumerSchema.safeParse(message).success).toBe(true);
		}
	});

	it('the unarmed no-op stays silent (no consumer error when the flag is off)', async () => {
		const { env, fake } = armedEnv();
		(env as { SCAN_DISPATCH_ENABLED?: string }).SCAN_DISPATCH_ENABLED = undefined;
		const consoleSpy = vi.spyOn(console, 'log');
		const { dispatchDueScans } = await import('../../src/scheduler/dispatch');
		await dispatchDueScans(env, { now: NOW });

		expect(fake.prepare).not.toHaveBeenCalled();
		expect(structuredLogs(consoleSpy).filter((l) => l.severity === 'error')).toHaveLength(0);
	});
});
