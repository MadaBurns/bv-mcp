// SPDX-License-Identifier: BUSL-1.1

/**
 * Integration tests for handleBrandAuditQueue — the discover_only branch.
 *
 * A `phase: 'discover_only'` message runs discoverBrandDomains directly and
 * writes the resulting CheckResult to brand_audit_targets.result_json, flipping
 * the target + audit rows to completed. Sociable: real handleBrandAuditQueue +
 * processDiscoverOnlyMessage execute; D1 is stubbed and discoverBrandDomains is
 * mocked via the injectable consumer dep.
 */

import { describe, it, expect, vi, afterEach } from 'vitest';

afterEach(() => vi.restoreAllMocks());

interface D1Call {
	sql: string;
	binds: unknown[];
}

/** D1 stub recording writes; SELECT status returns a queued row for the target. */
function makeRecordingD1(targetStatus: 'queued' | 'running' | 'completed' | 'failed' = 'queued') {
	const calls: D1Call[] = [];
	function makeStmt(sql: string) {
		let binds: unknown[] = [];
		const stmt = {
			bind(...args: unknown[]) {
				binds = args;
				return stmt;
			},
			async run() {
				calls.push({ sql, binds });
				return { meta: { changes: 1 } };
			},
			async first() {
				calls.push({ sql, binds });
				if (sql.includes('SELECT status')) return { status: targetStatus, completed_at: null };
				if (sql.includes('completed_targets')) return { completed_targets: 1, total_targets: 1 };
				return null;
			},
			async all() {
				calls.push({ sql, binds });
				return { results: [] };
			},
		};
		return stmt;
	}
	const db = { prepare: (sql: string) => makeStmt(sql) } as unknown as D1Database;
	return { db, calls };
}

function makeDiscoverOnlyBatch(body: Record<string, unknown>) {
	const ack = vi.fn();
	const retry = vi.fn();
	const batch = {
		messages: [{ body, ack, retry, id: 'msg-1', timestamp: new Date(), attempts: 1 }],
		queue: 'brand-audit-queue',
		retryAll: vi.fn(),
		ackAll: vi.fn(),
	} as unknown as MessageBatch<unknown>;
	return { batch, ack, retry };
}

describe('handleBrandAuditQueue — discover_only branch', () => {
	it('runs discoverBrandDomains and writes result_json, flipping target to completed', async () => {
		const { handleBrandAuditQueue } = await import('../src/queue/brand-audit-consumer');
		const { db, calls } = makeRecordingD1('queued');

		const fakeResult = { category: 'brand_discovery', passed: true, score: 100, findings: [] };
		const discoverBrandDomains = vi.fn().mockResolvedValue(fakeResult);

		const { batch, ack, retry } = makeDiscoverOnlyBatch({
			auditId: 'disc-1',
			target: 'brand-example.net',
			phase: 'discover_only',
			signals: ['san', 'ns'],
			min_confidence: 0.6,
		});

		await handleBrandAuditQueue(batch, { db, discoverBrandDomains });

		expect(ack).toHaveBeenCalledOnce();
		expect(retry).not.toHaveBeenCalled();

		// discoverBrandDomains called with the seed + forwarded args.
		expect(discoverBrandDomains).toHaveBeenCalledTimes(1);
		const [seed, options] = discoverBrandDomains.mock.calls[0];
		expect(seed).toBe('brand-example.net');
		expect(options.signals).toEqual(['san', 'ns']);
		expect(options.min_confidence).toBe(0.6);
		expect(options.signal).toBeInstanceOf(AbortSignal);

		// result_json persisted to the target row.
		const resultWrite = calls.find((c) => c.sql.includes('UPDATE brand_audit_targets') && c.sql.includes('result_json'));
		expect(resultWrite).toBeDefined();
		expect(resultWrite!.binds).toContain(JSON.stringify(fakeResult));

		// audit row flipped to completed.
		expect(calls.some((c) => c.sql.includes('UPDATE brand_audits') && c.sql.includes("status = 'completed'"))).toBe(true);
	});

	it('acks without re-running when the target is already completed (idempotency)', async () => {
		const { handleBrandAuditQueue } = await import('../src/queue/brand-audit-consumer');
		const { db } = makeRecordingD1('completed');
		const discoverBrandDomains = vi.fn();

		const { batch, ack } = makeDiscoverOnlyBatch({ auditId: 'disc-2', target: 'brand-example.net', phase: 'discover_only' });

		await handleBrandAuditQueue(batch, { db, discoverBrandDomains });

		expect(ack).toHaveBeenCalledOnce();
		expect(discoverBrandDomains).not.toHaveBeenCalled();
	});

	it('writes a failed row (does not throw) when discoverBrandDomains rejects', async () => {
		const { handleBrandAuditQueue } = await import('../src/queue/brand-audit-consumer');
		const { db, calls } = makeRecordingD1('queued');
		const discoverBrandDomains = vi.fn().mockRejectedValue(new Error('boom'));

		const { batch, ack } = makeDiscoverOnlyBatch({ auditId: 'disc-3', target: 'brand-example.net', phase: 'discover_only' });

		await handleBrandAuditQueue(batch, { db, discoverBrandDomains });

		expect(ack).toHaveBeenCalledOnce();
		const failWrite = calls.find((c) => c.sql.includes('UPDATE brand_audit_targets') && c.binds.includes('failed'));
		expect(failWrite).toBeDefined();
	});
});
