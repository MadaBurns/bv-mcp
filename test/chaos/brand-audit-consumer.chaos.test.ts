// SPDX-License-Identifier: BUSL-1.1

/**
 * Chaos invariant: duplicate queue delivery of a brand-audit message must not
 * re-run `brandAuditSingle` or re-tick the audit counter.
 *
 * Hypothesis: GIVEN a brand-audit message whose target row is already in a
 * terminal state ('completed' | 'failed'),
 * WHEN the consumer receives that message (which Cloudflare Queues can deliver
 * N times on retry — at-least-once semantics),
 * THEN it ack()s the message without invoking `brandAuditSingle` and without
 * any UPDATE on brand_audit_targets or brand_audits.
 *
 * Why this matters: the orchestrator costs ~3 min per target and consumes RDAP
 * + outbound budget. A misconfigured retry policy or transient ack failure
 * could deliver a "completed" message twice; without this guard, the second
 * delivery silently double-bills CPU + outbound + (later) PDF rendering.
 */

import { describe, it, expect, vi } from 'vitest';

interface D1Call {
	sql: string;
	binds: unknown[];
}

function makeMockD1(targetStatus: 'completed' | 'failed' | 'queued') {
	const calls: D1Call[] = [];
	const db = {
		prepare(sql: string) {
			let binds: unknown[] = [];
			const stmt = {
				bind(...args: unknown[]) {
					binds = args;
					return stmt;
				},
				async first() {
					calls.push({ sql, binds });
					if (sql.includes('SELECT status, completed_at FROM brand_audit_targets')) {
						return { status: targetStatus, completed_at: targetStatus === 'completed' ? 1 : null };
					}
					return null;
				},
				async run() {
					calls.push({ sql, binds });
					return { success: true, meta: { changes: 1 } };
				},
				async all() {
					calls.push({ sql, binds });
					return { results: [], success: true, meta: {} };
				},
			};
			return stmt;
		},
	} as unknown as D1Database;
	return { db, calls };
}

describe('chaos: brand-audit consumer idempotency under duplicate delivery', () => {
	it('does not re-run brandAuditSingle when the target is already completed', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const { db, calls } = makeMockD1('completed');
		const brandAuditSingle = vi.fn();

		const verdict = await processBrandAuditMessage(
			{ auditId: 'aud-1', target: 'apple.com', format: 'json' },
			{ db, brandAuditSingle, now: () => 1_750_000_000_000 },
		);

		expect(verdict).toBe('ack');
		expect(brandAuditSingle).not.toHaveBeenCalled();

		// No mutations — duplicate delivery is a pure no-op.
		const writes = calls.filter((c) => c.sql.startsWith('UPDATE') || c.sql.startsWith('INSERT'));
		expect(writes).toHaveLength(0);
	});

	it('does not re-run brandAuditSingle when the target is already failed', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const { db, calls } = makeMockD1('failed');
		const brandAuditSingle = vi.fn();

		const verdict = await processBrandAuditMessage(
			{ auditId: 'aud-1', target: 'apple.com', format: 'json' },
			{ db, brandAuditSingle, now: () => 1_750_000_000_000 },
		);

		expect(verdict).toBe('ack');
		expect(brandAuditSingle).not.toHaveBeenCalled();
		const writes = calls.filter((c) => c.sql.startsWith('UPDATE') || c.sql.startsWith('INSERT'));
		expect(writes).toHaveLength(0);
	});

	it('does run brandAuditSingle when the target is still queued (control)', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const { db } = makeMockD1('queued');
		const brandAuditSingle = vi.fn().mockResolvedValue({ category: 'brand_discovery', score: 100, findings: [] });

		await processBrandAuditMessage(
			{ auditId: 'aud-1', target: 'apple.com', format: 'json' },
			{ db, brandAuditSingle, now: () => 1_750_000_000_000 },
		);

		expect(brandAuditSingle).toHaveBeenCalledTimes(1);
	});
});
