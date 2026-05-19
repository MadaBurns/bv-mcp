// SPDX-License-Identifier: BUSL-1.1

/**
 * Chaos test: when `brandAuditSingle` hangs longer than the consumer's budget,
 * the AbortController-driven timeout MUST cause the orchestrator to unwind and
 * the target row MUST flip to `failed` from this same Worker invocation — not
 * from a downstream cron reaper.
 *
 * History: prior to the AbortController flow, the consumer wrapped the
 * orchestrator in `Promise.race(setTimeout)`. The race resolved at 300s but the
 * background orchestrator kept running, burning the Worker's wall-clock budget
 * before the failure-flip UPDATE landed — leaving rows stuck in `running` for a
 * cron reaper to clean up. This test pins the fixed behavior so it doesn't
 * regress.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { BRAND_AUDIT_MESSAGE_TIMEOUT_MS } from '../../src/queue/brand-audit-consumer';

interface D1Call {
	sql: string;
	binds: unknown[];
}

function makeMockD1(target: { status: string; completed_at: number | null } | null) {
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
					if (sql.includes('SELECT status, completed_at FROM brand_audit_targets')) return target;
					if (sql.includes('SELECT completed_targets, total_targets FROM brand_audits')) {
						return { completed_targets: 1, total_targets: 1 };
					}
					return null;
				},
				async run() {
					calls.push({ sql, binds });
					return { success: true, meta: { changes: 1, last_row_id: 0, duration: 0, rows_read: 0, rows_written: 1, size_after: 0 } };
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

describe('processBrandAuditMessage — budget chaos', () => {
	beforeEach(() => {
		vi.useFakeTimers();
	});

	afterEach(() => {
		vi.useRealTimers();
	});

	it('flips the target row to failed from this Worker invocation when the orchestrator exceeds budget', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const { db, calls } = makeMockD1({ status: 'queued', completed_at: null });

		// Orchestrator stub that mimics a wedged audit: it awaits a promise that
		// only resolves on abort. This is the same shape the real pipeline
		// implements after `runBrandAuditPipeline` checks `signal.aborted` at its
		// phase boundaries — when the signal fires, throw the abort reason and
		// let the consumer's catch handler do the failure flip.
		const brandAuditSingle = vi.fn((_target: string, options: { signal?: AbortSignal }) => {
			return new Promise<never>((_resolve, reject) => {
				const onAbort = () => {
					const reason = (options.signal as AbortSignal & { reason?: unknown } | undefined)?.reason;
					reject(reason instanceof Error ? reason : new Error(typeof reason === 'string' ? reason : 'aborted'));
				};
				if (options.signal?.aborted) {
					onAbort();
					return;
				}
				options.signal?.addEventListener('abort', onAbort, { once: true });
			});
		});

		const verdictPromise = processBrandAuditMessage(
			{ auditId: 'aud-chaos-1', target: 'brand-alpha.com', format: 'json' },
			{ db, brandAuditSingle, now: () => 1_750_000_000_000 },
		);

		// Advance just past the budget so the AbortController fires.
		await vi.advanceTimersByTimeAsync(BRAND_AUDIT_MESSAGE_TIMEOUT_MS + 1_000);

		const verdict = await verdictPromise;
		expect(verdict).toBe('ack');

		// The orchestrator was invoked with an AbortSignal AND a deadlineMs aligned
		// with the budget.
		const [, opts] = brandAuditSingle.mock.calls[0]!;
		expect(opts.signal).toBeInstanceOf(AbortSignal);
		expect((opts as { deadlineMs?: number }).deadlineMs).toBe(1_750_000_000_000 + BRAND_AUDIT_MESSAGE_TIMEOUT_MS);

		// The terminal-state UPDATE landed within this invocation. Specifically:
		// it was a `failed` flip carrying the budget-exceeded reason.
		const failedUpdate = calls.find(
			(c) =>
				c.sql.includes('UPDATE brand_audit_targets SET status = ?') &&
				(c.binds[0] as string) === 'failed',
		);
		expect(failedUpdate).toBeDefined();
		expect((failedUpdate!.binds[2] as string).toLowerCase()).toContain('budget');

		// And the parent counter ticked — no reaper needed.
		const auditTick = calls.find(
			(c) => c.sql.includes('UPDATE brand_audits') && c.sql.includes('completed_targets'),
		);
		expect(auditTick).toBeDefined();
	});

	it('does NOT flip the row when the orchestrator completes inside the budget window', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const { db, calls } = makeMockD1({ status: 'queued', completed_at: null });

		const brandAuditSingle = vi.fn(async (_target: string, _options: { signal?: AbortSignal }) => {
			// Real timer-free completion — resolves before the abort fires.
			return { category: 'brand_discovery', score: 100, findings: [] };
		});

		const verdict = await processBrandAuditMessage(
			{ auditId: 'aud-chaos-2', target: 'apple.com', format: 'json' },
			{ db, brandAuditSingle, now: () => 1_750_000_000_000 },
		);

		expect(verdict).toBe('ack');
		const completed = calls.find(
			(c) =>
				c.sql.includes('UPDATE brand_audit_targets SET status = ?') &&
				(c.binds[0] as string) === 'completed',
		);
		expect(completed).toBeDefined();
		const failed = calls.find(
			(c) =>
				c.sql.includes('UPDATE brand_audit_targets SET status = ?') &&
				(c.binds[0] as string) === 'failed',
		);
		expect(failed).toBeUndefined();
	});
});
