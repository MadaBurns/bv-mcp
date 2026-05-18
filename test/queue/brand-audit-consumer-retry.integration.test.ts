// SPDX-License-Identifier: BUSL-1.1

/**
 * Phase 2b of registrar-coverage-tdd-plan.md — consumer-level auto-retry.
 *
 * Asserts the contracts (advisor-flagged):
 *   - lookup_failed in result → consumer enqueues a single retry message
 *   - retry_scheduled step row is the idempotency token (dup-delivery safe)
 *   - retry_attempt=1 messages skip counter tick + force_refresh the pipeline
 *   - watch webhook fires on terminal result only (suppressed when retry pending)
 *
 * Mocks are restricted to the external boundaries (D1 + queue binding). The
 * orchestrator and webhook are plain async functions whose state is captured
 * in test-local arrays — fewer vi.fn instances per the testing-methodology
 * "sociable by default" guidance, while keeping every external boundary stubbed.
 */

import { describe, it, expect } from 'vitest';

interface AuditTargetRow {
	status: 'queued' | 'running' | 'completed' | 'failed';
	completed_at: number | null;
}

interface StepKey { auditId: string; target: string; step: string }
function stepKey(k: StepKey): string {
	return `${k.auditId}\0${k.target}\0${k.step}`;
}

function makeMockD1(initial: { target: AuditTargetRow & { result_json?: string | null; error?: string | null } }) {
	const targetRow: AuditTargetRow & { result_json: string | null; error: string | null } = {
		status: initial.target.status,
		completed_at: initial.target.completed_at,
		result_json: initial.target.result_json ?? null,
		error: initial.target.error ?? null,
	};
	const steps = new Map<string, { status: string; payload_json: string | null; error: string | null }>();
	const counter = { completed_targets: 0, total_targets: 3 };

	const db = {
		prepare(sql: string) {
			let binds: unknown[] = [];
			const stmt = {
				bind(...args: unknown[]) {
					binds = args;
					return stmt;
				},
				async first() {
					if (sql.includes('SELECT status, completed_at FROM brand_audit_targets')) {
						return { status: targetRow.status, completed_at: targetRow.completed_at };
					}
					if (sql.includes('SELECT completed_targets, total_targets FROM brand_audits')) {
						return { ...counter };
					}
					if (sql.includes('FROM brand_audit_steps')) {
						const [auditId, target, step] = binds as string[];
						const row = steps.get(stepKey({ auditId, target, step }));
						if (!row) return null;
						return { audit_id: auditId, target, step, status: row.status, payload_json: row.payload_json, error: row.error };
					}
					return null;
				},
				async run() {
					if (sql.includes('INSERT INTO brand_audit_steps')) {
						const [auditId, target, step, status, payload, errorVal] = binds as [string, string, string, string, string | null, string | null];
						steps.set(stepKey({ auditId, target, step }), { status, payload_json: payload, error: errorVal });
						return { success: true, meta: { changes: 1 } };
					}
					if (sql.includes('UPDATE brand_audit_targets')) {
						// Atomic claim: parameterized predicate `status = ?` with the
						// expected value bound as the third arg.
						if (sql.includes('SET status = \'running\' WHERE audit_id = ? AND target = ? AND status = ?')) {
							const expected = binds[2] as AuditTargetRow['status'];
							if (targetRow.status !== expected) return { success: true, meta: { changes: 0 } };
							targetRow.status = 'running';
							return { success: true, meta: { changes: 1 } };
						}
						// Retry-failure preservation path — error-only UPDATE.
						if (sql.includes('SET error = ?, completed_at = ? WHERE')) {
							const [errorVal] = binds as [string | null];
							targetRow.error = errorVal;
							return { success: true, meta: { changes: 1 } };
						}
						// Final-flip UPDATE — binding order matches the consumer's
						// SET clause. Track result_json + error so the retry-failure
						// preservation test can assert on them.
						const [newStatus, resultJson, errorVal] = binds as [AuditTargetRow['status'], string | null, string | null];
						targetRow.status = newStatus;
						if (resultJson !== undefined) targetRow.result_json = resultJson;
						if (errorVal !== undefined) targetRow.error = errorVal;
						targetRow.completed_at = Date.now();
						return { success: true, meta: { changes: 1 } };
					}
					if (sql.includes('UPDATE brand_audits SET completed_targets')) {
						counter.completed_targets += 1;
						return { success: true, meta: { changes: 1 } };
					}
					return { success: true, meta: { changes: 1 } };
				},
				async all() { return { results: [], success: true, meta: {} }; },
			};
			return stmt;
		},
	} as unknown as D1Database;

	return { db, getCounter: () => ({ ...counter }), getTargetRow: () => ({ ...targetRow }) };
}

const resultWithLookupFailed = {
	category: 'brand_audit',
	score: 100,
	findings: [
		{
			category: 'brand_audit',
			title: 'summary',
			severity: 'info' as const,
			detail: '',
			metadata: { summary: true, targetRegistrarSource: 'rdap' },
		},
		{
			category: 'brand_audit',
			title: 'candidate',
			severity: 'low' as const,
			detail: '',
			metadata: { candidate: 'flaky.net', registrarSource: 'lookup_failed', registrarFailureReason: 'rdap_http_503' },
		},
	],
};

const resultClean = {
	category: 'brand_audit',
	score: 100,
	findings: [
		{
			category: 'brand_audit',
			title: 'summary',
			severity: 'info' as const,
			detail: '',
			metadata: { summary: true, targetRegistrarSource: 'rdap' },
		},
	],
};

/** Plain orchestrator stub — records calls in `calls[]` instead of vi.fn. */
function makeOrchestrator(returnValue: unknown) {
	const calls: Array<{ target: string; opts: { force_refresh?: boolean } }> = [];
	const fn = async (target: string, opts: { force_refresh?: boolean }) => {
		calls.push({ target, opts });
		return returnValue;
	};
	return { fn, calls };
}

/** Plain queue stub — records enqueue payloads. */
function makeQueue() {
	const sent: Array<{ msg: unknown }> = [];
	return {
		binding: { async send(msg: unknown) { sent.push({ msg }); } },
		sent,
	};
}

/** Plain webhook stub — records deliveries. */
function makeWebhook() {
	const calls: Array<{ url: string }> = [];
	return {
		fn: async (url: string, _payload: unknown) => { calls.push({ url }); return true; },
		calls,
	};
}

describe('processBrandAuditMessage — Phase 2b retry orchestration', () => {
	it('enqueues a single retry pass when result has lookup_failed candidates AND suppresses webhook', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const { db } = makeMockD1({ target: { status: 'queued', completed_at: null } });
		const orchestrator = makeOrchestrator(resultWithLookupFailed);
		const queue = makeQueue();
		const webhook = makeWebhook();

		await processBrandAuditMessage(
			{ auditId: 'aud-1', target: 'example.com', format: 'json', watchId: 'watch-1', ownerId: 'owner-1' },
			{ db, brandAuditSingle: orchestrator.fn, brandAuditQueue: queue.binding, deliverWebhook: webhook.fn, now: () => 1_750_000_000_000 },
		);

		expect(queue.sent).toHaveLength(1);
		expect(queue.sent[0].msg).toMatchObject({ auditId: 'aud-1', target: 'example.com', retry_attempt: 1 });
		expect(webhook.calls, 'webhook suppressed when retry pending — fires on terminal result only').toEqual([]);
	});

	it('suppresses PDF fanout on the original pass when a retry was enqueued (no double PDF)', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const { db } = makeMockD1({ target: { status: 'queued', completed_at: null } });
		const orchestrator = makeOrchestrator(resultWithLookupFailed);
		const queue = makeQueue();
		const pdfQueue = { sent: [] as Array<{ msg: unknown }> };
		const pdfBinding = { async send(msg: unknown) { pdfQueue.sent.push({ msg }); } };

		await processBrandAuditMessage(
			{ auditId: 'aud-1', target: 'example.com', format: 'markdown' },
			{ db, brandAuditSingle: orchestrator.fn, brandAuditQueue: queue.binding, pdfQueue: pdfBinding, now: () => 1_750_000_000_000 },
		);

		expect(queue.sent, 'retry was enqueued').toHaveLength(1);
		expect(pdfQueue.sent, 'PDF must NOT fire on the partial pass when a retry is pending').toEqual([]);
	});

	it('does not enqueue retry when result is clean', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const { db } = makeMockD1({ target: { status: 'queued', completed_at: null } });
		const orchestrator = makeOrchestrator(resultClean);
		const queue = makeQueue();

		await processBrandAuditMessage(
			{ auditId: 'aud-1', target: 'example.com', format: 'json' },
			{ db, brandAuditSingle: orchestrator.fn, brandAuditQueue: queue.binding, now: () => 1_750_000_000_000 },
		);

		expect(queue.sent).toEqual([]);
	});

	it('duplicate delivery of the same original enqueues retry exactly once (retry_scheduled idempotency)', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const { db } = makeMockD1({ target: { status: 'queued', completed_at: null } });
		const orchestrator = makeOrchestrator(resultWithLookupFailed);
		const queue = makeQueue();
		const deps = { db, brandAuditSingle: orchestrator.fn, brandAuditQueue: queue.binding, now: () => 1_750_000_000_000 };

		await processBrandAuditMessage({ auditId: 'aud-1', target: 'example.com', format: 'json' }, deps);
		await processBrandAuditMessage({ auditId: 'aud-1', target: 'example.com', format: 'json' }, deps);

		expect(queue.sent).toHaveLength(1);
	});

	it('retry orchestrator throw preserves the original result_json (no destructive overwrite)', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const originalResultJson = JSON.stringify({ category: 'brand_audit', findings: [], score: 100 });
		const { db, getTargetRow } = makeMockD1({
			target: { status: 'completed', completed_at: 1000, result_json: originalResultJson, error: null },
		});

		const orchestrator = {
			fn: async () => { throw new Error('retry pass blew up'); },
			calls: [] as never[],
		};
		const queue = makeQueue();

		await processBrandAuditMessage(
			{ auditId: 'aud-1', target: 'example.com', format: 'json', retry_attempt: 1 },
			{ db, brandAuditSingle: orchestrator.fn, brandAuditQueue: queue.binding, now: () => 1_750_000_000_000 },
		);

		const final = getTargetRow();
		// Phase 2b correctness: a retry that throws MUST NOT destroy the
		// customer's first-pass result. The error column may capture the retry
		// failure, but result_json stays intact.
		expect(final.result_json, 'original result_json must survive a retry failure').toBe(originalResultJson);
	});

	it('retry message (retry_attempt=1) skips counter-tick and force_refreshes the orchestrator', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const { db, getCounter } = makeMockD1({ target: { status: 'completed', completed_at: 1000 } });
		const orchestrator = makeOrchestrator(resultClean);
		const queue = makeQueue();

		const verdict = await processBrandAuditMessage(
			{ auditId: 'aud-1', target: 'example.com', format: 'json', retry_attempt: 1 },
			{ db, brandAuditSingle: orchestrator.fn, brandAuditQueue: queue.binding, now: () => 1_750_000_000_000 },
		);

		expect(verdict).toBe('ack');
		expect(orchestrator.calls).toHaveLength(1);
		expect(orchestrator.calls[0].opts.force_refresh).toBe(true);
		expect(getCounter().completed_targets, 'retry pass must NOT bump completed_targets').toBe(0);
		expect(queue.sent, 'retry pass cannot enqueue another retry').toEqual([]);
	});
});
