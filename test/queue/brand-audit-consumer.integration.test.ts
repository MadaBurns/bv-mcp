// SPDX-License-Identifier: BUSL-1.1

/**
 * Tests for the brand-audit queue consumer.
 *
 * Strategy: mock D1 with a recording fake, inject a mocked `brandAuditSingle`,
 * exercise `processBrandAuditMessage` / `handleBrandAuditQueue` directly.
 *
 * Invariants asserted here:
 *   - Happy path: target row flips queued → running → completed; counter ticks
 *   - Idempotency: duplicate delivery of a `completed` row ack()s without re-running
 *   - Validation: malformed message body → ack (drop, don't retry forever)
 *   - Failure path: brandAuditSingle throws → target row flips → failed; counter ticks
 *   - Final-target sentinel: when completed_targets === total_targets, audit
 *     marked completed
 */

import { describe, it, expect, vi } from 'vitest';

interface D1Call {
	sql: string;
	binds: unknown[];
}

interface MakeMockOpts {
	target?: { status: string; completed_at: number | null } | null;
	auditAfter?: { completed_targets: number; total_targets: number } | null;
	throwOnUpdate?: boolean;
	throwOnStepStore?: boolean;
}

function makeMockD1(opts: MakeMockOpts = {}) {
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
					if (opts.throwOnStepStore && sql.includes('brand_audit_steps')) {
						throw new Error('D1_ERROR: no such table: brand_audit_steps');
					}
					if (sql.includes('SELECT status, completed_at FROM brand_audit_targets')) {
						return opts.target ?? null;
					}
					if (sql.includes('SELECT completed_targets, total_targets FROM brand_audits')) {
						return opts.auditAfter ?? null;
					}
					return null;
				},
				async run() {
					calls.push({ sql, binds });
					if (opts.throwOnUpdate && sql.includes('UPDATE')) throw new Error('d1_update_failed');
					// Model the conditional-claim UPDATE: the claim now parameterizes
					// the expected status (third bound arg) — match against the mocked
					// row's status to return changes=0 when "another worker already claimed".
					let changes = 1;
					const isClaim =
						sql.includes('UPDATE brand_audit_targets') &&
						sql.includes('SET status = \'running\' WHERE') &&
						sql.includes('status = ?');
					if (isClaim) {
						const expected = binds[2] as string | undefined;
						const currentStatus = opts.target?.status ?? 'queued';
						if (expected && currentStatus !== expected) {
							changes = 0;
						}
					}
					return { success: true, meta: { changes, last_row_id: 0, duration: 0, rows_read: 0, rows_written: changes, size_after: 0 } };
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

function fakeMessage(body: unknown, ack: () => void = vi.fn(), retry: () => void = vi.fn()) {
	return { id: 'msg-1', timestamp: new Date(), body, attempts: 1, ack, retry };
}

describe('processBrandAuditMessage', () => {
	it('runs brandAuditSingle, marks target completed, ticks audit counter', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const { db, calls } = makeMockD1({
			target: { status: 'queued', completed_at: null },
			auditAfter: { completed_targets: 1, total_targets: 3 },
		});
		const fakeResult = { category: 'brand_discovery', score: 100, findings: [] };
		const brandAuditSingle = vi.fn().mockResolvedValue(fakeResult);

		const verdict = await processBrandAuditMessage(
			{ auditId: 'aud-1', target: 'apple.com', format: 'json' },
			{ db, brandAuditSingle, now: () => 1_750_000_000_000 },
		);

		expect(verdict).toBe('ack');
		expect(brandAuditSingle).toHaveBeenCalledOnce();

		const updates = calls.filter((c) => c.sql.includes('UPDATE brand_audit_targets'));
		const completedUpdate = updates.find((c) => (c.binds[0] as string) === 'completed');
		expect(completedUpdate).toBeDefined();

		const auditTick = calls.find((c) => c.sql.includes('UPDATE brand_audits') && c.sql.includes('completed_targets'));
		expect(auditTick).toBeDefined();
	});

	it('acks without re-running when the row is already running (queue redelivery race)', async () => {
		// Cloudflare Queues visibility timeout is ~30s but a deep brand audit
		// runs for ~3min. Without an atomic claim, every redelivery would
		// re-enter brandAuditSingle while the first invocation is still running,
		// producing parallel-execution thrash that wedges the audit. The fix:
		// rely on the conditional `WHERE status = 'queued'` UPDATE to mutually
		// exclude — only the consumer whose UPDATE matches 1 row may proceed.
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const { db, calls } = makeMockD1({
			target: { status: 'running', completed_at: null },
		});
		const brandAuditSingle = vi.fn().mockResolvedValue({ category: 'brand_discovery', score: 100, findings: [] });

		const verdict = await processBrandAuditMessage(
			{ auditId: 'aud-1', target: 'brand-alpha.example.com', format: 'json' },
			{ db, brandAuditSingle, now: () => 1_750_000_000_000 },
		);

		expect(verdict).toBe('ack');
		expect(brandAuditSingle).not.toHaveBeenCalled();
		// Conditional claim UPDATE issued, terminal-status UPDATE not.
		const claimAttempt = calls.find(
			(c) =>
				c.sql.includes('UPDATE brand_audit_targets') &&
				c.sql.includes('SET status = \'running\' WHERE') &&
				c.sql.includes('status = ?') &&
				c.binds[2] === 'queued',
		);
		expect(claimAttempt).toBeDefined();
		const terminalUpdate = calls.find(
			(c) =>
				c.sql.includes('UPDATE brand_audit_targets SET status = ?') &&
				(c.binds[0] === 'completed' || c.binds[0] === 'failed'),
		);
		expect(terminalUpdate).toBeUndefined();
	});

	it('marks the parent audit running when a queued target starts', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const { db, calls } = makeMockD1({
			target: { status: 'queued', completed_at: null },
			auditAfter: { completed_targets: 1, total_targets: 3 },
		});
		const brandAuditSingle = vi.fn().mockResolvedValue({ category: 'brand_discovery', score: 100, findings: [] });

		await processBrandAuditMessage(
			{ auditId: 'aud-1', target: 'example.com', format: 'json' },
			{ db, brandAuditSingle, now: () => 1_750_000_000_000 },
		);

		const parentRunning = calls.find(
			(c) => c.sql.includes('UPDATE brand_audits') && c.sql.includes("status = 'running'") && c.binds.includes('aud-1'),
		);
		expect(parentRunning).toBeDefined();
	});

	it('passes deep-scan inputs from queue message into brandAuditSingle', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const { db } = makeMockD1({
			target: { status: 'queued', completed_at: null },
			auditAfter: { completed_targets: 1, total_targets: 1 },
		});
		const brandAuditSingle = vi.fn().mockResolvedValue({ category: 'brand_discovery', score: 100, findings: [] });

		await processBrandAuditMessage(
			{
				auditId: 'aud-1',
				target: 'example.com',
				format: 'json',
				depth: 'deep',
				brand_aliases: ['examplecorp'],
				candidate_domains: ['example.net'],
			},
			{ db, brandAuditSingle, now: () => 1_750_000_000_000 },
		);

		expect(brandAuditSingle).toHaveBeenCalledWith(
			'example.com',
			expect.objectContaining({
				depth: 'deep',
				brand_aliases: ['examplecorp'],
				candidate_domains: ['example.net'],
			}),
		);
	});

	it('passes the WHOIS service binding into brandAuditSingle deps for queued audits', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const { db } = makeMockD1({
			target: { status: 'queued', completed_at: null },
			auditAfter: { completed_targets: 1, total_targets: 1 },
		});
		const brandAuditSingle = vi.fn().mockResolvedValue({ category: 'brand_discovery', score: 100, findings: [] });
		const whoisBinding = { fetch: vi.fn() as unknown as typeof fetch };

		await processBrandAuditMessage(
			{ auditId: 'aud-1', target: 'example.com', format: 'json' },
			{ db, brandAuditSingle, whoisBinding, now: () => 1_750_000_000_000 },
		);

		expect(brandAuditSingle).toHaveBeenCalledWith(
			'example.com',
			expect.objectContaining({ auditId: 'aud-1' }),
			expect.objectContaining({ whoisBinding }),
		);
	});

	it('passes the certstream service binding into brandAuditSingle deps for queued audits', async () => {
		// Parity with the synchronous path (`handlers/tools.ts` brand_audit_single
		// execute closure threads `ro.certstream` into the pipeline deps). Without
		// this, the SAN signal in `discoverBrandDomains` falls back to the public
		// crt.sh fetch path for every queued audit, while sync calls use the
		// dedicated BV_CERTSTREAM binding. The deps-surface divergence is the
		// latent-correctness gap; this test pins parity.
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const { db } = makeMockD1({
			target: { status: 'queued', completed_at: null },
			auditAfter: { completed_targets: 1, total_targets: 1 },
		});
		const brandAuditSingle = vi.fn().mockResolvedValue({ category: 'brand_discovery', score: 100, findings: [] });
		const certstream = { fetch: vi.fn() as unknown as typeof fetch };

		await processBrandAuditMessage(
			{ auditId: 'aud-1', target: 'example.com', format: 'json' },
			{ db, brandAuditSingle, certstream, now: () => 1_750_000_000_000 },
		);

		expect(brandAuditSingle).toHaveBeenCalledWith(
			'example.com',
			expect.objectContaining({ auditId: 'aud-1' }),
			expect.objectContaining({ certstream }),
		);
	});

	it('passes the brandAuditQueue binding into brandAuditSingle deps for queued audits (CSC deep_scan enqueue)', async () => {
		// The pipeline at brand-audit-pipeline.ts:1061 only enqueues the
		// {phase:'deep_scan'} message when deps.brandAuditQueue is present.
		// Without this forwarding, queued view='csc_complement' audits write
		// csc_complement_fast only — brand_audit_get_report falls back to the
		// fast payload and the deep-scan-derived enrichment never materializes.
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const { db } = makeMockD1({
			target: { status: 'queued', completed_at: null },
			auditAfter: { completed_targets: 1, total_targets: 1 },
		});
		const brandAuditSingle = vi.fn().mockResolvedValue({ category: 'brand_discovery', score: 100, findings: [] });
		const brandAuditQueue = { send: vi.fn().mockResolvedValue(undefined) };

		await processBrandAuditMessage(
			{ auditId: 'aud-1', target: 'example.com', format: 'json', view: 'csc_complement' },
			{ db, brandAuditSingle, brandAuditQueue, now: () => 1_750_000_000_000 },
		);

		expect(brandAuditSingle).toHaveBeenCalledWith(
			'example.com',
			expect.objectContaining({ auditId: 'aud-1' }),
			expect.objectContaining({ brandAuditQueue }),
		);
	});

	it('passes auditId and a D1-backed stepStore into brandAuditSingle', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const { db, calls } = makeMockD1({
			target: { status: 'queued', completed_at: null },
			auditAfter: { completed_targets: 1, total_targets: 1 },
		});
		const brandAuditSingle = vi.fn(async (_target, options) => {
			expect(options.auditId).toBe('aud-1');
			expect(options.stepStore).toBeTruthy();
			await options.stepStore.put({
				auditId: 'aud-1',
				target: 'example.com',
				step: 'discovery',
				status: 'completed',
				payload: { resumed: true },
			});
			return { category: 'brand_discovery', score: 100, findings: [] };
		});

		const verdict = await processBrandAuditMessage(
			{ auditId: 'aud-1', target: 'example.com', format: 'json', min_confidence: 0.7 },
			{ db, brandAuditSingle, now: () => 1_750_000_000_000 },
		);

		expect(verdict).toBe('ack');
		expect(brandAuditSingle).toHaveBeenCalledWith(
			'example.com',
			expect.objectContaining({
				auditId: 'aud-1',
				format: 'json',
				min_confidence: 0.7,
				stepStore: expect.any(Object),
			}),
		);
		expect(calls.some((c) => c.sql.includes('INSERT INTO brand_audit_steps'))).toBe(true);
	});

	it('retries instead of failing the target when the step-store table is unavailable', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const { db, calls } = makeMockD1({
			target: { status: 'queued', completed_at: null },
			auditAfter: { completed_targets: 1, total_targets: 1 },
			throwOnStepStore: true,
		});
		const brandAuditSingle = vi.fn(async (_target, options) => {
			await options.stepStore?.get('aud-1', 'example.com', 'discovery');
			return { category: 'brand_discovery', score: 100, findings: [] };
		});

		const verdict = await processBrandAuditMessage(
			{ auditId: 'aud-1', target: 'example.com', format: 'json' },
			{ db, brandAuditSingle, now: () => 1_750_000_000_000 },
		);

		expect(verdict).toBe('retry');
		expect(calls.some((c) => c.sql.includes('UPDATE brand_audit_targets') && c.binds[0] === 'failed')).toBe(false);
	});

	it('marks the target failed without rejecting when the final result cannot be serialized', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const { db, calls } = makeMockD1({
			target: { status: 'queued', completed_at: null },
			auditAfter: { completed_targets: 1, total_targets: 1 },
		});
		const circular = { category: 'brand_discovery', score: 100, findings: [] as unknown[] } as Record<string, unknown>;
		circular.self = circular;
		const brandAuditSingle = vi.fn().mockResolvedValue(circular);

		const verdict = await processBrandAuditMessage(
			{ auditId: 'aud-1', target: 'example.com', format: 'json' },
			{ db, brandAuditSingle, now: () => 1_750_000_000_000 },
		);

		expect(verdict).toBe('ack');
		const failedUpdate = calls.find((c) => c.sql.includes('UPDATE brand_audit_targets') && c.binds[0] === 'failed');
		expect(failedUpdate?.binds[2]).toContain('brand_audit_result_serialization_failed');
	});

	it('is idempotent: a duplicate delivery of a completed target ack()s without re-running brandAuditSingle', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const { db, calls } = makeMockD1({
			target: { status: 'completed', completed_at: 1_700_000_000_000 },
		});
		const brandAuditSingle = vi.fn();

		const verdict = await processBrandAuditMessage(
			{ auditId: 'aud-1', target: 'apple.com', format: 'json' },
			{ db, brandAuditSingle, now: () => 1_750_000_000_000 },
		);

		expect(verdict).toBe('ack');
		expect(brandAuditSingle).not.toHaveBeenCalled();
		// Specifically: no UPDATE on brand_audit_targets after seeing completed.
		const writeOps = calls.filter((c) => c.sql.includes('UPDATE'));
		expect(writeOps).toHaveLength(0);
	});

	it('rejects malformed message body with ack (drop) — not retry forever', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const { db, calls } = makeMockD1({});
		const brandAuditSingle = vi.fn();

		const verdict = await processBrandAuditMessage(
			{ wrong: 'shape' } as unknown,
			{ db, brandAuditSingle, now: () => 1_750_000_000_000 },
		);

		expect(verdict).toBe('ack');
		expect(brandAuditSingle).not.toHaveBeenCalled();
		expect(calls).toHaveLength(0);
	});

	it('marks target failed and ticks counter when brandAuditSingle throws', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const { db, calls } = makeMockD1({
			target: { status: 'queued', completed_at: null },
			auditAfter: { completed_targets: 1, total_targets: 3 },
		});
		const brandAuditSingle = vi.fn().mockRejectedValue(new Error('discovery_timeout'));

		const verdict = await processBrandAuditMessage(
			{ auditId: 'aud-1', target: 'apple.com', format: 'json' },
			{ db, brandAuditSingle, now: () => 1_750_000_000_000 },
		);

		expect(verdict).toBe('ack');
		const failedUpdate = calls.find(
			(c) => c.sql.includes('UPDATE brand_audit_targets') && (c.binds[0] as string) === 'failed',
		);
		expect(failedUpdate).toBeDefined();
	});

	it('marks audit completed when this message was the final target', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const { db, calls } = makeMockD1({
			target: { status: 'queued', completed_at: null },
			auditAfter: { completed_targets: 3, total_targets: 3 },
		});
		const fakeResult = { category: 'brand_discovery', score: 100, findings: [] };
		const brandAuditSingle = vi.fn().mockResolvedValue(fakeResult);

		await processBrandAuditMessage(
			{ auditId: 'aud-1', target: 'final.example.com', format: 'json' },
			{ db, brandAuditSingle, now: () => 1_750_000_000_000 },
		);

		const auditFinalize = calls.find(
			(c) => c.sql.includes('UPDATE brand_audits') && c.sql.includes("status = 'completed'"),
		);
		expect(auditFinalize).toBeDefined();
	});

	it('fans out to the PDF queue on completion when format=both', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const { db } = makeMockD1({
			target: { status: 'queued', completed_at: null },
			auditAfter: { completed_targets: 1, total_targets: 3 },
		});
		const fakeResult = { category: 'brand_discovery', score: 100, findings: [] };
		const brandAuditSingle = vi.fn().mockResolvedValue(fakeResult);
		const pdfSend = vi.fn().mockResolvedValue(undefined);

		await processBrandAuditMessage(
			{ auditId: 'aud-1', target: 'apple.com', format: 'both' },
			{ db, brandAuditSingle, now: () => 1_750_000_000_000, pdfQueue: { send: pdfSend } },
		);

		expect(pdfSend).toHaveBeenCalledTimes(1);
		const [msg] = pdfSend.mock.calls[0];
		expect(msg).toMatchObject({ auditId: 'aud-1', target: 'apple.com', format: 'both' });
	});

	it('does NOT enqueue PDF when format=json', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const { db } = makeMockD1({
			target: { status: 'queued', completed_at: null },
			auditAfter: { completed_targets: 1, total_targets: 3 },
		});
		const fakeResult = { category: 'brand_discovery', score: 100, findings: [] };
		const brandAuditSingle = vi.fn().mockResolvedValue(fakeResult);
		const pdfSend = vi.fn();

		await processBrandAuditMessage(
			{ auditId: 'aud-1', target: 'apple.com', format: 'json' },
			{ db, brandAuditSingle, now: () => 1_750_000_000_000, pdfQueue: { send: pdfSend } },
		);

		expect(pdfSend).not.toHaveBeenCalled();
	});

	it('does NOT enqueue PDF when target failed (only on completed)', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const { db } = makeMockD1({
			target: { status: 'queued', completed_at: null },
			auditAfter: { completed_targets: 1, total_targets: 3 },
		});
		const brandAuditSingle = vi.fn().mockRejectedValue(new Error('oops'));
		const pdfSend = vi.fn();

		await processBrandAuditMessage(
			{ auditId: 'aud-1', target: 'apple.com', format: 'both' },
			{ db, brandAuditSingle, now: () => 1_750_000_000_000, pdfQueue: { send: pdfSend } },
		);

		expect(pdfSend).not.toHaveBeenCalled();
	});

	it('signals retry on a transient D1 update failure (no double-counting)', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const { db } = makeMockD1({
			target: { status: 'queued', completed_at: null },
			throwOnUpdate: true,
		});
		const fakeResult = { category: 'brand_discovery', score: 100, findings: [] };
		const brandAuditSingle = vi.fn().mockResolvedValue(fakeResult);

		const verdict = await processBrandAuditMessage(
			{ auditId: 'aud-1', target: 'apple.com', format: 'json' },
			{ db, brandAuditSingle, now: () => 1_750_000_000_000 },
		);

		expect(verdict).toBe('retry');
	});
});

describe('handleBrandAuditQueue', () => {
	it('ack/retry routes each message individually based on processBrandAuditMessage', async () => {
		const { handleBrandAuditQueue } = await import('../../src/queue/brand-audit-consumer');
		const { db } = makeMockD1({
			target: { status: 'queued', completed_at: null },
			auditAfter: { completed_targets: 1, total_targets: 3 },
		});

		const fakeResult = { category: 'brand_discovery', score: 100, findings: [] };
		const brandAuditSingle = vi.fn().mockResolvedValue(fakeResult);

		const ack1 = vi.fn();
		const retry1 = vi.fn();
		const ack2 = vi.fn();
		const retry2 = vi.fn();
		const batch = {
			queue: 'brand-audit-queue',
			messages: [
				fakeMessage({ auditId: 'aud-1', target: 'apple.com', format: 'json' }, ack1, retry1),
				fakeMessage({ wrong: 'shape' }, ack2, retry2),
			],
		} as unknown as MessageBatch<unknown>;

		await handleBrandAuditQueue(batch, { db, brandAuditSingle, now: () => 1_750_000_000_000 });

		expect(ack1).toHaveBeenCalled();
		expect(retry1).not.toHaveBeenCalled();
		expect(ack2).toHaveBeenCalled();
		expect(retry2).not.toHaveBeenCalled();
	});
});
