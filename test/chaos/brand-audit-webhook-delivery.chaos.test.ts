// SPDX-License-Identifier: BUSL-1.1

/**
 * Chaos invariants for the brand-audit watch webhook delivery path (v2.21.1+).
 *
 * Hypotheses:
 *   1. Webhook delivery failure does NOT mark the audit failed — the target
 *      row still flips to 'completed' regardless of receiver outcome.
 *   2. Classification hash advances only after successful delivery, so a
 *      failed attempt is retried by a later watch run instead of being lost.
 *   3. A watch with no webhook_url still updates last_classification_hash on
 *      drift — drift detection is independent of delivery.
 *   4. Cross-owner spoofing (message.ownerId != watch.owner_id) is rejected.
 *   5. Same classification (no drift) does NOT fire the webhook even when
 *      webhook_url is set.
 */

import { describe, it, expect, vi } from 'vitest';
import type { BrandAuditConsumerDeps } from '../../src/queue/brand-audit-consumer';
import { computeClassificationHash } from '../../src/lib/brand-audit-classification-diff';

interface D1Call {
	sql: string;
	binds: unknown[];
}

interface MockDbOpts {
	target?: { status: string; completed_at: number | null } | null;
	auditAfter?: { completed_targets: number; total_targets: number } | null;
	watch?: {
		id: string;
		owner_id: string;
		domain: string;
		interval: string;
		webhook_url: string | null;
		last_classification_hash: string | null;
		last_classification_result_json?: string | null;
		pending_webhook_json?: string | null;
	} | null;
	priorResult?: { result_json: string } | null;
	priorResults?: Array<{ result_json: string }>;
}

function makeMockD1(opts: MockDbOpts = {}) {
	const calls: D1Call[] = [];
	let persistedHash = opts.watch?.last_classification_hash ?? null;
	let persistedBaseline = opts.watch?.last_classification_result_json ?? null;
	let pendingWebhook = opts.watch?.pending_webhook_json ?? null;
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
						return opts.target ?? null;
					}
					if (sql.includes('SELECT completed_targets, total_targets FROM brand_audits')) {
						return opts.auditAfter ?? null;
					}
					if (sql.includes('FROM brand_audit_watches WHERE id =')) {
						return opts.watch
							? {
									...opts.watch,
									last_classification_hash: persistedHash,
									last_classification_result_json: persistedBaseline,
									pending_webhook_json: pendingWebhook,
								}
							: null;
					}
					return null;
				},
				async run() {
					calls.push({ sql, binds });
					if (sql.includes('UPDATE brand_audit_watches SET pending_webhook_json = ?')) {
						const expectedPrior = sql.includes('last_classification_hash IS NULL') ? null : (binds[2] as string);
						if (persistedHash !== expectedPrior || pendingWebhook !== null) {
							return { success: true, meta: { changes: 0 } };
						}
						pendingWebhook = binds[0] as string;
						return { success: true, meta: { changes: 1 } };
					}
					if (sql.includes('UPDATE brand_audit_watches SET last_classification_hash')) {
						const finalizesPending = sql.includes('pending_webhook_json = NULL');
						const expectedPrior = sql.includes('last_classification_hash IS NULL') ? null : (binds[3] as string);
						const expectedPending = finalizesPending ? (binds[sql.includes('last_classification_hash IS NULL') ? 3 : 4] as string) : null;
						if (persistedHash !== expectedPrior || pendingWebhook !== expectedPending) {
							return { success: true, meta: { changes: 0 } };
						}
						persistedHash = binds[0] as string;
						persistedBaseline = binds[1] as string;
						if (finalizesPending) pendingWebhook = null;
						return { success: true, meta: { changes: 1 } };
					}
					if (sql.includes('UPDATE brand_audit_watches SET last_classification_result_json')) {
						if (persistedHash !== binds[2] || persistedBaseline !== null || pendingWebhook !== null) {
							return { success: true, meta: { changes: 0 } };
						}
						persistedBaseline = binds[0] as string;
						return { success: true, meta: { changes: 1 } };
					}
					return { success: true, meta: { changes: 1 } };
				},
				async all() {
					calls.push({ sql, binds });
					if (sql.includes('SELECT t.result_json FROM brand_audit_targets')) {
						return {
							results: opts.priorResults ?? (opts.priorResult ? [opts.priorResult] : []),
							success: true,
							meta: {},
						};
					}
					return { results: [], success: true, meta: {} };
				},
			};
			return stmt;
		},
	} as unknown as D1Database;
	return {
		db,
		calls,
		getPersistedHash: () => persistedHash,
		getPersistedBaseline: () => persistedBaseline,
		getPendingWebhook: () => pendingWebhook,
		setPersistedHash: (value: string | null) => {
			persistedHash = value;
		},
		setPendingWebhook: (value: string | null) => {
			pendingWebhook = value;
		},
	};
}

function makeBrandAuditResult(domains: Array<{ domain: string; bucket: string }>) {
	return {
		category: 'brand_discovery',
		score: 100,
		findings: domains.map((d) => ({
			category: 'brand_discovery',
			title: `Candidate: ${d.domain}`,
			severity: 'info',
			detail: '',
			metadata: {
				candidate: d.domain,
				bucket: d.bucket,
				signals: ['ns'],
				combinedConfidence: 0.9,
				registrar: 'X',
				registrarSource: 'rdap',
			},
		})),
	};
}

describe('chaos: brand-audit watch webhook delivery', () => {
	it('webhook 500 does NOT mark the audit failed — target still completed', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const fakeResult = makeBrandAuditResult([{ domain: 'a.com', bucket: 'consolidated' }]);
		const priorResult = makeBrandAuditResult([]);
		const priorHash = await computeClassificationHash(priorResult);
		const { db, calls } = makeMockD1({
			target: { status: 'queued', completed_at: null },
			auditAfter: { completed_targets: 1, total_targets: 1 },
			watch: {
				id: 'w-1',
				owner_id: 'owner-1',
				domain: 'apple.com',
				interval: 'weekly',
				webhook_url: 'https://hooks.example.com/x',
				last_classification_hash: priorHash,
			},
			priorResult: { result_json: JSON.stringify(priorResult) },
		});
		const deliverWebhook = vi.fn().mockResolvedValue(false); // simulate 500
		const brandAuditSingle = vi.fn().mockResolvedValue(fakeResult);

		const verdict = await processBrandAuditMessage(
			{ auditId: 'aud-1', target: 'apple.com', format: 'json', watchId: 'w-1', ownerId: 'owner-1' },
			{ db, brandAuditSingle, now: () => 1_750_000_000_000, deliverWebhook } as BrandAuditConsumerDeps,
		);

		expect(verdict).toBe('ack');
		// Target still flipped to completed.
		const completedUpdate = calls.find((c) => c.sql.includes('UPDATE brand_audit_targets') && (c.binds[0] as string) === 'completed');
		expect(completedUpdate).toBeDefined();
		// Webhook attempt was made.
		expect(deliverWebhook).toHaveBeenCalledTimes(1);
		expect(calls.some((c) => c.sql.includes('UPDATE brand_audit_watches SET last_classification_hash'))).toBe(false);
	});

	it('replays the exact non-empty H0→H1 payload after failure on an unchanged H1 tick', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const h0Result = makeBrandAuditResult([]);
		const h1Result = makeBrandAuditResult([{ domain: 'new.example', bucket: 'impersonation' }]);
		const h0 = await computeClassificationHash(h0Result);
		const h1 = await computeClassificationHash(h1Result);
		const state = makeMockD1({
			target: { status: 'queued', completed_at: null },
			auditAfter: { completed_targets: 1, total_targets: 1 },
			watch: {
				id: 'w-retry',
				owner_id: 'owner-1',
				domain: 'example.com',
				interval: 'daily',
				webhook_url: 'https://hooks.example.com/retry',
				last_classification_hash: h0,
				last_classification_result_json: JSON.stringify(h0Result),
			},
		});
		const deliverWebhook = vi.fn().mockResolvedValueOnce(false).mockResolvedValueOnce(true);
		const deps = {
			db: state.db,
			brandAuditSingle: vi.fn().mockResolvedValue(h1Result),
			now: () => 1_750_000_000_001,
			deliverWebhook,
		} as BrandAuditConsumerDeps;

		await processBrandAuditMessage(
			{ auditId: 'aud-h1-failed', target: 'example.com', format: 'json', watchId: 'w-retry', ownerId: 'owner-1' },
			deps,
		);
		expect(state.getPersistedHash()).toBe(h0);
		expect(state.getPendingWebhook()).not.toBeNull();
		const firstPayload = deliverWebhook.mock.calls[0]?.[1] as {
			auditId: string;
			previousHash: string;
			currentHash: string;
			changes: { added: Array<{ domain: string }> };
		};
		expect(firstPayload).toMatchObject({
			auditId: 'aud-h1-failed',
			previousHash: h0,
			currentHash: h1,
		});
		expect(firstPayload.changes.added).toEqual([expect.objectContaining({ domain: 'new.example' })]);

		await processBrandAuditMessage(
			{ auditId: 'aud-h1-unchanged', target: 'example.com', format: 'json', watchId: 'w-retry', ownerId: 'owner-1' },
			deps,
		);

		expect(deliverWebhook).toHaveBeenCalledTimes(2);
		expect(deliverWebhook.mock.calls[1]?.[1]).toEqual(firstPayload);
		expect(state.getPersistedHash()).toBe(h1);
		expect(state.getPendingWebhook()).toBeNull();
		expect(JSON.parse(state.getPersistedBaseline() ?? '{}')).toEqual(h1Result);
	});

	it('delivers failed H0→H1 and current H1→H2 in order during one recovery tick', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const h0Result = makeBrandAuditResult([]);
		const h1Result = makeBrandAuditResult([{ domain: 'one.example', bucket: 'shadowIt' }]);
		const h2Result = makeBrandAuditResult([
			{ domain: 'one.example', bucket: 'shadowIt' },
			{ domain: 'two.example', bucket: 'impersonation' },
		]);
		const h0 = await computeClassificationHash(h0Result);
		const h1 = await computeClassificationHash(h1Result);
		const h2 = await computeClassificationHash(h2Result);
		const state = makeMockD1({
			target: { status: 'queued', completed_at: null },
			auditAfter: { completed_targets: 1, total_targets: 1 },
			watch: {
				id: 'w-ordered',
				owner_id: 'owner-1',
				domain: 'example.com',
				interval: 'monthly',
				webhook_url: 'https://hooks.example.com/ordered',
				last_classification_hash: h0,
				last_classification_result_json: JSON.stringify(h0Result),
			},
		});
		const deliverWebhook = vi.fn().mockResolvedValueOnce(false).mockResolvedValueOnce(true).mockResolvedValueOnce(true);
		const brandAuditSingle = vi.fn().mockResolvedValueOnce(h1Result).mockResolvedValueOnce(h2Result);
		const deps = {
			db: state.db,
			brandAuditSingle,
			now: () => 1_750_000_000_002,
			deliverWebhook,
		} as BrandAuditConsumerDeps;

		await processBrandAuditMessage(
			{ auditId: 'aud-h1-failed', target: 'example.com', format: 'json', watchId: 'w-ordered', ownerId: 'owner-1' },
			deps,
		);
		const failedH1Payload = deliverWebhook.mock.calls[0]?.[1];

		await processBrandAuditMessage(
			{ auditId: 'aud-h2-current', target: 'example.com', format: 'json', watchId: 'w-ordered', ownerId: 'owner-1' },
			deps,
		);

		expect(deliverWebhook).toHaveBeenCalledTimes(3);
		expect(deliverWebhook.mock.calls[1]?.[1]).toEqual(failedH1Payload);
		expect(deliverWebhook.mock.calls[2]?.[1]).toMatchObject({
			auditId: 'aud-h2-current',
			previousHash: h1,
			currentHash: h2,
			changes: { added: [expect.objectContaining({ domain: 'two.example' })] },
		});
		expect(state.getPersistedHash()).toBe(h2);
		expect(state.getPendingWebhook()).toBeNull();
		expect(JSON.parse(state.getPersistedBaseline() ?? '{}')).toEqual(h2Result);
	});

	it('replays a bounded 200-row pending payload without poisoning later delivery', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const h0Result = makeBrandAuditResult([]);
		const h1Result = makeBrandAuditResult(
			Array.from({ length: 200 }, (_, index) => ({ domain: `candidate-${index}.example`, bucket: 'impersonation' })),
		);
		const h0 = await computeClassificationHash(h0Result);
		const h1 = await computeClassificationHash(h1Result);
		const state = makeMockD1({
			target: { status: 'queued', completed_at: null },
			auditAfter: { completed_targets: 1, total_targets: 1 },
			watch: {
				id: 'w-max-contract',
				owner_id: 'owner-1',
				domain: 'example.com',
				interval: 'daily',
				webhook_url: 'https://www.blackveilsecurity.com/api/webhooks/brand-drift?t=valid-watch-token',
				last_classification_hash: h0,
				last_classification_result_json: JSON.stringify(h0Result),
			},
		});
		const deliverWebhook = vi.fn().mockResolvedValueOnce(false).mockResolvedValueOnce(true);
		const deps = {
			db: state.db,
			brandAuditSingle: vi.fn().mockResolvedValue(h1Result),
			now: () => 1_750_000_000_003,
			deliverWebhook,
		} as BrandAuditConsumerDeps;

		await processBrandAuditMessage(
			{ auditId: 'aud-200-failed', target: 'example.com', format: 'json', watchId: 'w-max-contract', ownerId: 'owner-1' },
			deps,
		);
		const originalPayload = deliverWebhook.mock.calls[0]?.[1] as { changes: { added: unknown[] } };
		expect(originalPayload.changes.added).toHaveLength(200);
		expect(state.getPendingWebhook()).not.toBeNull();

		await processBrandAuditMessage(
			{ auditId: 'aud-200-recovery', target: 'example.com', format: 'json', watchId: 'w-max-contract', ownerId: 'owner-1' },
			deps,
		);

		expect(deliverWebhook.mock.calls[1]?.[1]).toEqual(originalPayload);
		expect(state.getPersistedHash()).toBe(h1);
		expect(state.getPendingWebhook()).toBeNull();
	});

	it('successful delivery advances the hash with a compare-and-swap against the prior value', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const fakeResult = makeBrandAuditResult([{ domain: 'a.com', bucket: 'consolidated' }]);
		const priorResult = makeBrandAuditResult([]);
		const priorHash = await computeClassificationHash(priorResult);
		const { db, calls } = makeMockD1({
			target: { status: 'queued', completed_at: null },
			auditAfter: { completed_targets: 1, total_targets: 1 },
			watch: {
				id: 'w-1',
				owner_id: 'owner-1',
				domain: 'apple.com',
				interval: 'weekly',
				webhook_url: 'https://hooks.example.com/x',
				last_classification_hash: priorHash,
			},
			priorResult: { result_json: JSON.stringify(priorResult) },
		});

		const callOrder: string[] = [];
		const deliverWebhook = vi.fn().mockImplementation(async () => {
			callOrder.push('webhook');
			return true;
		});
		const brandAuditSingle = vi.fn().mockResolvedValue(fakeResult);

		await processBrandAuditMessage(
			{ auditId: 'aud-1', target: 'apple.com', format: 'json', watchId: 'w-1', ownerId: 'owner-1' },
			{ db, brandAuditSingle, now: () => 1_750_000_000_000, deliverWebhook },
		);

		const hashUpdateIdx = calls.findIndex((c) => c.sql.includes('UPDATE brand_audit_watches SET last_classification_hash'));
		expect(hashUpdateIdx).toBeGreaterThanOrEqual(0);
		expect(callOrder).toEqual(['webhook']);
		const hashUpdate = calls[hashUpdateIdx];
		expect(hashUpdate.sql).toContain('AND last_classification_hash = ?');
		expect(hashUpdate.binds[3]).toBe(priorHash);
	});

	it('recovers an exact completed-target baseline even when its parent audit never reached completed', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const priorResult = makeBrandAuditResult([{ domain: 'old.example', bucket: 'shadowIt' }]);
		const currentResult = makeBrandAuditResult([{ domain: 'old.example', bucket: 'impersonation' }]);
		const priorHash = await computeClassificationHash(priorResult);
		const state = makeMockD1({
			target: { status: 'queued', completed_at: null },
			auditAfter: { completed_targets: 1, total_targets: 1 },
			watch: {
				id: 'w-stale-parent',
				owner_id: 'owner-1',
				domain: 'example.com',
				interval: 'daily',
				webhook_url: 'https://hooks.example.com/stale-parent',
				last_classification_hash: priorHash,
				last_classification_result_json: null,
			},
			priorResults: [{ result_json: JSON.stringify(priorResult) }],
		});
		const deliverWebhook = vi.fn().mockResolvedValue(true);

		await processBrandAuditMessage(
			{ auditId: 'aud-current', target: 'example.com', format: 'json', watchId: 'w-stale-parent', ownerId: 'owner-1' },
			{
				db: state.db,
				brandAuditSingle: vi.fn().mockResolvedValue(currentResult),
				now: () => 1_750_000_000_004,
				deliverWebhook,
			},
		);

		expect(deliverWebhook).toHaveBeenCalledOnce();
		expect(deliverWebhook.mock.calls[0]?.[1]).toMatchObject({
			previousHash: priorHash,
			changes: {
				modified: [expect.objectContaining({ domain: 'old.example', previousBucket: 'shadowIt', bucket: 'impersonation' })],
			},
		});
		const historyQuery = state.calls.find((call) => call.sql.includes('SELECT t.result_json FROM brand_audit_targets'));
		expect(historyQuery?.sql).toContain("t.status = 'completed'");
		expect(historyQuery?.sql).not.toContain('a.status');
	});

	it('uses the persisted adoption baseline on the first canonical-owner drift tick', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const adoptedBaseline = makeBrandAuditResult([{ domain: 'adopted.example', bucket: 'shadowIt' }]);
		const currentResult = makeBrandAuditResult([{ domain: 'adopted.example', bucket: 'impersonation' }]);
		const adoptedHash = await computeClassificationHash(adoptedBaseline);
		const state = makeMockD1({
			target: { status: 'queued', completed_at: null },
			auditAfter: { completed_targets: 1, total_targets: 1 },
			watch: {
				id: 'w-first-canonical',
				owner_id: 'a'.repeat(64),
				domain: 'example.com',
				interval: 'monthly',
				webhook_url: 'https://hooks.example.com/adopted',
				last_classification_hash: adoptedHash,
				last_classification_result_json: JSON.stringify(adoptedBaseline),
			},
		});
		const deliverWebhook = vi.fn().mockResolvedValue(true);

		await processBrandAuditMessage(
			{
				auditId: 'aud-first-canonical',
				target: 'example.com',
				format: 'json',
				watchId: 'w-first-canonical',
				ownerId: 'a'.repeat(64),
			},
			{
				db: state.db,
				brandAuditSingle: vi.fn().mockResolvedValue(currentResult),
				now: () => 1_750_000_000_005,
				deliverWebhook,
			},
		);

		expect(deliverWebhook.mock.calls[0]?.[1]).toMatchObject({
			previousHash: adoptedHash,
			changes: {
				modified: [expect.objectContaining({ domain: 'adopted.example', previousBucket: 'shadowIt', bucket: 'impersonation' })],
			},
		});
		expect(state.calls.some((call) => call.sql.includes('SELECT t.result_json FROM brand_audit_targets'))).toBe(false);
	});

	it('a stale concurrent successful delivery cannot regress a newer classification hash', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const fakeResult = makeBrandAuditResult([{ domain: 'a.com', bucket: 'consolidated' }]);
		const priorResult = makeBrandAuditResult([]);
		const priorHash = await computeClassificationHash(priorResult);
		const newerHash = 'new' + 'f'.repeat(61);
		const newerPending = JSON.stringify({ owner: 'newer-concurrent-delivery' });
		const state = makeMockD1({
			target: { status: 'queued', completed_at: null },
			auditAfter: { completed_targets: 1, total_targets: 1 },
			watch: {
				id: 'w-1',
				owner_id: 'owner-1',
				domain: 'apple.com',
				interval: 'weekly',
				webhook_url: 'https://hooks.example.com/x',
				last_classification_hash: priorHash,
			},
			priorResult: { result_json: JSON.stringify(priorResult) },
		});
		const deliverWebhook = vi.fn().mockImplementation(async () => {
			// Another invocation wins while this delivery is in flight and owns a
			// different outbox value.
			state.setPersistedHash(newerHash);
			state.setPendingWebhook(newerPending);
			return true;
		});

		await processBrandAuditMessage(
			{ auditId: 'aud-1', target: 'apple.com', format: 'json', watchId: 'w-1', ownerId: 'owner-1' },
			{ db: state.db, brandAuditSingle: vi.fn().mockResolvedValue(fakeResult), now: () => 1_750_000_000_000, deliverWebhook },
		);

		expect(state.getPersistedHash()).toBe(newerHash);
		expect(state.getPendingWebhook()).toBe(newerPending);
		const hashUpdate = state.calls.find((c) => c.sql.includes('UPDATE brand_audit_watches SET last_classification_hash'));
		expect(hashUpdate?.sql).toContain('AND last_classification_hash = ?');
		expect(hashUpdate?.sql).toContain('AND pending_webhook_json = ?');
		expect(hashUpdate?.binds[3]).toBe(priorHash);
	});

	it('watch with no webhook_url still persists hash on drift, never calls deliverWebhook', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const fakeResult = makeBrandAuditResult([{ domain: 'a.com', bucket: 'consolidated' }]);
		const { db, calls } = makeMockD1({
			target: { status: 'queued', completed_at: null },
			auditAfter: { completed_targets: 1, total_targets: 1 },
			watch: { id: 'w-1', owner_id: 'owner-1', domain: 'apple.com', interval: 'weekly', webhook_url: null, last_classification_hash: null },
		});
		const deliverWebhook = vi.fn();
		const brandAuditSingle = vi.fn().mockResolvedValue(fakeResult);

		await processBrandAuditMessage(
			{ auditId: 'aud-1', target: 'apple.com', format: 'json', watchId: 'w-1', ownerId: 'owner-1' },
			{ db, brandAuditSingle, now: () => 1_750_000_000_000, deliverWebhook },
		);

		const hashUpdate = calls.find((c) => c.sql.includes('UPDATE brand_audit_watches SET last_classification_hash'));
		expect(hashUpdate).toBeDefined();
		expect(deliverWebhook).not.toHaveBeenCalled();
	});

	it('cross-owner spoof: message.ownerId != watch.owner_id → no webhook, no hash update', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const fakeResult = makeBrandAuditResult([{ domain: 'a.com', bucket: 'consolidated' }]);
		const { db, calls } = makeMockD1({
			target: { status: 'queued', completed_at: null },
			auditAfter: { completed_targets: 1, total_targets: 1 },
			watch: {
				id: 'w-1',
				owner_id: 'owner-LEGIT',
				domain: 'apple.com',
				interval: 'weekly',
				webhook_url: 'https://hooks.example.com/x',
				last_classification_hash: null,
			},
		});
		const deliverWebhook = vi.fn();
		const brandAuditSingle = vi.fn().mockResolvedValue(fakeResult);

		await processBrandAuditMessage(
			{ auditId: 'aud-1', target: 'apple.com', format: 'json', watchId: 'w-1', ownerId: 'owner-SPOOFER' },
			{ db, brandAuditSingle, now: () => 1_750_000_000_000, deliverWebhook },
		);

		const hashUpdate = calls.find((c) => c.sql.includes('UPDATE brand_audit_watches SET last_classification_hash'));
		expect(hashUpdate).toBeUndefined();
		expect(deliverWebhook).not.toHaveBeenCalled();
	});

	it('same classification (no drift) does NOT fire the webhook', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const { computeClassificationHash } = await import('../../src/lib/brand-audit-classification-diff');
		const fakeResult = makeBrandAuditResult([{ domain: 'a.com', bucket: 'consolidated' }]);
		const stableHash = await computeClassificationHash(fakeResult);

		const { db, calls } = makeMockD1({
			target: { status: 'queued', completed_at: null },
			auditAfter: { completed_targets: 1, total_targets: 1 },
			watch: {
				id: 'w-1',
				owner_id: 'owner-1',
				domain: 'apple.com',
				interval: 'weekly',
				webhook_url: 'https://hooks.example.com/x',
				last_classification_hash: stableHash,
			},
		});
		const deliverWebhook = vi.fn();
		const brandAuditSingle = vi.fn().mockResolvedValue(fakeResult);

		await processBrandAuditMessage(
			{ auditId: 'aud-1', target: 'apple.com', format: 'json', watchId: 'w-1', ownerId: 'owner-1' },
			{ db, brandAuditSingle, now: () => 1_750_000_000_000, deliverWebhook },
		);

		expect(deliverWebhook).not.toHaveBeenCalled();
		const hashUpdate = calls.find((c) => c.sql.includes('UPDATE brand_audit_watches SET last_classification_hash'));
		expect(hashUpdate).toBeUndefined();
	});

	it('first-ever delivery (no prior hash, no prior result) populates `added` with the full current candidate set', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const fakeResult = makeBrandAuditResult([
			{ domain: 'apple.net', bucket: 'consolidated' },
			{ domain: 'apple.org', bucket: 'shadowIt' },
		]);
		const { db } = makeMockD1({
			target: { status: 'queued', completed_at: null },
			auditAfter: { completed_targets: 1, total_targets: 1 },
			watch: {
				id: 'w-1',
				owner_id: 'owner-1',
				domain: 'apple.com',
				interval: 'weekly',
				webhook_url: 'https://hooks.example.com/x',
				last_classification_hash: null,
			},
			// No priorResult — first-ever delivery for this watch.
		});
		const deliverWebhook = vi.fn().mockResolvedValue(true);
		const brandAuditSingle = vi.fn().mockResolvedValue(fakeResult);

		await processBrandAuditMessage(
			{ auditId: 'aud-1', target: 'apple.com', format: 'json', watchId: 'w-1', ownerId: 'owner-1' },
			{ db, brandAuditSingle, now: () => 1_750_000_000_000, deliverWebhook },
		);

		expect(deliverWebhook).toHaveBeenCalledTimes(1);
		const [, payload] = deliverWebhook.mock.calls[0];
		const typed = payload as {
			previousHash: string | null;
			changes: { added: Array<{ domain: string }>; removed: unknown[]; modified: unknown[] };
		};
		expect(typed.previousHash).toBeNull();
		// On first delivery, `added` carries the entire current candidate set.
		expect(typed.changes.added.map((c) => c.domain).sort()).toEqual(['apple.net', 'apple.org']);
		expect(typed.changes.removed).toEqual([]);
		expect(typed.changes.modified).toEqual([]);
	});

	it('webhook delivery throws → audit still completes cleanly (best-effort posture)', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const fakeResult = makeBrandAuditResult([{ domain: 'a.com', bucket: 'consolidated' }]);
		const { db, calls } = makeMockD1({
			target: { status: 'queued', completed_at: null },
			auditAfter: { completed_targets: 1, total_targets: 1 },
			watch: {
				id: 'w-1',
				owner_id: 'owner-1',
				domain: 'apple.com',
				interval: 'weekly',
				webhook_url: 'https://hooks.example.com/x',
				last_classification_hash: null,
			},
		});
		const deliverWebhook = vi.fn().mockRejectedValue(new Error('connection_reset'));
		const brandAuditSingle = vi.fn().mockResolvedValue(fakeResult);

		const verdict = await processBrandAuditMessage(
			{ auditId: 'aud-1', target: 'apple.com', format: 'json', watchId: 'w-1', ownerId: 'owner-1' },
			{ db, brandAuditSingle, now: () => 1_750_000_000_000, deliverWebhook },
		);

		expect(verdict).toBe('ack');
		const completedUpdate = calls.find((c) => c.sql.includes('UPDATE brand_audit_targets') && (c.binds[0] as string) === 'completed');
		expect(completedUpdate).toBeDefined();
		expect(calls.some((c) => c.sql.includes('UPDATE brand_audit_watches SET last_classification_hash'))).toBe(false);
	});
});
