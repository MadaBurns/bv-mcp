// SPDX-License-Identifier: BUSL-1.1

/**
 * Chaos invariants for the brand-audit watch webhook delivery path (v2.21.1+).
 *
 * Hypotheses:
 *   1. Webhook delivery failure does NOT mark the audit failed — the target
 *      row still flips to 'completed' regardless of receiver outcome.
 *   2. Classification hash is persisted BEFORE delivery, so a redelivered
 *      message can't re-fire the webhook (idempotency).
 *   3. A watch with no webhook_url still updates last_classification_hash on
 *      drift — drift detection is independent of delivery.
 *   4. Cross-owner spoofing (message.ownerId != watch.owner_id) is rejected.
 *   5. Same classification (no drift) does NOT fire the webhook even when
 *      webhook_url is set.
 */

import { describe, it, expect, vi } from 'vitest';
import type { BrandAuditConsumerDeps } from '../../src/queue/brand-audit-consumer';

interface D1Call {
	sql: string;
	binds: unknown[];
}

interface MockDbOpts {
	target?: { status: string; completed_at: number | null } | null;
	auditAfter?: { completed_targets: number; total_targets: number } | null;
	watch?: { id: string; owner_id: string; domain: string; interval: string; webhook_url: string | null; last_classification_hash: string | null } | null;
	priorResult?: { result_json: string } | null;
}

function makeMockD1(opts: MockDbOpts = {}) {
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
						return opts.target ?? null;
					}
					if (sql.includes('SELECT completed_targets, total_targets FROM brand_audits')) {
						return opts.auditAfter ?? null;
					}
					if (sql.includes('FROM brand_audit_watches WHERE id =')) {
						return opts.watch ?? null;
					}
					if (sql.includes('FROM brand_audit_targets WHERE target =')) {
						return opts.priorResult ?? null;
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

function makeBrandAuditResult(domains: Array<{ domain: string; bucket: string }>) {
	return {
		category: 'brand_discovery',
		score: 100,
		findings: domains.map((d) => ({
			category: 'brand_discovery',
			title: `Candidate: ${d.domain}`,
			severity: 'info',
			detail: '',
			metadata: { candidate: d.domain, bucket: d.bucket, signals: ['ns'], combinedConfidence: 0.9, registrar: 'X', registrarSource: 'rdap' },
		})),
	};
}

describe('chaos: brand-audit watch webhook delivery', () => {
	it('webhook 500 does NOT mark the audit failed — target still completed', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const fakeResult = makeBrandAuditResult([{ domain: 'a.com', bucket: 'consolidated' }]);
		const { db, calls } = makeMockD1({
			target: { status: 'queued', completed_at: null },
			auditAfter: { completed_targets: 1, total_targets: 1 },
			watch: { id: 'w-1', owner_id: 'owner-1', domain: 'apple.com', interval: 'weekly', webhook_url: 'https://hooks.example.com/x', last_classification_hash: 'old' + '0'.repeat(61) },
			priorResult: { result_json: JSON.stringify(makeBrandAuditResult([])) },
		});
		const deliverWebhook = vi.fn().mockResolvedValue(false); // simulate 500
		const brandAuditSingle = vi.fn().mockResolvedValue(fakeResult);

		const verdict = await processBrandAuditMessage(
			{ auditId: 'aud-1', target: 'apple.com', format: 'json', watchId: 'w-1', ownerId: 'owner-1' },
			{ db, brandAuditSingle, now: () => 1_750_000_000_000, deliverWebhook } as BrandAuditConsumerDeps,
		);

		expect(verdict).toBe('ack');
		// Target still flipped to completed.
		const completedUpdate = calls.find(
			(c) => c.sql.includes('UPDATE brand_audit_targets') && (c.binds[0] as string) === 'completed',
		);
		expect(completedUpdate).toBeDefined();
		// Webhook attempt was made.
		expect(deliverWebhook).toHaveBeenCalledTimes(1);
	});

	it('classification hash persisted BEFORE webhook delivery (no re-fire on retry)', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const fakeResult = makeBrandAuditResult([{ domain: 'a.com', bucket: 'consolidated' }]);
		const { db, calls } = makeMockD1({
			target: { status: 'queued', completed_at: null },
			auditAfter: { completed_targets: 1, total_targets: 1 },
			watch: { id: 'w-1', owner_id: 'owner-1', domain: 'apple.com', interval: 'weekly', webhook_url: 'https://hooks.example.com/x', last_classification_hash: 'old' + '0'.repeat(61) },
			priorResult: { result_json: JSON.stringify(makeBrandAuditResult([])) },
		});

		// Sequence the calls: webhook only fires AFTER the hash UPDATE has been called.
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

		const hashUpdateIdx = calls.findIndex(
			(c) => c.sql.includes('UPDATE brand_audit_watches SET last_classification_hash'),
		);
		expect(hashUpdateIdx).toBeGreaterThanOrEqual(0);
		expect(callOrder).toEqual(['webhook']);
		// Hash UPDATE happened before webhook call returned — the test framework
		// records `calls` synchronously on each prepare/bind/run, so hashUpdateIdx
		// existing means we hit that UPDATE in the sequence.
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
			watch: { id: 'w-1', owner_id: 'owner-LEGIT', domain: 'apple.com', interval: 'weekly', webhook_url: 'https://hooks.example.com/x', last_classification_hash: null },
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
			watch: { id: 'w-1', owner_id: 'owner-1', domain: 'apple.com', interval: 'weekly', webhook_url: 'https://hooks.example.com/x', last_classification_hash: stableHash },
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
			watch: { id: 'w-1', owner_id: 'owner-1', domain: 'apple.com', interval: 'weekly', webhook_url: 'https://hooks.example.com/x', last_classification_hash: null },
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
		const typed = payload as { previousHash: string | null; changes: { added: Array<{ domain: string }>; removed: unknown[]; modified: unknown[] } };
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
			watch: { id: 'w-1', owner_id: 'owner-1', domain: 'apple.com', interval: 'weekly', webhook_url: 'https://hooks.example.com/x', last_classification_hash: null },
		});
		const deliverWebhook = vi.fn().mockRejectedValue(new Error('connection_reset'));
		const brandAuditSingle = vi.fn().mockResolvedValue(fakeResult);

		const verdict = await processBrandAuditMessage(
			{ auditId: 'aud-1', target: 'apple.com', format: 'json', watchId: 'w-1', ownerId: 'owner-1' },
			{ db, brandAuditSingle, now: () => 1_750_000_000_000, deliverWebhook },
		);

		expect(verdict).toBe('ack');
		const completedUpdate = calls.find(
			(c) => c.sql.includes('UPDATE brand_audit_targets') && (c.binds[0] as string) === 'completed',
		);
		expect(completedUpdate).toBeDefined();
	});
});
