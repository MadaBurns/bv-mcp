// SPDX-License-Identifier: BUSL-1.1

/**
 * SQ-290 (fix wave T12) — brand-audit target claim lifecycle, against REAL D1
 * (`d1Databases: ['BRAND_AUDIT_DB']` in vitest.config.mts), so the conditional
 * UPDATEs below execute as SQL rather than being string-matched.
 *
 * Items pinned here:
 *   1. `running` rows age from the CLAIM, not from enqueue (`created_at`), in the
 *      cron reaper, `brand_audit_status` and `brand_audit_get_report`.
 *   2. The consumer's final write is guarded on `status = 'running'` and the
 *      audit counter only ticks when that row transition actually happened.
 *   3. A retryable failure AFTER the atomic claim releases the claim, so the
 *      redelivery can re-claim and finish instead of acking a row stuck `running`.
 */

import { beforeAll, describe, expect, it } from 'vitest';
import { env } from 'cloudflare:test';
import { processBrandAuditMessage } from '../src/queue/brand-audit-consumer';
import { reapStuckBrandAudits, STUCK_TARGET_THRESHOLD_MS, BRAND_AUDIT_TARGET_DEADLINE_MS } from '../src/lib/brand-audit-reaper';
import { brandAuditStatus } from '../src/tools/brand-audit-status';
import { brandAuditGetReport } from '../src/tools/brand-audit-get-report';
import { BrandAuditStepStoreError } from '../src/lib/brand-audit-step-store';

function brandAuditDb(): D1Database {
	return (env as unknown as { BRAND_AUDIT_DB: D1Database }).BRAND_AUDIT_DB;
}

// Mirrors the production tables (src/lib/db/brand-audit-schema.ts).
const SCHEMA = `
CREATE TABLE IF NOT EXISTS brand_audits (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL,
  status TEXT NOT NULL,
  total_targets INTEGER NOT NULL,
  completed_targets INTEGER NOT NULL DEFAULT 0,
  format TEXT NOT NULL,
  results_json TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  completed_at INTEGER
);
CREATE TABLE IF NOT EXISTS brand_audit_targets (
  audit_id TEXT NOT NULL REFERENCES brand_audits(id),
  target TEXT NOT NULL,
  status TEXT NOT NULL,
  result_json TEXT,
  pdf_r2_key TEXT,
  error TEXT,
  created_at INTEGER NOT NULL,
  completed_at INTEGER,
  PRIMARY KEY (audit_id, target)
);
CREATE TABLE IF NOT EXISTS brand_audit_steps (
  audit_id TEXT NOT NULL,
  target TEXT NOT NULL,
  step TEXT NOT NULL,
  status TEXT NOT NULL,
  payload_json TEXT,
  error TEXT,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (audit_id, target, step)
);`;

beforeAll(async () => {
	await brandAuditDb().exec(SCHEMA.replace(/\s+/g, ' ').trim());
});

const NOW = 1_750_000_000_000;
const MIN = 60_000;

interface SeedTarget {
	target: string;
	status: 'queued' | 'running' | 'completed' | 'failed';
	createdAt: number;
	/** Claim stamp (running) / completion time (terminal). */
	completedAt?: number | null;
	resultJson?: string | null;
}

async function seedAudit(opts: { total: number; completed?: number; createdAt: number; targets: SeedTarget[] }) {
	const db = brandAuditDb();
	const auditId = `aud-${crypto.randomUUID()}`;
	await db
		.prepare(
			"INSERT INTO brand_audits (id, owner_id, status, total_targets, completed_targets, format, created_at, updated_at) VALUES (?, 'owner-1', 'running', ?, ?, 'json', ?, ?)",
		)
		.bind(auditId, opts.total, opts.completed ?? 0, opts.createdAt, opts.createdAt)
		.run();
	for (const t of opts.targets) {
		await db
			.prepare(
				'INSERT INTO brand_audit_targets (audit_id, target, status, result_json, created_at, completed_at) VALUES (?, ?, ?, ?, ?, ?)',
			)
			.bind(auditId, t.target, t.status, t.resultJson ?? null, t.createdAt, t.completedAt ?? null)
			.run();
	}
	return auditId;
}

async function targetRow(auditId: string, target: string) {
	return (await brandAuditDb()
		.prepare('SELECT status, result_json, error, created_at, completed_at FROM brand_audit_targets WHERE audit_id = ? AND target = ?')
		.bind(auditId, target)
		.first()) as { status: string; result_json: string | null; error: string | null; created_at: number; completed_at: number | null };
}

async function auditRow(auditId: string) {
	return (await brandAuditDb()
		.prepare('SELECT status, completed_targets, total_targets FROM brand_audits WHERE id = ?')
		.bind(auditId)
		.first()) as { status: string; completed_targets: number; total_targets: number };
}

const OK_RESULT = { category: 'brand_discovery', score: 100, findings: [] };

describe('item 1 — running rows age from the claim, not from enqueue', () => {
	it('the consumer stamps the claim time on the row it claims', async () => {
		const auditId = await seedAudit({
			total: 1,
			createdAt: NOW - 30 * MIN,
			targets: [{ target: 'late.example.com', status: 'queued', createdAt: NOW - 30 * MIN }],
		});
		let observed: Awaited<ReturnType<typeof targetRow>> | undefined;
		const brandAuditSingle = async () => {
			observed = await targetRow(auditId, 'late.example.com');
			return OK_RESULT as never;
		};
		const verdict = await processBrandAuditMessage(
			{ auditId, target: 'late.example.com', format: 'json' },
			{ db: brandAuditDb(), brandAuditSingle, now: () => NOW },
		);
		expect(verdict).toBe('ack');
		// While the orchestrator runs, the row is `running` and carries the CLAIM time —
		// not null, and not the 30-minute-old enqueue time.
		expect(observed?.status).toBe('running');
		expect(observed?.completed_at).toBe(NOW);
	});

	it('cron reaper does not reap a target claimed recently even though it was enqueued long ago', async () => {
		const auditId = await seedAudit({
			total: 1,
			createdAt: NOW - 40 * MIN,
			targets: [{ target: 'late.example.com', status: 'running', createdAt: NOW - 40 * MIN, completedAt: NOW - 30_000 }],
		});
		await reapStuckBrandAudits({ db: brandAuditDb(), now: () => NOW });
		expect((await targetRow(auditId, 'late.example.com')).status).toBe('running');
	});

	it('cron reaper still reaps a target whose CLAIM is older than the threshold, and legacy running rows with no claim stamp', async () => {
		const auditId = await seedAudit({
			total: 2,
			createdAt: NOW - 40 * MIN,
			targets: [
				{
					target: 'claimed-long-ago.example.com',
					status: 'running',
					createdAt: NOW - 40 * MIN,
					completedAt: NOW - STUCK_TARGET_THRESHOLD_MS - MIN,
				},
				{ target: 'legacy.example.com', status: 'running', createdAt: NOW - 40 * MIN, completedAt: null },
			],
		});
		await reapStuckBrandAudits({ db: brandAuditDb(), now: () => NOW });
		expect((await targetRow(auditId, 'claimed-long-ago.example.com')).status).toBe('failed');
		expect((await targetRow(auditId, 'legacy.example.com')).status).toBe('failed');
	});

	it('brand_audit_status does not synthesise failed for a recently-claimed running target', async () => {
		const auditId = await seedAudit({
			total: 1,
			createdAt: NOW - 20 * MIN,
			targets: [{ target: 'late.example.com', status: 'running', createdAt: NOW - 20 * MIN, completedAt: NOW - 10_000 }],
		});
		const result = await brandAuditStatus(auditId, 'owner-1', { db: brandAuditDb(), now: () => NOW });
		const summary = result.findings.find((f) => f.metadata?.summary === true);
		const targets = summary?.metadata?.targets as Array<{ target: string; status: string; completedAt: number | null }>;
		expect(targets[0].status).toBe('running');
		// The claim stamp is internal bookkeeping, not a completion time.
		expect(targets[0].completedAt).toBeNull();
		expect((await targetRow(auditId, 'late.example.com')).status).toBe('running');
	});

	it('brand_audit_status still synthesises failed once the claim is older than the deadline', async () => {
		const auditId = await seedAudit({
			total: 1,
			createdAt: NOW - 20 * MIN,
			targets: [
				{
					target: 'stuck.example.com',
					status: 'running',
					createdAt: NOW - 20 * MIN,
					completedAt: NOW - BRAND_AUDIT_TARGET_DEADLINE_MS - MIN,
				},
			],
		});
		const result = await brandAuditStatus(auditId, 'owner-1', { db: brandAuditDb(), now: () => NOW });
		const summary = result.findings.find((f) => f.metadata?.summary === true);
		const targets = summary?.metadata?.targets as Array<{ status: string }>;
		expect(targets[0].status).toBe('failed');
	});

	it('brand_audit_get_report (per-target) does not synthesise failed for a recently-claimed running target', async () => {
		const auditId = await seedAudit({
			total: 1,
			createdAt: NOW - 20 * MIN,
			targets: [{ target: 'late.example.com', status: 'running', createdAt: NOW - 20 * MIN, completedAt: NOW - 10_000 }],
		});
		await brandAuditGetReport({ auditId, target: 'late.example.com' }, 'owner-1', { db: brandAuditDb(), now: () => NOW });
		expect((await targetRow(auditId, 'late.example.com')).status).toBe('running');
	});

	it('brand_audit_get_report (aggregate) counts a recently-claimed running target as running, not stuck', async () => {
		const auditId = await seedAudit({
			total: 1,
			createdAt: NOW - 20 * MIN,
			targets: [{ target: 'late.example.com', status: 'running', createdAt: NOW - 20 * MIN, completedAt: NOW - 10_000 }],
		});
		await brandAuditGetReport({ auditId }, 'owner-1', { db: brandAuditDb(), now: () => NOW });
		// An all-terminal misread would have flipped the parent audit to failed/completed.
		expect((await auditRow(auditId)).status).toBe('running');
	});
});

describe('item 2 — the final write is guarded on status = running', () => {
	it('a late result does not overwrite a failed row or tick the audit counter a second time', async () => {
		const auditId = await seedAudit({
			total: 2,
			createdAt: NOW - MIN,
			targets: [
				{ target: 'slow.example.com', status: 'queued', createdAt: NOW - MIN },
				{ target: 'sibling.example.com', status: 'running', createdAt: NOW - MIN, completedAt: NOW - 1_000 },
			],
		});
		const brandAuditSingle = async () => {
			// While the orchestrator is "running", the reaper (or the read path) fails
			// the row and ticks the parent counter once for it.
			await brandAuditDb()
				.prepare("UPDATE brand_audit_targets SET status = 'failed', error = 'reaper', completed_at = ? WHERE audit_id = ? AND target = ?")
				.bind(NOW, auditId, 'slow.example.com')
				.run();
			await brandAuditDb().prepare('UPDATE brand_audits SET completed_targets = completed_targets + 1 WHERE id = ?').bind(auditId).run();
			return OK_RESULT as never;
		};
		const verdict = await processBrandAuditMessage(
			{ auditId, target: 'slow.example.com', format: 'json' },
			{ db: brandAuditDb(), brandAuditSingle, now: () => NOW + 1_000 },
		);
		expect(verdict).toBe('ack');

		const row = await targetRow(auditId, 'slow.example.com');
		expect(row.status).toBe('failed');
		expect(row.result_json).toBeNull();
		const audit = await auditRow(auditId);
		// One tick (the reaper's), not two — and the audit is NOT finalised while the sibling still runs.
		expect(audit.completed_targets).toBe(1);
		expect(audit.status).toBe('running');
	});
});

describe('item 3 — a retryable failure after the claim releases the claim', () => {
	/** D1 wrapper that throws on the first statement matching `match` (after that, behaves normally). */
	function flakyDb(match: (sql: string) => boolean): D1Database {
		const real = brandAuditDb();
		let tripped = false;
		return {
			prepare(sql: string) {
				if (!tripped && match(sql)) {
					tripped = true;
					throw new Error('D1_ERROR: transient');
				}
				return real.prepare(sql);
			},
		} as unknown as D1Database;
	}

	it('final-write D1 failure → retry; row is released to queued so the redelivery re-claims and completes', async () => {
		const auditId = await seedAudit({
			total: 1,
			createdAt: NOW - MIN,
			targets: [{ target: 'brand.example.com', status: 'queued', createdAt: NOW - MIN }],
		});
		const brandAuditSingle = async () => OK_RESULT as never;
		const message = { auditId, target: 'brand.example.com', format: 'json' as const };

		const first = await processBrandAuditMessage(message, {
			db: flakyDb((sql) => sql.startsWith('UPDATE brand_audit_targets SET status = ?')),
			brandAuditSingle,
			now: () => NOW,
		});
		expect(first).toBe('retry');
		expect((await targetRow(auditId, 'brand.example.com')).status).toBe('queued');

		const second = await processBrandAuditMessage(message, { db: brandAuditDb(), brandAuditSingle, now: () => NOW + 1_000 });
		expect(second).toBe('ack');
		const row = await targetRow(auditId, 'brand.example.com');
		expect(row.status).toBe('completed');
		expect(row.result_json).not.toBeNull();
		const audit = await auditRow(auditId);
		expect(audit.completed_targets).toBe(1);
		expect(audit.status).toBe('completed');
	});

	it('step-store error → retry; row is released to queued', async () => {
		const auditId = await seedAudit({
			total: 1,
			createdAt: NOW - MIN,
			targets: [{ target: 'brand.example.com', status: 'queued', createdAt: NOW - MIN }],
		});
		const brandAuditSingle = async () => {
			throw new BrandAuditStepStoreError('put', new Error('d1 busy'));
		};
		const verdict = await processBrandAuditMessage(
			{ auditId, target: 'brand.example.com', format: 'json' },
			{ db: brandAuditDb(), brandAuditSingle, now: () => NOW },
		);
		expect(verdict).toBe('retry');
		expect((await targetRow(auditId, 'brand.example.com')).status).toBe('queued');
	});

	it('discover_only: final-write D1 failure → retry; row is released to queued', async () => {
		const { processDiscoverOnlyMessage } = await import('../src/queue/brand-audit-consumer');
		const auditId = await seedAudit({
			total: 1,
			createdAt: NOW - MIN,
			targets: [{ target: 'brand.example.com', status: 'queued', createdAt: NOW - MIN }],
		});
		const discoverBrandDomains = async () => OK_RESULT as never;
		const verdict = await processDiscoverOnlyMessage(
			{ auditId, target: 'brand.example.com', phase: 'discover_only' },
			{
				db: flakyDb((sql) => sql.startsWith('UPDATE brand_audit_targets SET status = ?')),
				discoverBrandDomains,
				now: () => NOW,
			},
		);
		expect(verdict).toBe('retry');
		expect((await targetRow(auditId, 'brand.example.com')).status).toBe('queued');
	});
});
