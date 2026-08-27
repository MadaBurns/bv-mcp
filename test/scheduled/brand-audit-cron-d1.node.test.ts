// SPDX-License-Identifier: BUSL-1.1

import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { processBrandAuditMessage } from '../../src/queue/brand-audit-consumer';
import { handleBrandAuditWatches } from '../../src/scheduled';

let miniflare: Miniflare | undefined;

afterEach(async () => {
	await miniflare?.dispose();
	miniflare = undefined;
});

const SCHEMA = `
CREATE TABLE brand_audits (
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
CREATE TABLE brand_audit_targets (
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
CREATE TABLE brand_audit_steps (
  audit_id TEXT NOT NULL,
  target TEXT NOT NULL,
  step TEXT NOT NULL,
  status TEXT NOT NULL,
  payload_json TEXT,
  error TEXT,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (audit_id, target, step)
);
CREATE TABLE brand_audit_watches (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL,
  domain TEXT NOT NULL,
  interval TEXT NOT NULL,
  webhook_url TEXT,
  last_run_at INTEGER,
  last_classification_hash TEXT,
  last_classification_result_json TEXT,
  pending_webhook_json TEXT,
  active INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL
);`;

describe('Brand Watch scheduler to consumer D1 contract', () => {
	it('persists the consumer precondition atomically before enqueue and the real consumer completes it', async () => {
		miniflare = new Miniflare(
			convertV4MiniflareOptions({
				modules: true,
				script: 'export default { fetch() { return new Response("ok") } }',
				d1Databases: { DB: `brand-watch-scheduler-${crypto.randomUUID()}` },
			}),
		);
		const db = (await miniflare.getD1Database('DB')) as unknown as D1Database;
		// D1 exec treats newlines as statement boundaries; compact each multi-line
		// CREATE while preserving semicolon boundaries.
		await db.exec(SCHEMA.replace(/\s+/g, ' ').trim());
		await db
			.prepare(
				'INSERT INTO brand_audit_watches (id, owner_id, domain, interval, webhook_url, last_run_at, last_classification_hash, active, created_at) VALUES (?, ?, ?, ?, NULL, NULL, NULL, 1, ?)',
			)
			.bind('watch-real-d1', 'owner-real-d1', 'example.com', 'daily', Date.now())
			.run();

		const messages: unknown[] = [];
		await handleBrandAuditWatches(
			{
				BRAND_AUDIT_DB: db,
				BRAND_AUDIT_QUEUE: { send: vi.fn(async (message: unknown) => void messages.push(message)) },
			},
			{ waitUntil: () => undefined } as unknown as ExecutionContext,
		);

		expect(messages).toHaveLength(1);
		const message = messages[0] as { auditId: string; target: string; watchId: string; ownerId: string; format: 'json' };
		const persisted = await db
			.prepare(
				'SELECT a.owner_id, a.status AS audit_status, t.target, t.status AS target_status FROM brand_audits a JOIN brand_audit_targets t ON t.audit_id = a.id WHERE a.id = ?',
			)
			.bind(message.auditId)
			.first<{ owner_id: string; audit_status: string; target: string; target_status: string }>();
		expect(persisted).toEqual({
			owner_id: 'owner-real-d1',
			audit_status: 'queued',
			target: 'example.com',
			target_status: 'queued',
		});

		const brandAuditSingle = vi.fn(async () => ({
			category: 'brand_discovery' as const,
			passed: true,
			score: 100,
			findings: [],
		}));
		await expect(
			processBrandAuditMessage(message, {
				db,
				brandAuditSingle,
				now: () => Date.now(),
			}),
		).resolves.toBe('ack');
		expect(brandAuditSingle).toHaveBeenCalledOnce();
		await expect(
			db
				.prepare('SELECT status FROM brand_audit_targets WHERE audit_id = ? AND target = ?')
				.bind(message.auditId, message.target)
				.first<{ status: string }>(),
		).resolves.toEqual({ status: 'completed' });
		await expect(
			db.prepare('SELECT status, completed_targets FROM brand_audits WHERE id = ?').bind(message.auditId).first(),
		).resolves.toEqual({ status: 'completed', completed_targets: 1 });
	});
});
