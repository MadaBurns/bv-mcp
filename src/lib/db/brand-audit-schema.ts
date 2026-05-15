// SPDX-License-Identifier: BUSL-1.1

/**
 * Drizzle ORM schema for the **brand-audit D1** (`brand-audit-v1`).
 *
 * Two-table model:
 *   - `brand_audits` — parent row per batch, written by `brand_audit_batch_start`
 *     before enqueueing per-target queue messages. `total_targets` is locked at
 *     enqueue time; `completed_targets` advances as the consumer drains.
 *   - `brand_audit_targets` — child row per (auditId, target) pair. Holds the
 *     per-target result JSON (full CheckResult from `brandAuditSingle`) and,
 *     once Phase 3 lands, the R2 key for the rendered PDF.
 *
 * `owner_id` stores the caller's principalId — same shape used by
 * `lib/rate-limiter.ts`: an API-key hash for authenticated callers, an IP hash
 * (`i_<fnv1a>`) for unauthenticated. Free/agent tiers can't reach this surface
 * (quota=0), so in practice owner_id is always a key hash, but the column is
 * permissive to match the existing principalId contract.
 *
 * Provisioning (not committed as a migration file — see CHANGELOG):
 *   wrangler d1 create brand-audit-v1
 *   wrangler d1 execute brand-audit-v1 --file docs/provisioning/brand-audit-v1.sql --remote
 *
 * Status state machine: queued → running → completed | failed.
 * Idempotency: consumer must SELECT status before re-running brandAuditSingle —
 * Cloudflare Queues can deliver a message N times on retry.
 */

import { index, integer, primaryKey, sqliteTable, text } from 'drizzle-orm/sqlite-core';

/** State machine for both audits and targets. */
export type BrandAuditStatus = 'queued' | 'running' | 'completed' | 'failed';

/** Output format requested at enqueue time. */
export type BrandAuditFormat = 'json' | 'markdown' | 'both';

export const brandAudits = sqliteTable(
	'brand_audits',
	{
		id: text('id').primaryKey(),
		owner_id: text('owner_id').notNull(),
		status: text('status', { enum: ['queued', 'running', 'completed', 'failed'] as const }).notNull(),
		total_targets: integer('total_targets').notNull(),
		completed_targets: integer('completed_targets').notNull().default(0),
		format: text('format', { enum: ['json', 'markdown', 'both'] as const }).notNull(),
		/** Aggregate per-audit summary JSON, populated by the consumer on final-target completion. */
		results_json: text('results_json'),
		created_at: integer('created_at').notNull(),
		updated_at: integer('updated_at').notNull(),
		completed_at: integer('completed_at'),
	},
	(t) => [index('idx_brand_audits_owner').on(t.owner_id, t.created_at)],
);

export const brandAuditTargets = sqliteTable(
	'brand_audit_targets',
	{
		audit_id: text('audit_id')
			.notNull()
			.references(() => brandAudits.id),
		target: text('target').notNull(),
		status: text('status', { enum: ['queued', 'running', 'completed', 'failed'] as const }).notNull(),
		/** Full per-target CheckResult JSON from `brandAuditSingle`. Null until status=completed. */
		result_json: text('result_json'),
		/** R2 object key for the rendered PDF. Populated in Phase 3 by the PDF queue consumer. */
		pdf_r2_key: text('pdf_r2_key'),
		/** Error message when status=failed. Sanitized — should not leak internal infra. */
		error: text('error'),
		created_at: integer('created_at').notNull(),
		completed_at: integer('completed_at'),
	},
	(t) => [primaryKey({ columns: [t.audit_id, t.target] })],
);

export type BrandAuditRow = typeof brandAudits.$inferSelect;
export type BrandAuditInsert = typeof brandAudits.$inferInsert;
export type BrandAuditTargetRow = typeof brandAuditTargets.$inferSelect;
export type BrandAuditTargetInsert = typeof brandAuditTargets.$inferInsert;
