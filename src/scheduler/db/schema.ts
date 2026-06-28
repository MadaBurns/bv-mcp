// SPDX-License-Identifier: BUSL-1.1

/**
 * Drizzle ORM schema for the **optional** Phase 2 `SCAN_SCHEDULE_DB` (D1).
 *
 * This DB backs the default-OFF scheduler core (`src/scheduler/*`,
 * `src/lib/scan-scheduler.ts`). It is NOT bound in the public `wrangler.jsonc`;
 * an operator provisions it and applies the migration only at enable time, so
 * the subsystem ships byte-for-byte dark.
 *
 * Tables:
 *   - scan_schedule  one row per (tenant, domain). `id` is an autoincrement PK
 *                    (the GATE-4 claim `RETURNING id …` needs it); a separate
 *                    `UNIQUE(tenant_id, domain)` is the `upsertSchedule`
 *                    ON CONFLICT target. `idx_scan_schedule_due (active, lane,
 *                    next_scan_at)` serves the Form-B claim subquery.
 *   - scan_rollup    compact per-run record. RETENTION-BOUNDED (decisions
 *                    #8/#9): it MUST be pruned, never grown unbounded. Prune via
 *                    a daily cron / operator job:
 *                      DELETE FROM scan_rollup WHERE bucket_day < ?;
 *                    where `?` = floor((now - retentionMs) / 86_400_000). The
 *                    `idx_scan_rollup_bucket_day` index keeps that prune cheap.
 *
 * Migration: `src/scheduler/db/migrations/0000_scan_schedule.sql`, applied with
 * `wrangler d1 migrations apply --remote <SCAN_SCHEDULE_DB>` at enable time.
 *
 * NOTE: cadence is stored in MILLISECONDS (`cadence_ms`) to match the scheduler
 * core's ms-based arithmetic; `last_scanned_at` records the last successful scan.
 */

import { index, integer, sqliteTable, text, uniqueIndex } from 'drizzle-orm/sqlite-core';

export const scanSchedule = sqliteTable(
	'scan_schedule',
	{
		id: integer('id').primaryKey({ autoIncrement: true }),
		tenant_id: text('tenant_id').notNull(),
		domain: text('domain').notNull(),
		tier: text('tier'),
		lane: text('lane').notNull(),
		cadence_ms: integer('cadence_ms').notNull(),
		next_scan_at: integer('next_scan_at').notNull(),
		jitter_seed: integer('jitter_seed'),
		last_dispatched_at: integer('last_dispatched_at'),
		last_scanned_at: integer('last_scanned_at'),
		consecutive_failures: integer('consecutive_failures').notNull().default(0),
		active: integer('active', { mode: 'boolean' }).notNull().default(true),
		created_at: integer('created_at').notNull(),
	},
	(t) => [
		uniqueIndex('idx_scan_schedule_tenant_domain').on(t.tenant_id, t.domain),
		index('idx_scan_schedule_due').on(t.active, t.lane, t.next_scan_at),
	],
);

export const scanRollup = sqliteTable(
	'scan_rollup',
	{
		id: integer('id').primaryKey({ autoIncrement: true }),
		bucket_day: integer('bucket_day').notNull(),
		tenant_id: text('tenant_id').notNull(),
		domain: text('domain').notNull(),
		run_id: text('run_id'),
		grade: text('grade'),
		score: integer('score'),
		finding_count: integer('finding_count'),
		created_at: integer('created_at').notNull(),
	},
	(t) => [index('idx_scan_rollup_bucket_day').on(t.bucket_day), index('idx_scan_rollup_tenant_domain').on(t.tenant_id, t.domain)],
);
