// SPDX-License-Identifier: BUSL-1.1

/**
 * Drizzle ORM schema for the **per-sub-tenant D1**.
 *
 * Source of truth: `CSC-Scalable-Architecture-Design.md` §3.2.
 *
 * One database per sub-tenant. Cloudflare's binding model enforces isolation
 * at the platform layer — a bug in one tenant's path can't read another
 * tenant's rows because the binding itself points at a different physical DB.
 *
 * Tables:
 *   - domains   the seed + discovery list (PK = domain, normalised lowercase)
 *   - scans     each scan_domain run, FK to domains, indexed by (domain, scan_at desc)
 *   - findings  per-scan findings, FK to scans, indexed by (domain, severity)
 *   - alerts    monitoring alerts, partial-indexed on triggered_at WHERE resolved_at IS NULL
 *
 * TODO(csc-d1-schemas): no `drizzle.config.*` exists yet. When added, the
 * generated migration must include the `idx_alerts_active` partial index
 * (`WHERE resolved_at IS NULL`) — drizzle-kit emits partial-index `where`
 * clauses but that's worth an audit test. R2 archival of cold scans (>90d)
 * is described in §3.2 storage table but lives outside the schema.
 */

import { index, integer, real, sqliteTable, text } from 'drizzle-orm/sqlite-core';
import { sql } from 'drizzle-orm';

export const domains = sqliteTable('domains', {
	domain: text('domain').primaryKey(),
	source: text('source').notNull(),
	added_at: integer('added_at').notNull(),
	last_scanned_at: integer('last_scanned_at'),
	last_score: integer('last_score'),
	last_grade: text('last_grade'),
	watch: integer('watch', { mode: 'boolean' }).default(true),
	watch_interval_hours: integer('watch_interval_hours').default(168),
	is_candidate: integer('is_candidate', { mode: 'boolean' }).default(false),
	discovery_signals: text('discovery_signals'),
	discovery_confidence: real('discovery_confidence'),
});

export const scans = sqliteTable(
	'scans',
	{
		id: text('id').primaryKey(),
		domain: text('domain')
			.notNull()
			.references(() => domains.domain),
		scan_at: integer('scan_at').notNull(),
		score: integer('score'),
		grade: text('grade'),
		maturity_stage: integer('maturity_stage'),
		finding_count: integer('finding_count'),
		result_json: text('result_json'),
		cycle_id: text('cycle_id'),
	},
	(t) => [index('idx_scans_domain_time').on(t.domain, t.scan_at), index('idx_scans_cycle').on(t.cycle_id)],
);

export const findings = sqliteTable(
	'findings',
	{
		id: text('id').primaryKey(),
		scan_id: text('scan_id')
			.notNull()
			.references(() => scans.id),
		domain: text('domain').notNull(),
		category: text('category').notNull(),
		severity: text('severity').notNull(),
		title: text('title').notNull(),
		detail: text('detail'),
		metadata: text('metadata'),
	},
	(t) => [index('idx_findings_domain_severity').on(t.domain, t.severity)],
);

export const alerts = sqliteTable(
	'alerts',
	{
		id: text('id').primaryKey(),
		domain: text('domain').notNull(),
		alert_type: text('alert_type').notNull(),
		triggered_at: integer('triggered_at').notNull(),
		resolved_at: integer('resolved_at'),
		detail: text('detail'),
		delivered_to: text('delivered_to'),
		delivered_at: integer('delivered_at'),
	},
	(t) => [index('idx_alerts_active').on(t.triggered_at).where(sql`${t.resolved_at} IS NULL`)],
);
