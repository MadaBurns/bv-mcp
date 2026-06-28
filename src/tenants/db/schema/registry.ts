// SPDX-License-Identifier: BUSL-1.1

/**
 * Drizzle ORM schema for the **shared registry D1** that fronts the Tenant
 * super-tenant / sub-tenant model.
 *
 * One DB across all super-tenants. Stores tenant metadata, API key hashes,
 * and billing events — never customer scan data (that lives per-tenant in
 * `./tenant.ts`).
 *
 * Migration: `src/tenants/db/migrations/registry/0000_*.sql` (generated via
 * `npm run tenants:migrate:registry`). Apply on the shared registry D1 with
 * `wrangler d1 migrations apply --remote <TENANT_REGISTRY_DB>` once provisioned.
 */

import { index, integer, sqliteTable, text } from 'drizzle-orm/sqlite-core';
import { sql } from 'drizzle-orm';

export const superTenants = sqliteTable('super_tenants', {
	id: text('id').primaryKey(),
	name: text('name').notNull(),
	api_key_hash: text('api_key_hash').notNull(),
	d1_binding_prefix: text('d1_binding_prefix').notNull(),
	rate_limit_per_minute: integer('rate_limit_per_minute').default(1000),
	active: integer('active', { mode: 'boolean' }).default(true),
	created_at: integer('created_at').notNull(),
	metadata: text('metadata'),
});

export const subTenants = sqliteTable('sub_tenants', {
	id: text('id').primaryKey(),
	super_tenant_id: text('super_tenant_id')
		.notNull()
		.references(() => superTenants.id),
	name: text('name').notNull(),
	d1_db_id: text('d1_db_id').notNull(),
	/**
	 * Phase 4 (WFP routing) — per-tenant D1 backend selector consumed by
	 * `resolveTenant()` / `buildTenantDb()` in `src/tenants/tenant-resolver.ts`:
	 *   - `'convention'` (default) — today's static `TENANT_DB_<ID>` binding.
	 *   - `'dispatch'`   — a Workers-for-Platforms user Worker via
	 *                      `env.TENANT_DISPATCH_NAMESPACE`.
	 *   - `'rest'`       — the D1 REST-by-`d1_db_id` operator fallback.
	 * Nullable; absent/unknown → `'convention'` (ship-dark: behavior unchanged).
	 */
	routing_mode: text('routing_mode').default('convention'),
	domain_count: integer('domain_count').default(0),
	scan_schedule: text('scan_schedule'),
	scan_quota_per_month: integer('scan_quota_per_month'),
	active: integer('active', { mode: 'boolean' }).default(true),
	created_at: integer('created_at').notNull(),
});

export const tenantKeys = sqliteTable('tenant_keys', {
	key_hash: text('key_hash').primaryKey(),
	super_tenant_id: text('super_tenant_id')
		.notNull()
		.references(() => superTenants.id),
	sub_tenant_id: text('sub_tenant_id'),
	scope: text('scope').notNull(),
	expires_at: integer('expires_at'),
	revoked_at: integer('revoked_at'),
	last_used_at: integer('last_used_at'),
});

export const billingEvents = sqliteTable(
	'billing_events',
	{
		id: text('id').primaryKey(),
		super_tenant_id: text('super_tenant_id')
			.notNull()
			.references(() => superTenants.id),
		sub_tenant_id: text('sub_tenant_id'),
		event_type: text('event_type').notNull(),
		count: integer('count').notNull(),
		cost_cents: integer('cost_cents'),
		occurred_at: integer('occurred_at').notNull(),
	},
	(t) => [index('idx_billing_lookup').on(t.super_tenant_id, t.occurred_at)],
);

/**
 * Cross-tenant security/compliance audit log.
 *
 * Append-only ledger of every security-relevant action — tenant CRUD, scan
 * lifecycle, cross-tenant access decisions, auth outcomes. Never holds raw IPs
 * or secrets: `ip_hash` is the FNV-1a hash from `lib/analytics.ts`, and
 * `blob` is sanitized via `lib/log.ts` before insert (see `src/tenants/audit.ts`).
 *
 * Indexes serve the four documented read patterns:
 *   - per super-tenant timeline       → idx_audit_super_tenant_ts
 *   - per sub-tenant timeline         → idx_audit_sub_tenant_ts
 *   - per principal (key/OAuth) trace → idx_audit_actor_ts
 *   - per action drill-down           → idx_audit_action_ts
 */
export const auditEvents = sqliteTable(
	'audit_events',
	{
		id: text('id').primaryKey(),
		timestamp: integer('timestamp').notNull(),
		actor_principal: text('actor_principal').notNull(),
		actor_tier: text('actor_tier').notNull(),
		super_tenant_id: text('super_tenant_id').references(() => superTenants.id),
		sub_tenant_id: text('sub_tenant_id').references(() => subTenants.id),
		action: text('action').notNull(),
		resource_type: text('resource_type').notNull(),
		resource_id: text('resource_id'),
		outcome: text('outcome').notNull(),
		request_id: text('request_id'),
		cf_ray: text('cf_ray'),
		ip_hash: text('ip_hash'),
		blob: text('blob'),
	},
	(t) => [
		index('idx_audit_super_tenant_ts').on(t.super_tenant_id, t.timestamp),
		index('idx_audit_sub_tenant_ts').on(t.sub_tenant_id, t.timestamp),
		index('idx_audit_actor_ts').on(t.actor_principal, t.timestamp),
		index('idx_audit_action_ts').on(t.action, t.timestamp),
	],
);

/**
 * Tenant cycle tracking.
 *
 * One row per (sub_tenant, weekly-rescan run). The cron dispatcher
 * (`handleTenantWeeklyRescan` in `src/tenants/scheduled-handlers.ts`) inserts the
 * row with `expected_total` set to the number of domains it enqueued; the
 * queue consumer (`persistScan` in `src/tenants/queue-consumer.ts`) increments
 * `completed_total` per scan landed; and the dispatcher itself increments
 * `errored_total` for fingerprint / DNS failures so
 * `(completed_total + errored_total >= expected_total)` still resolves a
 * cycle whose first attempt couldn't even reach the queue.
 *
 * The cycle-alert sweep (`handleTenantCycleAlerts`) finds rows where the cycle
 * has settled (`completed_total + errored_total >= expected_total`) and
 * `alert_sent_at IS NULL`, computes the diff vs `baseline_cycle_id`, fires
 * the webhook, and stamps `alert_sent_at` + `alert_outcome`.
 *
 * The partial index `idx_cycles_pending_alert` is what makes the alert sweep
 * cheap: it scans only un-alerted rows.
 */
export const tenantCycles = sqliteTable(
	'tenant_cycles',
	{
		id: text('id').primaryKey(),
		super_tenant_id: text('super_tenant_id')
			.notNull()
			.references(() => superTenants.id),
		sub_tenant_id: text('sub_tenant_id')
			.notNull()
			.references(() => subTenants.id),
		started_at: integer('started_at').notNull(),
		expected_total: integer('expected_total').notNull(),
		completed_total: integer('completed_total').notNull().default(0),
		errored_total: integer('errored_total').notNull().default(0),
		alert_sent_at: integer('alert_sent_at'),
		alert_outcome: text('alert_outcome'),
		baseline_cycle_id: text('baseline_cycle_id'),
	},
	(t) => [
		index('idx_cycles_sub_tenant_ts').on(t.sub_tenant_id, t.started_at),
		index('idx_cycles_pending_alert').on(t.alert_sent_at).where(sql`${t.alert_sent_at} IS NULL`),
	],
);
