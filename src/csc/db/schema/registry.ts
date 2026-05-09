// SPDX-License-Identifier: BUSL-1.1

/**
 * Drizzle ORM schema for the **shared registry D1** that fronts the CSC
 * super-tenant / sub-tenant model.
 *
 * Source of truth: `CSC-Scalable-Architecture-Design.md` §3.1.
 *
 * One DB across all super-tenants. Stores tenant metadata, API key hashes,
 * and billing events — never customer scan data (that lives per-tenant in
 * `./tenant.ts`).
 *
 * Migration: `src/csc/db/migrations/registry/0000_*.sql` (generated via
 * `npm run csc:migrate:registry`). Apply on the shared registry D1 with
 * `wrangler d1 migrations apply --remote <CSC_REGISTRY_DB>` once provisioned.
 */

import { index, integer, sqliteTable, text } from 'drizzle-orm/sqlite-core';

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
