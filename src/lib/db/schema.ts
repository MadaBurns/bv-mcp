// SPDX-License-Identifier: BUSL-1.1

/**
 * Drizzle ORM schema for the ProfileAccumulator Durable Object SQLite database.
 *
 * Five tables:
 *   profile_stats            — per-profile/category EMA failure rate and avg score
 *   provider_stats           — per-profile/provider/category EMA stats
 *   score_histogram          — bucketed score distribution per profile
 *   provider_cohort_summary  — aggregate cohort data per provider+profile
 *   trend_snapshots          — hourly trend data per profile
 */

import { integer, primaryKey, real, sqliteTable, text } from 'drizzle-orm/sqlite-core';

export const profileStats = sqliteTable(
	'profile_stats',
	{
		profile: text('profile').notNull(),
		category: text('category').notNull(),
		sample_count: integer('sample_count').notNull().default(0),
		ema_failure_rate: real('ema_failure_rate').notNull().default(0.0),
		ema_avg_score: real('ema_avg_score').notNull().default(0.0),
		last_updated: integer('last_updated').notNull().default(0),
	},
	(t) => [primaryKey({ columns: [t.profile, t.category] })],
);

export const providerStats = sqliteTable(
	'provider_stats',
	{
		profile: text('profile').notNull(),
		provider: text('provider').notNull(),
		category: text('category').notNull(),
		sample_count: integer('sample_count').notNull().default(0),
		ema_failure_rate: real('ema_failure_rate').notNull().default(0.0),
		ema_avg_score: real('ema_avg_score').notNull().default(0.0),
		last_updated: integer('last_updated').notNull().default(0),
	},
	(t) => [primaryKey({ columns: [t.profile, t.provider, t.category] })],
);

export const scoreHistogram = sqliteTable(
	'score_histogram',
	{
		profile: text('profile').notNull(),
		bucket: integer('bucket').notNull(),
		count: integer('count').notNull().default(0),
		last_updated: integer('last_updated').notNull().default(0),
	},
	(t) => [primaryKey({ columns: [t.profile, t.bucket] })],
);

export const providerCohortSummary = sqliteTable(
	'provider_cohort_summary',
	{
		provider: text('provider').notNull(),
		profile: text('profile').notNull(),
		total_scans: integer('total_scans').notNull().default(0),
		ema_overall_score: real('ema_overall_score').notNull().default(0.0),
		top_failing_categories: text('top_failing_categories').notNull().default('[]'),
		last_updated: integer('last_updated').notNull().default(0),
	},
	(t) => [primaryKey({ columns: [t.provider, t.profile] })],
);

export const trendSnapshots = sqliteTable(
	'trend_snapshots',
	{
		profile: text('profile').notNull(),
		snapshot_hour: integer('snapshot_hour').notNull(),
		avg_score: real('avg_score').notNull().default(0.0),
		scan_count: integer('scan_count').notNull().default(0),
		failure_rates: text('failure_rates').notNull().default('{}'),
	},
	(t) => [primaryKey({ columns: [t.profile, t.snapshot_hour] })],
);
