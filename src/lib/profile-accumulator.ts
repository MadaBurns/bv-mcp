// SPDX-License-Identifier: BUSL-1.1

/**
 * ProfileAccumulator Durable Object — collects per-profile and per-provider
 * category failure/score EMA statistics, and returns adaptive weights on demand.
 *
 * Also maintains intelligence layer tables (score histogram, provider cohort
 * summaries, trend snapshots) for benchmark and insight queries.
 *
 * Single global instance routed by name "global".
 * Uses SQLite storage (via Drizzle ORM) for persistent EMA tracking across five
 * tables: `profile_stats`, `provider_stats`, `score_histogram`,
 * `provider_cohort_summary`, and `trend_snapshots`.
 */

import { DurableObject } from 'cloudflare:workers';
import { and, asc, count, desc, eq, gte, inArray, type InferSelectModel, sql } from 'drizzle-orm';
import { drizzle, type DrizzleSqliteDODatabase } from 'drizzle-orm/durable-sqlite';
import {
	EMA_ALPHA,
	MATURITY_THRESHOLD,
	BASELINE_FAILURE_RATES,
	WEIGHT_BOUNDS,
	computeAdaptiveWeight,
	blendWeights,
} from './adaptive-weights';
import type { AdaptiveWeightsResponse } from './adaptive-weights';
import { PROFILE_WEIGHTS } from './context-profiles';
import * as schema from './db/schema';
import { profileStats, providerStats, scoreHistogram, providerCohortSummary, trendSnapshots } from './db/schema';

// ─── DDL schema strings (idempotent CREATE TABLE IF NOT EXISTS) ──────────
// Kept here for schema initialisation on first DO activation.
// The Drizzle schema in src/lib/db/schema.ts is the source of truth.

const SCHEMA_DDL = `
CREATE TABLE IF NOT EXISTS profile_stats (
  profile TEXT NOT NULL, category TEXT NOT NULL,
  sample_count INTEGER DEFAULT 0, ema_failure_rate REAL DEFAULT 0.0,
  ema_avg_score REAL DEFAULT 0.0, last_updated INTEGER DEFAULT 0,
  PRIMARY KEY (profile, category)
);
CREATE TABLE IF NOT EXISTS provider_stats (
  profile TEXT NOT NULL, provider TEXT NOT NULL, category TEXT NOT NULL,
  sample_count INTEGER DEFAULT 0, ema_failure_rate REAL DEFAULT 0.0,
  ema_avg_score REAL DEFAULT 0.0, last_updated INTEGER DEFAULT 0,
  PRIMARY KEY (profile, provider, category)
);
CREATE TABLE IF NOT EXISTS score_histogram (
  profile TEXT NOT NULL, bucket INTEGER NOT NULL,
  count INTEGER DEFAULT 0, last_updated INTEGER DEFAULT 0,
  PRIMARY KEY (profile, bucket)
);
CREATE TABLE IF NOT EXISTS provider_cohort_summary (
  provider TEXT NOT NULL, profile TEXT NOT NULL,
  total_scans INTEGER DEFAULT 0, ema_overall_score REAL DEFAULT 0.0,
  top_failing_categories TEXT DEFAULT '[]', last_updated INTEGER DEFAULT 0,
  PRIMARY KEY (provider, profile)
);
CREATE TABLE IF NOT EXISTS trend_snapshots (
  profile TEXT NOT NULL, snapshot_hour INTEGER NOT NULL,
  avg_score REAL DEFAULT 0.0, scan_count INTEGER DEFAULT 0,
  failure_rates TEXT DEFAULT '{}',
  PRIMARY KEY (profile, snapshot_hour)
);`;

// ─── Drizzle row types ───────────────────────────────────────────────────

type ProviderStatsRow = InferSelectModel<typeof providerStats>;

// ─── Validation ────────────────────────────────────────────────────────

/** Known scoring profiles accepted by the accumulator. */
const VALID_PROFILES = new Set(['mail_enabled', 'enterprise_mail', 'non_mail', 'web_only', 'minimal']);

/** Known check categories accepted by the accumulator. */
const VALID_CATEGORIES = new Set([
	'spf', 'dmarc', 'dkim', 'dnssec', 'ssl', 'mta_sts',
	'ns', 'caa', 'bimi', 'tlsrpt', 'subdomain_takeover', 'mx', 'lookalikes',
]);

/** Maximum number of category findings per ingest request. */
const MAX_CATEGORY_FINDINGS = 50;

/** Maximum string length for the provider field. */
const MAX_PROVIDER_LENGTH = 128;

/** Maximum trend snapshot rows per profile (30 days of hourly snapshots). */
const MAX_TREND_SNAPSHOTS_PER_PROFILE = 720;

/** Minimum scans required before benchmark data is considered meaningful. */
export const MIN_BENCHMARK_SCANS = 100;

// ─── Durable Object ────────────────────────────────────────────────────

/** ProfileAccumulator Durable Object for adaptive weight telemetry and intelligence aggregation. */
export class ProfileAccumulator extends DurableObject<Env> {
	private initialized = false;
	private db!: DrizzleSqliteDODatabase<typeof schema>;

	private ensureSchema(): void {
		if (this.initialized) return;
		// Run DDL directly on SqlStorage — CREATE TABLE IF NOT EXISTS is idempotent.
		// The Drizzle schema in src/lib/db/schema.ts is the source of truth for column types.
		for (const stmt of SCHEMA_DDL.split(';').map((s) => s.trim()).filter(Boolean)) {
			this.ctx.storage.sql.exec(stmt + ';');
		}
		this.db = drizzle(this.ctx.storage, { schema });
		this.initialized = true;
	}

	/** Handle incoming HTTP requests. */
	async fetch(request: Request): Promise<Response> {
		this.ensureSchema();

		const url = new URL(request.url);
		const path = url.pathname;

		if (request.method === 'POST' && path === '/ingest') {
			return this.handleIngest(request);
		}

		if (request.method === 'GET') {
			switch (path) {
				case '/weights':
					return this.handleGetWeights(url);
				case '/benchmark':
					return this.handleGetBenchmark(url);
				case '/provider-insights':
					return this.handleGetProviderInsights(url);
				case '/trends':
					return this.handleGetTrends(url);
				default:
					break;
			}
		}

		return new Response('Not Found', { status: 404 });
	}

	// ─── Ingest ───────────────────────────────────────────────────────────

	private async handleIngest(request: Request): Promise<Response> {
		let raw: unknown;
		try {
			raw = await request.json();
		} catch {
			return new Response('Invalid JSON', { status: 400 });
		}

		if (!raw || typeof raw !== 'object') {
			return new Response('Invalid payload', { status: 400 });
		}

		const body = raw as Record<string, unknown>;
		if (typeof body.profile !== 'string' || !body.profile) {
			return new Response('Missing required profile', { status: 400 });
		}
		if (!VALID_PROFILES.has(body.profile)) {
			return new Response('Invalid profile', { status: 400 });
		}
		if (!Array.isArray(body.categoryFindings) || body.categoryFindings.length > MAX_CATEGORY_FINDINGS) {
			return new Response('Missing or oversized categoryFindings array', { status: 400 });
		}
		const provider = typeof body.provider === 'string' ? body.provider : null;
		if (provider && provider.length > MAX_PROVIDER_LENGTH) {
			return new Response('Invalid provider: too long', { status: 400 });
		}

		const profile = body.profile;
		const now = Date.now();

		// Extract per-category failure rates for trend snapshots
		const categoryFailureMap = new Map<string, boolean>();

		for (const cf of body.categoryFindings as Array<unknown>) {
			if (!cf || typeof cf !== 'object') continue;
			const entry = cf as Record<string, unknown>;
			if (typeof entry.category !== 'string' || !VALID_CATEGORIES.has(entry.category)) continue;
			if (typeof entry.score !== 'number' || !Number.isFinite(entry.score) || entry.score < 0 || entry.score > 100) continue;
			if (typeof entry.passed !== 'boolean') continue;

			const failureValue = entry.passed ? 0.0 : 1.0;

			// Upsert profile_stats
			await this.upsertProfileStats(profile, entry.category, failureValue, entry.score, now);

			// Upsert provider_stats if provider is present
			if (provider) {
				await this.upsertProviderStats(profile, provider, entry.category, failureValue, entry.score, now);
			}

			categoryFailureMap.set(entry.category, entry.passed);
		}

		// Intelligence layer updates — only when overallScore is present
		const overallScore = typeof body.overallScore === 'number' && Number.isFinite(body.overallScore)
			? Math.max(0, Math.min(100, body.overallScore))
			: null;

		if (overallScore !== null) {
			await this.updateScoreHistogram(profile, overallScore, now);
			await this.updateTrendSnapshot(profile, overallScore, categoryFailureMap, now);

			if (provider) {
				await this.updateProviderCohort(profile, provider, overallScore, categoryFailureMap, now);
			}
		}

		return new Response(null, { status: 204 });
	}

	// ─── Profile & provider stats upserts ─────────────────────────────────

	private async upsertProfileStats(profile: string, category: string, failureValue: number, score: number, now: number): Promise<void> {
		const [existing] = await this.db
			.select({
				sample_count: profileStats.sample_count,
				ema_failure_rate: profileStats.ema_failure_rate,
				ema_avg_score: profileStats.ema_avg_score,
			})
			.from(profileStats)
			.where(and(eq(profileStats.profile, profile), eq(profileStats.category, category)));

		if (existing) {
			const newFailureRate = EMA_ALPHA * failureValue + (1 - EMA_ALPHA) * existing.ema_failure_rate;
			const newAvgScore = EMA_ALPHA * score + (1 - EMA_ALPHA) * existing.ema_avg_score;
			await this.db
				.update(profileStats)
				.set({
					sample_count: sql`${profileStats.sample_count} + 1`,
					ema_failure_rate: newFailureRate,
					ema_avg_score: newAvgScore,
					last_updated: now,
				})
				.where(and(eq(profileStats.profile, profile), eq(profileStats.category, category)));
		} else {
			// New row: apply EMA formula against initial 0
			await this.db.insert(profileStats).values({
				profile,
				category,
				sample_count: 1,
				ema_failure_rate: EMA_ALPHA * failureValue,
				ema_avg_score: EMA_ALPHA * score,
				last_updated: now,
			});
		}
	}

	private async upsertProviderStats(
		profile: string,
		provider: string,
		category: string,
		failureValue: number,
		score: number,
		now: number,
	): Promise<void> {
		const [existing] = await this.db
			.select({
				sample_count: providerStats.sample_count,
				ema_failure_rate: providerStats.ema_failure_rate,
				ema_avg_score: providerStats.ema_avg_score,
			})
			.from(providerStats)
			.where(
				and(
					eq(providerStats.profile, profile),
					eq(providerStats.provider, provider),
					eq(providerStats.category, category),
				),
			);

		if (existing) {
			const newFailureRate = EMA_ALPHA * failureValue + (1 - EMA_ALPHA) * existing.ema_failure_rate;
			const newAvgScore = EMA_ALPHA * score + (1 - EMA_ALPHA) * existing.ema_avg_score;
			await this.db
				.update(providerStats)
				.set({
					sample_count: sql`${providerStats.sample_count} + 1`,
					ema_failure_rate: newFailureRate,
					ema_avg_score: newAvgScore,
					last_updated: now,
				})
				.where(
					and(
						eq(providerStats.profile, profile),
						eq(providerStats.provider, provider),
						eq(providerStats.category, category),
					),
				);
		} else {
			await this.db.insert(providerStats).values({
				profile,
				provider,
				category,
				sample_count: 1,
				ema_failure_rate: EMA_ALPHA * failureValue,
				ema_avg_score: EMA_ALPHA * score,
				last_updated: now,
			});
		}
	}

	/** Update score histogram bucket for the given profile and overall score. */
	private async updateScoreHistogram(profile: string, overallScore: number, now: number): Promise<void> {
		const bucket = Math.min(90, Math.floor(overallScore / 10) * 10);

		const [existing] = await this.db
			.select({ count: scoreHistogram.count })
			.from(scoreHistogram)
			.where(and(eq(scoreHistogram.profile, profile), eq(scoreHistogram.bucket, bucket)));

		if (existing) {
			await this.db
				.update(scoreHistogram)
				.set({ count: sql`${scoreHistogram.count} + 1`, last_updated: now })
				.where(and(eq(scoreHistogram.profile, profile), eq(scoreHistogram.bucket, bucket)));
		} else {
			await this.db.insert(scoreHistogram).values({ profile, bucket, count: 1, last_updated: now });
		}
	}

	/** Update provider cohort summary with EMA-smoothed overall score. */
	private async updateProviderCohort(
		profile: string,
		provider: string,
		overallScore: number,
		categoryFailures: Map<string, boolean>,
		now: number,
	): Promise<void> {
		const [existing] = await this.db
			.select({
				total_scans: providerCohortSummary.total_scans,
				ema_overall_score: providerCohortSummary.ema_overall_score,
			})
			.from(providerCohortSummary)
			.where(and(eq(providerCohortSummary.provider, provider), eq(providerCohortSummary.profile, profile)));

		// Compute top failing categories from this scan's data
		const topFailing = JSON.stringify(
			Array.from(categoryFailures.entries())
				.filter(([, passed]) => !passed)
				.map(([cat]) => cat)
				.slice(0, 5),
		);

		if (existing) {
			const newEmaScore = EMA_ALPHA * overallScore + (1 - EMA_ALPHA) * existing.ema_overall_score;
			await this.db
				.update(providerCohortSummary)
				.set({
					total_scans: sql`${providerCohortSummary.total_scans} + 1`,
					ema_overall_score: newEmaScore,
					top_failing_categories: topFailing,
					last_updated: now,
				})
				.where(and(eq(providerCohortSummary.provider, provider), eq(providerCohortSummary.profile, profile)));
		} else {
			await this.db.insert(providerCohortSummary).values({
				provider,
				profile,
				total_scans: 1,
				ema_overall_score: EMA_ALPHA * overallScore,
				top_failing_categories: topFailing,
				last_updated: now,
			});
		}
	}

	/** Update hourly trend snapshot with running average. */
	private async updateTrendSnapshot(
		profile: string,
		overallScore: number,
		categoryFailures: Map<string, boolean>,
		now: number,
	): Promise<void> {
		const snapshotHour = Math.floor(now / 3_600_000);

		// Build failure rates JSON from this scan
		const failureRates: Record<string, number> = {};
		for (const [cat, passed] of categoryFailures) {
			failureRates[cat] = passed ? 0 : 1;
		}

		const [existing] = await this.db
			.select({
				avg_score: trendSnapshots.avg_score,
				scan_count: trendSnapshots.scan_count,
				failure_rates: trendSnapshots.failure_rates,
			})
			.from(trendSnapshots)
			.where(and(eq(trendSnapshots.profile, profile), eq(trendSnapshots.snapshot_hour, snapshotHour)));

		if (existing) {
			const newCount = existing.scan_count + 1;
			// Running average
			const newAvg = existing.avg_score + (overallScore - existing.avg_score) / newCount;

			// Merge failure rates (running average per category)
			let existingRates: Record<string, number> = {};
			try {
				existingRates = JSON.parse(existing.failure_rates);
			} catch { /* empty */ }

			for (const [cat, rate] of Object.entries(failureRates)) {
				const prev = existingRates[cat] ?? rate;
				existingRates[cat] = prev + (rate - prev) / newCount;
			}

			await this.db
				.update(trendSnapshots)
				.set({
					avg_score: newAvg,
					scan_count: newCount,
					failure_rates: JSON.stringify(existingRates),
				})
				.where(and(eq(trendSnapshots.profile, profile), eq(trendSnapshots.snapshot_hour, snapshotHour)));
		} else {
			// Evict old snapshots if over limit
			await this.evictOldSnapshots(profile);

			await this.db.insert(trendSnapshots).values({
				profile,
				snapshot_hour: snapshotHour,
				avg_score: overallScore,
				scan_count: 1,
				failure_rates: JSON.stringify(failureRates),
			});
		}
	}

	/** Remove oldest trend snapshots when limit is exceeded. */
	private async evictOldSnapshots(profile: string): Promise<void> {
		const [{ total }] = await this.db
			.select({ total: count() })
			.from(trendSnapshots)
			.where(eq(trendSnapshots.profile, profile));

		if (total >= MAX_TREND_SNAPSHOTS_PER_PROFILE) {
			const toDelete = total - MAX_TREND_SNAPSHOTS_PER_PROFILE + 1;
			const oldest = await this.db
				.select({ snapshot_hour: trendSnapshots.snapshot_hour })
				.from(trendSnapshots)
				.where(eq(trendSnapshots.profile, profile))
				.orderBy(asc(trendSnapshots.snapshot_hour))
				.limit(toDelete);

			await this.db
				.delete(trendSnapshots)
				.where(and(
					eq(trendSnapshots.profile, profile),
					inArray(trendSnapshots.snapshot_hour, oldest.map((r) => r.snapshot_hour)),
				));
		}
	}

	// ─── GET /weights (existing) ──────────────────────────────────────────

	private async handleGetWeights(url: URL): Promise<Response> {
		const profile = url.searchParams.get('profile');
		if (!profile) {
			return new Response('Missing required profile parameter', { status: 400 });
		}

		const provider = url.searchParams.get('provider');

		// Read all profile_stats rows for this profile
		const rows = await this.db.select().from(profileStats).where(eq(profileStats.profile, profile));

		if (rows.length === 0) {
			const response: AdaptiveWeightsResponse = {
				profile,
				provider: provider ?? null,
				sampleCount: 0,
				blendFactor: 0,
				weights: {},
				boundHits: [],
			};
			return Response.json(response);
		}

		// Determine static weights — use mail_enabled as fallback if profile is unknown
		const staticWeightMap = (PROFILE_WEIGHTS as Record<string, Record<string, { importance: number }>>)[profile] ??
			PROFILE_WEIGHTS.mail_enabled;
		const boundsMap = (WEIGHT_BOUNDS as Record<string, Record<string, { min: number; max: number }>>)[profile] ??
			WEIGHT_BOUNDS.mail_enabled;

		// Prefetch all provider stats for this profile+provider to avoid N+1 queries
		const providerStatsMap = new Map<string, ProviderStatsRow>();
		if (provider) {
			const pRows = await this.db
				.select()
				.from(providerStats)
				.where(and(eq(providerStats.profile, profile), eq(providerStats.provider, provider)));
			for (const r of pRows) {
				providerStatsMap.set(r.category, r);
			}
		}

		const weights: Record<string, number> = {};
		const boundHits: string[] = [];
		let minSampleCount = Infinity;

		for (const row of rows) {
			const cat = row.category;
			const staticEntry = staticWeightMap[cat];
			if (!staticEntry) continue;

			const staticWeight = staticEntry.importance;
			const baseline = BASELINE_FAILURE_RATES[cat] ?? 0;
			const bounds = boundsMap[cat] ?? { min: 0, max: staticWeight * 2 + 3 };

			const { weight: adaptiveWeight, boundHit } = computeAdaptiveWeight({
				staticWeight,
				emaFailureRate: row.ema_failure_rate,
				baselineFailureRate: baseline,
				bounds,
			});

			const blended = blendWeights(staticWeight, adaptiveWeight, row.sample_count);
			let finalWeight = blended;

			// Provider overlay
			const pRow = providerStatsMap.get(cat);
			if (pRow) {
				const modifier = (pRow.ema_failure_rate - row.ema_failure_rate) * 0.3 * staticWeight;
				finalWeight = Math.max(bounds.min, finalWeight + modifier);
			}

			weights[cat] = Math.round(finalWeight * 100) / 100;

			if (boundHit) {
				boundHits.push(cat);
			}

			if (row.sample_count < minSampleCount) {
				minSampleCount = row.sample_count;
			}
		}

		const sampleCount = minSampleCount === Infinity ? 0 : minSampleCount;
		const blendFactor = Math.min(1.0, sampleCount / MATURITY_THRESHOLD);

		const response: AdaptiveWeightsResponse = {
			profile,
			provider: provider ?? null,
			sampleCount,
			blendFactor: Math.round(blendFactor * 100) / 100,
			weights,
			boundHits,
		};

		return Response.json(response);
	}

	// ─── GET /benchmark ───────────────────────────────────────────────────

	/** Return score histogram and percentile distribution for a profile. */
	private async handleGetBenchmark(url: URL): Promise<Response> {
		const profile = url.searchParams.get('profile') ?? 'mail_enabled';
		if (!VALID_PROFILES.has(profile)) {
			return new Response('Invalid profile', { status: 400 });
		}

		const rows = await this.db
			.select({
				bucket: scoreHistogram.bucket,
				count: scoreHistogram.count,
				last_updated: scoreHistogram.last_updated,
			})
			.from(scoreHistogram)
			.where(eq(scoreHistogram.profile, profile))
			.orderBy(asc(scoreHistogram.bucket));

		const totalScans = rows.reduce((sum, r) => sum + r.count, 0);

		if (totalScans < MIN_BENCHMARK_SCANS) {
			return Response.json({
				status: 'insufficient_data',
				profile,
				totalScans,
				minimumRequired: MIN_BENCHMARK_SCANS,
				baselineFailureRates: BASELINE_FAILURE_RATES,
			});
		}

		// Build distribution and compute percentile ranks
		const distribution: Record<string, number> = {};
		const percentiles: Record<string, number> = {};
		let cumulative = 0;
		let weightedSum = 0;

		for (const row of rows) {
			const label = `${row.bucket}-${row.bucket + 9}`;
			const pct = Math.round((row.count / totalScans) * 10000) / 100;
			distribution[label] = pct;

			// Percentile: percentage of scans scoring at or below this bucket
			cumulative += row.count;
			percentiles[label] = Math.round((cumulative / totalScans) * 10000) / 100;

			// Weighted sum for mean (use midpoint of bucket)
			weightedSum += (row.bucket + 5) * row.count;
		}

		const meanScore = Math.round((weightedSum / totalScans) * 10) / 10;

		// Compute median bucket
		let medianCumulative = 0;
		let medianBucket = 50;
		for (const row of rows) {
			medianCumulative += row.count;
			if (medianCumulative >= totalScans / 2) {
				medianBucket = row.bucket;
				break;
			}
		}

		// Top failing categories from profile_stats
		const profileStatsRows = await this.db
			.select({ category: profileStats.category, ema_failure_rate: profileStats.ema_failure_rate })
			.from(profileStats)
			.where(eq(profileStats.profile, profile))
			.orderBy(desc(profileStats.ema_failure_rate))
			.limit(5);

		const topFailingCategories = profileStatsRows
			.filter((r) => r.ema_failure_rate > 0.1)
			.map((r) => r.category);

		const lastUpdated = rows.reduce((max, r) => Math.max(max, r.last_updated), 0);

		return Response.json({
			status: 'ok',
			profile,
			totalScans,
			meanScore,
			medianBucket,
			distribution,
			percentiles,
			topFailingCategories,
			dataFreshness: new Date(lastUpdated).toISOString(),
		});
	}

	// ─── GET /provider-insights ───────────────────────────────────────────

	/** Return provider cohort benchmark data. */
	private async handleGetProviderInsights(url: URL): Promise<Response> {
		const provider = url.searchParams.get('provider');
		if (!provider) {
			return new Response('Missing required provider parameter', { status: 400 });
		}

		const profile = url.searchParams.get('profile') ?? 'mail_enabled';
		if (!VALID_PROFILES.has(profile)) {
			return new Response('Invalid profile', { status: 400 });
		}

		const [row] = await this.db
			.select()
			.from(providerCohortSummary)
			.where(and(eq(providerCohortSummary.provider, provider), eq(providerCohortSummary.profile, profile)));

		if (!row) {
			return Response.json({ status: 'no_data', provider, profile });
		}

		let topFailing: string[] = [];
		try {
			topFailing = JSON.parse(row.top_failing_categories);
		} catch { /* empty */ }

		// Get overall population stats for comparison
		const histogramRows = await this.db
			.select({ bucket: scoreHistogram.bucket, count: scoreHistogram.count })
			.from(scoreHistogram)
			.where(eq(scoreHistogram.profile, profile))
			.orderBy(asc(scoreHistogram.bucket));

		const populationTotal = histogramRows.reduce((sum, r) => sum + r.count, 0);
		let populationMean: number | null = null;
		if (populationTotal > 0) {
			const weightedSum = histogramRows.reduce((sum, r) => sum + (r.bucket + 5) * r.count, 0);
			populationMean = Math.round((weightedSum / populationTotal) * 10) / 10;
		}

		// Compute percentile rank for this provider's EMA score
		let percentileRank: number | null = null;
		if (populationTotal >= MIN_BENCHMARK_SCANS) {
			const scoreBucket = Math.min(90, Math.floor(row.ema_overall_score / 10) * 10);
			let below = 0;
			for (const hr of histogramRows) {
				if (hr.bucket < scoreBucket) {
					below += hr.count;
				}
			}
			percentileRank = Math.round((below / populationTotal) * 100);
		}

		return Response.json({
			status: 'ok',
			provider,
			profile,
			totalScans: row.total_scans,
			emaOverallScore: Math.round(row.ema_overall_score * 10) / 10,
			topFailingCategories: topFailing,
			populationMeanScore: populationMean,
			percentileRank,
			dataFreshness: new Date(row.last_updated).toISOString(),
		});
	}

	// ─── GET /trends ──────────────────────────────────────────────────────

	/** Return hourly trend snapshots for a profile. */
	private async handleGetTrends(url: URL): Promise<Response> {
		const profile = url.searchParams.get('profile') ?? 'mail_enabled';
		if (!VALID_PROFILES.has(profile)) {
			return new Response('Invalid profile', { status: 400 });
		}

		const hoursParam = url.searchParams.get('hours');
		const hours = hoursParam ? Math.min(720, Math.max(1, parseInt(hoursParam, 10) || 168)) : 168;

		const currentHour = Math.floor(Date.now() / 3_600_000);
		const startHour = currentHour - hours;

		const rows = await this.db
			.select({
				snapshot_hour: trendSnapshots.snapshot_hour,
				avg_score: trendSnapshots.avg_score,
				scan_count: trendSnapshots.scan_count,
				failure_rates: trendSnapshots.failure_rates,
			})
			.from(trendSnapshots)
			.where(and(eq(trendSnapshots.profile, profile), gte(trendSnapshots.snapshot_hour, startHour)))
			.orderBy(asc(trendSnapshots.snapshot_hour));

		if (rows.length === 0) {
			return Response.json({ status: 'no_data', profile, hours });
		}

		const snapshots = rows.map((r) => {
			let failureRates: Record<string, number> = {};
			try {
				failureRates = JSON.parse(r.failure_rates);
			} catch { /* empty */ }

			return {
				hour: r.snapshot_hour,
				timestamp: new Date(r.snapshot_hour * 3_600_000).toISOString(),
				avgScore: Math.round(r.avg_score * 10) / 10,
				scanCount: r.scan_count,
				failureRates,
			};
		});

		const totalScans = snapshots.reduce((sum, s) => sum + s.scanCount, 0);
		const weightedAvg = totalScans > 0
			? snapshots.reduce((sum, s) => sum + s.avgScore * s.scanCount, 0) / totalScans
			: 0;

		return Response.json({
			status: 'ok',
			profile,
			hours,
			snapshotCount: snapshots.length,
			totalScans,
			periodAvgScore: Math.round(weightedAvg * 10) / 10,
			snapshots,
		});
	}
}
