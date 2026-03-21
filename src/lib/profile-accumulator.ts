// SPDX-License-Identifier: BUSL-1.1

/**
 * ProfileAccumulator Durable Object — collects per-profile and per-provider
 * category failure/score EMA statistics, and returns adaptive weights on demand.
 *
 * Also maintains intelligence layer tables (score histogram, provider cohort
 * summaries, trend snapshots) for benchmark and insight queries.
 *
 * Single global instance routed by name "global".
 * Uses SQLite storage for persistent EMA tracking across five tables:
 * `profile_stats`, `provider_stats`, `score_histogram`, `provider_cohort_summary`,
 * and `trend_snapshots`.
 */

import { DurableObject } from 'cloudflare:workers';
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

// ─── SQL schema ─────────────────────────────────────────────────────────

const SCHEMA_PROFILE_STATS = `CREATE TABLE IF NOT EXISTS profile_stats (
  profile TEXT NOT NULL, category TEXT NOT NULL,
  sample_count INTEGER DEFAULT 0, ema_failure_rate REAL DEFAULT 0.0,
  ema_avg_score REAL DEFAULT 0.0, last_updated INTEGER DEFAULT 0,
  PRIMARY KEY (profile, category)
);`;

const SCHEMA_PROVIDER_STATS = `CREATE TABLE IF NOT EXISTS provider_stats (
  profile TEXT NOT NULL, provider TEXT NOT NULL, category TEXT NOT NULL,
  sample_count INTEGER DEFAULT 0, ema_failure_rate REAL DEFAULT 0.0,
  ema_avg_score REAL DEFAULT 0.0, last_updated INTEGER DEFAULT 0,
  PRIMARY KEY (profile, provider, category)
);`;

// ─── Intelligence layer schema ──────────────────────────────────────────

const SCHEMA_SCORE_HISTOGRAM = `CREATE TABLE IF NOT EXISTS score_histogram (
  profile TEXT NOT NULL,
  bucket INTEGER NOT NULL,
  count INTEGER DEFAULT 0,
  last_updated INTEGER DEFAULT 0,
  PRIMARY KEY (profile, bucket)
);`;

const SCHEMA_PROVIDER_COHORT = `CREATE TABLE IF NOT EXISTS provider_cohort_summary (
  provider TEXT NOT NULL,
  profile TEXT NOT NULL,
  total_scans INTEGER DEFAULT 0,
  ema_overall_score REAL DEFAULT 0.0,
  top_failing_categories TEXT DEFAULT '[]',
  last_updated INTEGER DEFAULT 0,
  PRIMARY KEY (provider, profile)
);`;

const SCHEMA_TREND_SNAPSHOTS = `CREATE TABLE IF NOT EXISTS trend_snapshots (
  profile TEXT NOT NULL,
  snapshot_hour INTEGER NOT NULL,
  avg_score REAL DEFAULT 0.0,
  scan_count INTEGER DEFAULT 0,
  failure_rates TEXT DEFAULT '{}',
  PRIMARY KEY (profile, snapshot_hour)
);`;

// ─── Row types ──────────────────────────────────────────────────────────

interface ProfileStatsRow {
	[key: string]: SqlStorageValue;
	profile: string;
	category: string;
	sample_count: number;
	ema_failure_rate: number;
	ema_avg_score: number;
	last_updated: number;
}

interface ProviderStatsRow {
	[key: string]: SqlStorageValue;
	profile: string;
	provider: string;
	category: string;
	sample_count: number;
	ema_failure_rate: number;
	ema_avg_score: number;
	last_updated: number;
}

interface ScoreHistogramRow {
	[key: string]: SqlStorageValue;
	profile: string;
	bucket: number;
	count: number;
	last_updated: number;
}

interface ProviderCohortRow {
	[key: string]: SqlStorageValue;
	provider: string;
	profile: string;
	total_scans: number;
	ema_overall_score: number;
	top_failing_categories: string;
	last_updated: number;
}

interface TrendSnapshotRow {
	[key: string]: SqlStorageValue;
	profile: string;
	snapshot_hour: number;
	avg_score: number;
	scan_count: number;
	failure_rates: string;
}

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

	private ensureSchema(): void {
		if (this.initialized) return;
		this.ctx.storage.sql.exec(SCHEMA_PROFILE_STATS);
		this.ctx.storage.sql.exec(SCHEMA_PROVIDER_STATS);
		this.ctx.storage.sql.exec(SCHEMA_SCORE_HISTOGRAM);
		this.ctx.storage.sql.exec(SCHEMA_PROVIDER_COHORT);
		this.ctx.storage.sql.exec(SCHEMA_TREND_SNAPSHOTS);
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
			this.upsertProfileStats(profile, entry.category, failureValue, entry.score, now);

			// Upsert provider_stats if provider is present
			if (provider) {
				this.upsertProviderStats(profile, provider, entry.category, failureValue, entry.score, now);
			}

			categoryFailureMap.set(entry.category, entry.passed);
		}

		// Intelligence layer updates — only when overallScore is present
		const overallScore = typeof body.overallScore === 'number' && Number.isFinite(body.overallScore)
			? Math.max(0, Math.min(100, body.overallScore))
			: null;

		if (overallScore !== null) {
			this.updateScoreHistogram(profile, overallScore, now);
			this.updateTrendSnapshot(profile, overallScore, categoryFailureMap, now);

			if (provider) {
				this.updateProviderCohort(profile, provider, overallScore, categoryFailureMap, now);
			}
		}

		return new Response(null, { status: 204 });
	}

	// ─── Profile & provider stats upserts ─────────────────────────────────

	private upsertProfileStats(profile: string, category: string, failureValue: number, score: number, now: number): void {
		// Check if row exists
		const existing = this.ctx.storage.sql
			.exec<ProfileStatsRow>(
				'SELECT sample_count, ema_failure_rate, ema_avg_score FROM profile_stats WHERE profile = ? AND category = ?',
				profile,
				category,
			)
			.toArray();

		if (existing.length > 0) {
			const row = existing[0];
			const newFailureRate = EMA_ALPHA * failureValue + (1 - EMA_ALPHA) * row.ema_failure_rate;
			const newAvgScore = EMA_ALPHA * score + (1 - EMA_ALPHA) * row.ema_avg_score;
			this.ctx.storage.sql.exec(
				'UPDATE profile_stats SET sample_count = sample_count + 1, ema_failure_rate = ?, ema_avg_score = ?, last_updated = ? WHERE profile = ? AND category = ?',
				newFailureRate,
				newAvgScore,
				now,
				profile,
				category,
			);
		} else {
			// New row: apply EMA formula against initial 0
			const initFailureRate = EMA_ALPHA * failureValue;
			const initAvgScore = EMA_ALPHA * score;
			this.ctx.storage.sql.exec(
				'INSERT INTO profile_stats (profile, category, sample_count, ema_failure_rate, ema_avg_score, last_updated) VALUES (?, ?, 1, ?, ?, ?)',
				profile,
				category,
				initFailureRate,
				initAvgScore,
				now,
			);
		}
	}

	private upsertProviderStats(
		profile: string,
		provider: string,
		category: string,
		failureValue: number,
		score: number,
		now: number,
	): void {
		const existing = this.ctx.storage.sql
			.exec<ProviderStatsRow>(
				'SELECT sample_count, ema_failure_rate, ema_avg_score FROM provider_stats WHERE profile = ? AND provider = ? AND category = ?',
				profile,
				provider,
				category,
			)
			.toArray();

		if (existing.length > 0) {
			const row = existing[0];
			const newFailureRate = EMA_ALPHA * failureValue + (1 - EMA_ALPHA) * row.ema_failure_rate;
			const newAvgScore = EMA_ALPHA * score + (1 - EMA_ALPHA) * row.ema_avg_score;
			this.ctx.storage.sql.exec(
				'UPDATE provider_stats SET sample_count = sample_count + 1, ema_failure_rate = ?, ema_avg_score = ?, last_updated = ? WHERE profile = ? AND provider = ? AND category = ?',
				newFailureRate,
				newAvgScore,
				now,
				profile,
				provider,
				category,
			);
		} else {
			const initFailureRate = EMA_ALPHA * failureValue;
			const initAvgScore = EMA_ALPHA * score;
			this.ctx.storage.sql.exec(
				'INSERT INTO provider_stats (profile, category, provider, sample_count, ema_failure_rate, ema_avg_score, last_updated) VALUES (?, ?, ?, 1, ?, ?, ?)',
				profile,
				category,
				provider,
				initFailureRate,
				initAvgScore,
				now,
			);
		}
	}

	// ─── Intelligence layer upserts ───────────────────────────────────────

	/** Update score histogram bucket for the given profile and overall score. */
	private updateScoreHistogram(profile: string, overallScore: number, now: number): void {
		const bucket = Math.min(90, Math.floor(overallScore / 10) * 10);

		const existing = this.ctx.storage.sql
			.exec<ScoreHistogramRow>(
				'SELECT count FROM score_histogram WHERE profile = ? AND bucket = ?',
				profile,
				bucket,
			)
			.toArray();

		if (existing.length > 0) {
			this.ctx.storage.sql.exec(
				'UPDATE score_histogram SET count = count + 1, last_updated = ? WHERE profile = ? AND bucket = ?',
				now,
				profile,
				bucket,
			);
		} else {
			this.ctx.storage.sql.exec(
				'INSERT INTO score_histogram (profile, bucket, count, last_updated) VALUES (?, ?, 1, ?)',
				profile,
				bucket,
				now,
			);
		}
	}

	/** Update provider cohort summary with EMA-smoothed overall score. */
	private updateProviderCohort(
		profile: string,
		provider: string,
		overallScore: number,
		categoryFailures: Map<string, boolean>,
		now: number,
	): void {
		const existing = this.ctx.storage.sql
			.exec<ProviderCohortRow>(
				'SELECT total_scans, ema_overall_score FROM provider_cohort_summary WHERE provider = ? AND profile = ?',
				provider,
				profile,
			)
			.toArray();

		// Compute top failing categories from this scan's data
		const failingCats = Array.from(categoryFailures.entries())
			.filter(([, passed]) => !passed)
			.map(([cat]) => cat);

		if (existing.length > 0) {
			const row = existing[0];
			const newEmaScore = EMA_ALPHA * overallScore + (1 - EMA_ALPHA) * row.ema_overall_score;

			// Store up to 5 most recent failing categories
			const topFailing = JSON.stringify(failingCats.slice(0, 5));

			this.ctx.storage.sql.exec(
				'UPDATE provider_cohort_summary SET total_scans = total_scans + 1, ema_overall_score = ?, top_failing_categories = ?, last_updated = ? WHERE provider = ? AND profile = ?',
				newEmaScore,
				topFailing,
				now,
				provider,
				profile,
			);
		} else {
			const initScore = EMA_ALPHA * overallScore;
			const topFailing = JSON.stringify(failingCats.slice(0, 5));
			this.ctx.storage.sql.exec(
				'INSERT INTO provider_cohort_summary (provider, profile, total_scans, ema_overall_score, top_failing_categories, last_updated) VALUES (?, ?, 1, ?, ?, ?)',
				provider,
				profile,
				initScore,
				topFailing,
				now,
			);
		}
	}

	/** Update hourly trend snapshot with running average. */
	private updateTrendSnapshot(
		profile: string,
		overallScore: number,
		categoryFailures: Map<string, boolean>,
		now: number,
	): void {
		const snapshotHour = Math.floor(now / 3_600_000);

		// Build failure rates JSON from this scan
		const failureRates: Record<string, number> = {};
		for (const [cat, passed] of categoryFailures) {
			failureRates[cat] = passed ? 0 : 1;
		}

		const existing = this.ctx.storage.sql
			.exec<TrendSnapshotRow>(
				'SELECT avg_score, scan_count, failure_rates FROM trend_snapshots WHERE profile = ? AND snapshot_hour = ?',
				profile,
				snapshotHour,
			)
			.toArray();

		if (existing.length > 0) {
			const row = existing[0];
			const newCount = row.scan_count + 1;
			// Running average
			const newAvg = row.avg_score + (overallScore - row.avg_score) / newCount;

			// Merge failure rates (running average per category)
			let existingRates: Record<string, number> = {};
			try {
				existingRates = JSON.parse(row.failure_rates as string);
			} catch { /* empty */ }

			for (const [cat, rate] of Object.entries(failureRates)) {
				const prev = existingRates[cat] ?? rate;
				existingRates[cat] = prev + (rate - prev) / newCount;
			}

			this.ctx.storage.sql.exec(
				'UPDATE trend_snapshots SET avg_score = ?, scan_count = ?, failure_rates = ? WHERE profile = ? AND snapshot_hour = ?',
				newAvg,
				newCount,
				JSON.stringify(existingRates),
				profile,
				snapshotHour,
			);
		} else {
			// Evict old snapshots if over limit
			this.evictOldSnapshots(profile);

			this.ctx.storage.sql.exec(
				'INSERT INTO trend_snapshots (profile, snapshot_hour, avg_score, scan_count, failure_rates) VALUES (?, ?, ?, 1, ?)',
				profile,
				snapshotHour,
				overallScore,
				JSON.stringify(failureRates),
			);
		}
	}

	/** Remove oldest trend snapshots when limit is exceeded. */
	private evictOldSnapshots(profile: string): void {
		const countResult = this.ctx.storage.sql
			.exec<{ cnt: number }>('SELECT COUNT(*) as cnt FROM trend_snapshots WHERE profile = ?', profile)
			.toArray();

		const count = countResult[0]?.cnt ?? 0;
		if (count >= MAX_TREND_SNAPSHOTS_PER_PROFILE) {
			const toDelete = count - MAX_TREND_SNAPSHOTS_PER_PROFILE + 1;
			this.ctx.storage.sql.exec(
				'DELETE FROM trend_snapshots WHERE profile = ? AND snapshot_hour IN (SELECT snapshot_hour FROM trend_snapshots WHERE profile = ? ORDER BY snapshot_hour ASC LIMIT ?)',
				profile,
				profile,
				toDelete,
			);
		}
	}

	// ─── GET /weights (existing) ──────────────────────────────────────────

	private handleGetWeights(url: URL): Response {
		const profile = url.searchParams.get('profile');
		if (!profile) {
			return new Response('Missing required profile parameter', { status: 400 });
		}

		const provider = url.searchParams.get('provider');

		// Read profile_stats rows
		const rows = this.ctx.storage.sql
			.exec<ProfileStatsRow>('SELECT * FROM profile_stats WHERE profile = ?', profile)
			.toArray();

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
			if (provider) {
				const providerRows = this.ctx.storage.sql
					.exec<ProviderStatsRow>(
						'SELECT * FROM provider_stats WHERE profile = ? AND provider = ? AND category = ?',
						profile,
						provider,
						cat,
					)
					.toArray();

				if (providerRows.length > 0) {
					const pRow = providerRows[0];
					const modifier = (pRow.ema_failure_rate - row.ema_failure_rate) * 0.3 * staticWeight;
					finalWeight = Math.max(bounds.min, finalWeight + modifier);
				}
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
	private handleGetBenchmark(url: URL): Response {
		const profile = url.searchParams.get('profile') ?? 'mail_enabled';
		if (!VALID_PROFILES.has(profile)) {
			return new Response('Invalid profile', { status: 400 });
		}

		const rows = this.ctx.storage.sql
			.exec<ScoreHistogramRow>(
				'SELECT bucket, count, last_updated FROM score_histogram WHERE profile = ? ORDER BY bucket ASC',
				profile,
			)
			.toArray();

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
		const profileStatsRows = this.ctx.storage.sql
			.exec<ProfileStatsRow>(
				'SELECT category, ema_failure_rate FROM profile_stats WHERE profile = ? ORDER BY ema_failure_rate DESC LIMIT 5',
				profile,
			)
			.toArray();

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
	private handleGetProviderInsights(url: URL): Response {
		const provider = url.searchParams.get('provider');
		if (!provider) {
			return new Response('Missing required provider parameter', { status: 400 });
		}

		const profile = url.searchParams.get('profile') ?? 'mail_enabled';
		if (!VALID_PROFILES.has(profile)) {
			return new Response('Invalid profile', { status: 400 });
		}

		const rows = this.ctx.storage.sql
			.exec<ProviderCohortRow>(
				'SELECT * FROM provider_cohort_summary WHERE provider = ? AND profile = ?',
				provider,
				profile,
			)
			.toArray();

		if (rows.length === 0) {
			return Response.json({
				status: 'no_data',
				provider,
				profile,
			});
		}

		const row = rows[0];

		let topFailing: string[] = [];
		try {
			topFailing = JSON.parse(row.top_failing_categories);
		} catch { /* empty */ }

		// Get overall population stats for comparison
		const histogramRows = this.ctx.storage.sql
			.exec<ScoreHistogramRow>(
				'SELECT bucket, count FROM score_histogram WHERE profile = ? ORDER BY bucket ASC',
				profile,
			)
			.toArray();

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
	private handleGetTrends(url: URL): Response {
		const profile = url.searchParams.get('profile') ?? 'mail_enabled';
		if (!VALID_PROFILES.has(profile)) {
			return new Response('Invalid profile', { status: 400 });
		}

		const hoursParam = url.searchParams.get('hours');
		const hours = hoursParam ? Math.min(720, Math.max(1, parseInt(hoursParam, 10) || 168)) : 168;

		const currentHour = Math.floor(Date.now() / 3_600_000);
		const startHour = currentHour - hours;

		const rows = this.ctx.storage.sql
			.exec<TrendSnapshotRow>(
				'SELECT snapshot_hour, avg_score, scan_count, failure_rates FROM trend_snapshots WHERE profile = ? AND snapshot_hour >= ? ORDER BY snapshot_hour ASC',
				profile,
				startHour,
			)
			.toArray();

		if (rows.length === 0) {
			return Response.json({
				status: 'no_data',
				profile,
				hours,
			});
		}

		const snapshots = rows.map((r) => {
			let failureRates: Record<string, number> = {};
			try {
				failureRates = JSON.parse(r.failure_rates as string);
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
