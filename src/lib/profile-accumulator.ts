// SPDX-License-Identifier: MIT

/**
 * ProfileAccumulator Durable Object — collects per-profile and per-provider
 * category failure/score EMA statistics, and returns adaptive weights on demand.
 *
 * Single global instance routed by name "global".
 * Uses SQLite storage for persistent EMA tracking across two tables:
 * `profile_stats` and `provider_stats`.
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

// ─── Durable Object ────────────────────────────────────────────────────

/** ProfileAccumulator Durable Object for adaptive weight telemetry. */
export class ProfileAccumulator extends DurableObject<Env> {
	private initialized = false;

	private ensureSchema(): void {
		if (this.initialized) return;
		this.ctx.storage.sql.exec(SCHEMA_PROFILE_STATS);
		this.ctx.storage.sql.exec(SCHEMA_PROVIDER_STATS);
		this.initialized = true;
	}

	/** Handle incoming HTTP requests (POST /ingest, GET /weights). */
	async fetch(request: Request): Promise<Response> {
		this.ensureSchema();

		const url = new URL(request.url);
		const path = url.pathname;

		if (request.method === 'POST' && path === '/ingest') {
			return this.handleIngest(request);
		}

		if (request.method === 'GET' && path === '/weights') {
			return this.handleGetWeights(url);
		}

		return new Response('Not Found', { status: 404 });
	}

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
		}

		return new Response(null, { status: 204 });
	}

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
}
