// SPDX-License-Identifier: BUSL-1.1

/**
 * Intelligence layer tools — expose anonymized aggregate insights
 * from the ProfileAccumulator Durable Object.
 *
 * These tools query pre-computed aggregates (histograms, cohort summaries,
 * trends) and never access per-domain data. Fail-open: returns a graceful
 * "unavailable" response when the DO binding is absent or unresponsive.
 */

import type { OutputFormat } from '../handlers/tool-args';
import { resolveAccumulatorShardName, type AccumulatorShardMode } from '../lib/profile-accumulator';
import { disposeUnreadResponseBody, readJsonResponseCapped } from '../lib/response-body';

/** Trend snapshot from the DO. */
export interface TrendSnapshot {
	hour: number;
	timestamp: string;
	avgScore: number;
	scanCount: number;
	failureRates: Record<string, number>;
}

/** Trend summary included in benchmark responses. */
export interface TrendSummary {
	hours: number;
	snapshotCount: number;
	totalScans: number;
	periodAvgScore: number;
	snapshots: TrendSnapshot[];
}

/**
 * Why a benchmark read came back `unavailable`.
 *
 * A bare `unavailable` is unactionable (#783): a caller's three sensible
 * responses — retry, fall back, or record a permanent limitation — cannot be
 * chosen between without knowing which happened. Measured 2026-08-24: the
 * `mail_enabled` profile returned `unavailable` while `enterprise_mail`
 * succeeded in the same window, which reads as "this profile has no cohort".
 * It was a 500ms timeout on the BUSIEST profile (1.47M scans vs 46k); the
 * identical call succeeded minutes later. Recorded in a client document as a
 * permanent scope limitation before it was caught.
 *
 * - `not_configured` — the DO binding is absent. Permanent for this deployment.
 * - `timeout` — the shard did not answer inside the budget. Retryable, and the
 *   likeliest reason on a large profile.
 * - `upstream_error` — the shard answered non-2xx. Retryable.
 */
export type BenchmarkUnavailableReason = 'not_configured' | 'timeout' | 'upstream_error';

/** Benchmark response from the DO. */
export interface BenchmarkResult {
	status: 'ok' | 'insufficient_data' | 'unavailable';
	profile: string;
	/** Set only when `status === 'unavailable'`. See {@link BenchmarkUnavailableReason}. */
	reason?: BenchmarkUnavailableReason;
	/** Set only when `status === 'unavailable'`. `false` means do not re-probe. */
	retryable?: boolean;
	totalScans?: number;
	minimumRequired?: number;
	meanScore?: number;
	medianBucket?: number;
	distribution?: Record<string, number>;
	percentiles?: Record<string, number>;
	topFailingCategories?: string[];
	baselineFailureRates?: Record<string, number>;
	dataFreshness?: string;
	trends?: TrendSummary;
}

/** Provider insights response from the DO. */
export interface ProviderInsightsResult {
	status: 'ok' | 'no_data' | 'unavailable';
	provider: string;
	profile: string;
	/** Set only when `status === 'unavailable'`. See {@link BenchmarkUnavailableReason}. */
	reason?: BenchmarkUnavailableReason;
	/** Set only when `status === 'unavailable'`. `false` means do not re-probe. */
	retryable?: boolean;
	totalScans?: number;
	emaOverallScore?: number;
	topFailingCategories?: string[];
	populationMeanScore?: number | null;
	percentileRank?: number | null;
	dataFreshness?: string;
}

/** Timeout for DO queries (ms). */
const INTELLIGENCE_FETCH_TIMEOUT_MS = 500;
const INTELLIGENCE_MAX_BODY_BYTES = 512 * 1024;

type IntelligenceFetchResult<T> = { kind: 'ok'; data: T } | { kind: 'timeout' | 'upstream_error' };

/** Bound both headers and body for a DO read and dispose every unused body. */
async function fetchIntelligenceJson<T>(stub: DurableObjectStub, url: string): Promise<IntelligenceFetchResult<T>> {
	const controller = new AbortController();
	const timeoutId = setTimeout(
		() => controller.abort(new DOMException('Intelligence read timed out', 'TimeoutError')),
		INTELLIGENCE_FETCH_TIMEOUT_MS,
	);
	try {
		const response = await stub.fetch(url, { method: 'GET', signal: controller.signal });
		if (!response.ok) {
			await disposeUnreadResponseBody(response);
			return { kind: 'upstream_error' };
		}
		const data = await readJsonResponseCapped<T>(response, INTELLIGENCE_MAX_BODY_BYTES);
		return data === null ? { kind: 'upstream_error' } : { kind: 'ok', data };
	} catch {
		return { kind: controller.signal.aborted ? 'timeout' : 'upstream_error' };
	} finally {
		clearTimeout(timeoutId);
	}
}

/**
 * Fetch benchmark data from the ProfileAccumulator DO.
 *
 * Read seam co-routing (R10): the benchmark read MUST resolve the SAME shard the
 * /ingest write targeted for this profile. `getBenchmark` carries the profile, so
 * `resolveAccumulatorShardName(profile, shardMode)` picks the shard the writes for
 * that profile landed in. Default `shardMode` (`'global'`/undefined) reads the
 * legacy single instance — byte-for-byte the prior behavior. This closes the
 * split-brain that would otherwise make get_benchmark read a write-starved
 * 'global' instance the moment sharding is flipped on.
 *
 * @param accumulator - ProfileAccumulator DO namespace binding
 * @param profile - Scoring profile to query (default: 'mail_enabled')
 * @param shardMode - Write-sharding mode (default 'global' → legacy instance).
 * @returns Benchmark data or unavailable response
 */
export async function getBenchmark(
	accumulator: DurableObjectNamespace | undefined,
	profile: string = 'mail_enabled',
	shardMode: AccumulatorShardMode = 'global',
): Promise<BenchmarkResult> {
	if (!accumulator) {
		return { status: 'unavailable', profile, reason: 'not_configured', retryable: false };
	}

	try {
		const shardName = resolveAccumulatorShardName(profile, shardMode);
		const stub = accumulator.get(accumulator.idFromName(shardName));
		const url = new URL('https://do/benchmark');
		url.searchParams.set('profile', profile);

		// ONE retry on timeout (#783). The measured failure was the busiest
		// profile missing a 500ms budget while a smaller sibling answered — a
		// blip, not a capability gap, but indistinguishable from one at the call
		// site. Retrying only the timeout path keeps the worst case at two
		// budgets and leaves a genuine upstream error to surface immediately.
		let benchmarkData: BenchmarkResult | undefined;
		for (let attempt = 0; attempt < 2; attempt++) {
			const result = await fetchIntelligenceJson<BenchmarkResult>(stub, url.toString());
			if (result.kind === 'ok') {
				benchmarkData = result.data;
				break;
			}
			if (result.kind === 'upstream_error') {
				return { status: 'unavailable', profile, reason: 'upstream_error', retryable: true };
			}
			if (attempt === 1) return { status: 'unavailable', profile, reason: 'timeout', retryable: true };
		}

		if (!benchmarkData) {
			return { status: 'unavailable', profile, reason: 'upstream_error', retryable: true };
		}

		// If benchmark data is available, also fetch trend data (best-effort)
		if (benchmarkData.status === 'ok') {
			try {
				const trendUrl = new URL('https://do/trends');
				trendUrl.searchParams.set('profile', profile);
				trendUrl.searchParams.set('hours', '168'); // 7 days

				const trendResponse = await fetchIntelligenceJson<{ status: string; snapshots?: TrendSnapshot[] } & TrendSummary>(
					stub,
					trendUrl.toString(),
				);

				if (trendResponse.kind === 'ok') {
					const trendData = trendResponse.data;
					if (trendData.status === 'ok' && trendData.snapshots) {
						benchmarkData.trends = {
							hours: trendData.hours,
							snapshotCount: trendData.snapshotCount,
							totalScans: trendData.totalScans,
							periodAvgScore: trendData.periodAvgScore,
							snapshots: trendData.snapshots,
						};
					}
				}
			} catch {
				// Trend fetch is best-effort — benchmark still valid without it
			}
		}

		return benchmarkData;
	} catch {
		// Shard resolution / JSON parse failed rather than the fetch — retryable,
		// but not a timeout, so it is reported as an upstream problem.
		return { status: 'unavailable', profile, reason: 'upstream_error', retryable: true };
	}
}

/**
 * Fetch provider insights from the ProfileAccumulator DO.
 *
 * Read seam co-routing (R10): resolves the SAME shard the writes for this profile
 * landed in via `resolveAccumulatorShardName(profile, shardMode)`. Default
 * `shardMode` reads the legacy 'global' instance — unchanged behavior.
 *
 * @param accumulator - ProfileAccumulator DO namespace binding
 * @param provider - Email provider name to query
 * @param profile - Scoring profile (default: 'mail_enabled')
 * @param shardMode - Write-sharding mode (default 'global' → legacy instance).
 * @returns Provider cohort data or unavailable response
 */
export async function getProviderInsights(
	accumulator: DurableObjectNamespace | undefined,
	provider: string,
	profile: string = 'mail_enabled',
	shardMode: AccumulatorShardMode = 'global',
): Promise<ProviderInsightsResult> {
	if (!accumulator) {
		return { status: 'unavailable', provider, profile, reason: 'not_configured', retryable: false };
	}

	try {
		const shardName = resolveAccumulatorShardName(profile, shardMode);
		const stub = accumulator.get(accumulator.idFromName(shardName));
		const url = new URL('https://do/provider-insights');
		url.searchParams.set('provider', provider);
		url.searchParams.set('profile', profile);

		// Same one-retry-on-timeout as `getBenchmark` — this reads the same DO
		// under the same budget, so it has the same blip-vs-gap ambiguity (#783).
		let providerData: ProviderInsightsResult | undefined;
		for (let attempt = 0; attempt < 2; attempt++) {
			const result = await fetchIntelligenceJson<ProviderInsightsResult>(stub, url.toString());
			if (result.kind === 'ok') {
				providerData = result.data;
				break;
			}
			if (result.kind === 'upstream_error') {
				return { status: 'unavailable', provider, profile, reason: 'upstream_error', retryable: true };
			}
			if (attempt === 1) return { status: 'unavailable', provider, profile, reason: 'timeout', retryable: true };
		}

		if (!providerData) {
			return { status: 'unavailable', provider, profile, reason: 'upstream_error', retryable: true };
		}

		return providerData;
	} catch {
		// Shard resolution / JSON parse failed rather than the fetch.
		return { status: 'unavailable', provider, profile, reason: 'upstream_error', retryable: true };
	}
}

/**
 * Compute the percentile rank for a given score within a benchmark.
 * Returns null if benchmark data is insufficient.
 */
export function computePercentileRank(score: number, benchmark: BenchmarkResult): number | null {
	if (benchmark.status !== 'ok' || !benchmark.percentiles || !benchmark.totalScans) {
		return null;
	}

	const bucket = Math.min(90, Math.floor(score / 10) * 10);

	// Find the percentile for the bucket below this score
	const prevBucket = bucket - 10;
	if (prevBucket < 0) return 0;

	const prevLabel = `${prevBucket}-${prevBucket + 9}`;
	return benchmark.percentiles[prevLabel] ?? 0;
}

/** Format benchmark data as human-readable text. */
export function formatBenchmark(result: BenchmarkResult, format: OutputFormat = 'full'): string {
	const lines: string[] = [];

	if (format === 'compact') {
		if (result.status === 'unavailable') {
			return `Benchmark: ${result.profile} — unavailable`;
		}
		if (result.status === 'insufficient_data') {
			return `Benchmark: ${result.profile} — insufficient data (${result.totalScans ?? 0} scans)`;
		}
		lines.push(
			`Benchmark: ${result.profile} — ${result.totalScans} scans, mean ${result.meanScore}/100, median ${result.medianBucket}-${(result.medianBucket ?? 0) + 9}`,
		);
		if (result.topFailingCategories && result.topFailingCategories.length > 0) {
			lines.push(`Top failures: ${result.topFailingCategories.map((c) => c.toUpperCase()).join(', ')}`);
		}
		if (result.trends && result.trends.snapshotCount > 0 && result.trends.snapshots.length >= 2) {
			const first = result.trends.snapshots[0];
			const last = result.trends.snapshots[result.trends.snapshots.length - 1];
			const delta = Math.round((last.avgScore - first.avgScore) * 10) / 10;
			const dir = delta > 0 ? `↑ +${delta}` : delta < 0 ? `↓ ${delta}` : '→ stable';
			lines.push(`Trend: ${dir} pts over 7d`);
		}
		return lines.join('\n');
	}

	lines.push(`# Benchmark: ${result.profile}`);

	if (result.status === 'unavailable') {
		lines.push('Benchmark data is currently unavailable. The intelligence layer requires the ProfileAccumulator Durable Object binding.');
		return lines.join('\n');
	}

	if (result.status === 'insufficient_data') {
		lines.push(
			`Insufficient data for meaningful benchmarks (${result.totalScans ?? 0} scans, minimum ${result.minimumRequired ?? 100} required).`,
		);
		if (result.baselineFailureRates) {
			lines.push('');
			lines.push('Baseline failure rates (industry estimates):');
			for (const [cat, rate] of Object.entries(result.baselineFailureRates)) {
				lines.push(`  ${cat.toUpperCase()}: ${Math.round(rate * 100)}%`);
			}
		}
		return lines.join('\n');
	}

	lines.push(`Total scans: ${result.totalScans}`);
	lines.push(`Mean score: ${result.meanScore}/100`);
	lines.push(`Median bucket: ${result.medianBucket}-${(result.medianBucket ?? 0) + 9}`);
	lines.push('');

	if (result.distribution) {
		lines.push('Score distribution:');
		for (const [range, pct] of Object.entries(result.distribution)) {
			const bar = '█'.repeat(Math.round(pct / 2));
			lines.push(`  ${range.padEnd(6)} ${bar} ${pct}%`);
		}
		lines.push('');
	}

	if (result.topFailingCategories && result.topFailingCategories.length > 0) {
		lines.push(`Top failing categories: ${result.topFailingCategories.map((c) => c.toUpperCase()).join(', ')}`);
	}

	if (result.trends && result.trends.snapshotCount > 0) {
		lines.push('');
		lines.push(`7-day trend: ${result.trends.totalScans} scans, avg score ${result.trends.periodAvgScore}/100`);
		if (result.trends.snapshots.length >= 2) {
			const first = result.trends.snapshots[0];
			const last = result.trends.snapshots[result.trends.snapshots.length - 1];
			const delta = Math.round((last.avgScore - first.avgScore) * 10) / 10;
			if (delta > 0) {
				lines.push(`  Trend: ↑ improving (+${delta} points over period)`);
			} else if (delta < 0) {
				lines.push(`  Trend: ↓ declining (${delta} points over period)`);
			} else {
				lines.push('  Trend: → stable');
			}
		}
	}

	if (result.dataFreshness) {
		lines.push(`Data freshness: ${result.dataFreshness}`);
	}

	return lines.join('\n');
}

/** Format provider insights as human-readable text. */
export function formatProviderInsights(result: ProviderInsightsResult, format: OutputFormat = 'full'): string {
	if (format === 'compact') {
		if (result.status === 'unavailable') return `Provider: ${result.provider} — unavailable`;
		if (result.status === 'no_data') return `Provider: ${result.provider} — no data`;
		const parts = [`Provider: ${result.provider} (${result.profile}) — ${result.emaOverallScore}/100, ${result.totalScans} scans`];
		if (result.percentileRank !== null && result.percentileRank !== undefined) {
			parts[0] += `, ${result.percentileRank}th pctl`;
		}
		if (result.topFailingCategories && result.topFailingCategories.length > 0) {
			parts.push(`Issues: ${result.topFailingCategories.map((c) => c.toUpperCase()).join(', ')}`);
		}
		return parts.join('\n');
	}

	const lines: string[] = [];

	lines.push(`# Provider Insights: ${result.provider}`);

	if (result.status === 'unavailable') {
		lines.push('Provider insights are currently unavailable.');
		return lines.join('\n');
	}

	if (result.status === 'no_data') {
		lines.push(`No data available for provider "${result.provider}" in profile "${result.profile}".`);
		return lines.join('\n');
	}

	lines.push(`Profile: ${result.profile}`);
	lines.push(`Total scans: ${result.totalScans}`);
	lines.push(`Average score (EMA): ${result.emaOverallScore}/100`);

	if (result.populationMeanScore !== null && result.populationMeanScore !== undefined) {
		const diff = (result.emaOverallScore ?? 0) - result.populationMeanScore;
		const direction = diff > 0 ? 'above' : diff < 0 ? 'below' : 'at';
		lines.push(`Population mean: ${result.populationMeanScore}/100 (${Math.abs(Math.round(diff))} points ${direction} average)`);
	}

	if (result.percentileRank !== null && result.percentileRank !== undefined) {
		lines.push(`Percentile rank: ${result.percentileRank}th`);
	}

	if (result.topFailingCategories && result.topFailingCategories.length > 0) {
		lines.push(`Common issues: ${result.topFailingCategories.map((c) => c.toUpperCase()).join(', ')}`);
	}

	if (result.dataFreshness) {
		lines.push(`Data freshness: ${result.dataFreshness}`);
	}

	return lines.join('\n');
}
