// SPDX-License-Identifier: BUSL-1.1

/**
 * Intelligence layer tools — expose anonymized aggregate insights
 * from the ProfileAccumulator Durable Object.
 *
 * These tools query pre-computed aggregates (histograms, cohort summaries,
 * trends) and never access per-domain data. Fail-open: returns a graceful
 * "unavailable" response when the DO binding is absent or unresponsive.
 */

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

/** Benchmark response from the DO. */
export interface BenchmarkResult {
	status: 'ok' | 'insufficient_data' | 'unavailable';
	profile: string;
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
	totalScans?: number;
	emaOverallScore?: number;
	topFailingCategories?: string[];
	populationMeanScore?: number | null;
	percentileRank?: number | null;
	dataFreshness?: string;
}

/** Timeout for DO queries (ms). */
const INTELLIGENCE_FETCH_TIMEOUT_MS = 500;

/**
 * Fetch benchmark data from the ProfileAccumulator DO.
 *
 * @param accumulator - ProfileAccumulator DO namespace binding
 * @param profile - Scoring profile to query (default: 'mail_enabled')
 * @returns Benchmark data or unavailable response
 */
export async function getBenchmark(
	accumulator: DurableObjectNamespace | undefined,
	profile: string = 'mail_enabled',
): Promise<BenchmarkResult> {
	if (!accumulator) {
		return { status: 'unavailable', profile };
	}

	try {
		const stub = accumulator.get(accumulator.idFromName('global'));
		const url = new URL('https://do/benchmark');
		url.searchParams.set('profile', profile);

		const response = await Promise.race([
			stub.fetch(url.toString(), { method: 'GET' }),
			new Promise<never>((_, reject) =>
				setTimeout(() => reject(new Error('timeout')), INTELLIGENCE_FETCH_TIMEOUT_MS),
			),
		]);

		if (!response.ok) {
			return { status: 'unavailable', profile };
		}

		const benchmarkData = await response.json() as BenchmarkResult;

		// If benchmark data is available, also fetch trend data (best-effort)
		if (benchmarkData.status === 'ok') {
			try {
				const trendUrl = new URL('https://do/trends');
				trendUrl.searchParams.set('profile', profile);
				trendUrl.searchParams.set('hours', '168'); // 7 days

				const trendResponse = await Promise.race([
					stub.fetch(trendUrl.toString(), { method: 'GET' }),
					new Promise<never>((_, reject) =>
						setTimeout(() => reject(new Error('timeout')), INTELLIGENCE_FETCH_TIMEOUT_MS),
					),
				]);

				if (trendResponse.ok) {
					const trendData = await trendResponse.json() as { status: string; snapshots?: TrendSnapshot[] } & TrendSummary;
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
		return { status: 'unavailable', profile };
	}
}

/**
 * Fetch provider insights from the ProfileAccumulator DO.
 *
 * @param accumulator - ProfileAccumulator DO namespace binding
 * @param provider - Email provider name to query
 * @param profile - Scoring profile (default: 'mail_enabled')
 * @returns Provider cohort data or unavailable response
 */
export async function getProviderInsights(
	accumulator: DurableObjectNamespace | undefined,
	provider: string,
	profile: string = 'mail_enabled',
): Promise<ProviderInsightsResult> {
	if (!accumulator) {
		return { status: 'unavailable', provider, profile };
	}

	try {
		const stub = accumulator.get(accumulator.idFromName('global'));
		const url = new URL('https://do/provider-insights');
		url.searchParams.set('provider', provider);
		url.searchParams.set('profile', profile);

		const response = await Promise.race([
			stub.fetch(url.toString(), { method: 'GET' }),
			new Promise<never>((_, reject) =>
				setTimeout(() => reject(new Error('timeout')), INTELLIGENCE_FETCH_TIMEOUT_MS),
			),
		]);

		if (!response.ok) {
			return { status: 'unavailable', provider, profile };
		}

		return await response.json() as ProviderInsightsResult;
	} catch {
		return { status: 'unavailable', provider, profile };
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
export function formatBenchmark(result: BenchmarkResult): string {
	const lines: string[] = [];

	lines.push(`# Benchmark: ${result.profile}`);

	if (result.status === 'unavailable') {
		lines.push('Benchmark data is currently unavailable. The intelligence layer requires the ProfileAccumulator Durable Object binding.');
		return lines.join('\n');
	}

	if (result.status === 'insufficient_data') {
		lines.push(`Insufficient data for meaningful benchmarks (${result.totalScans ?? 0} scans, minimum ${result.minimumRequired ?? 100} required).`);
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
export function formatProviderInsights(result: ProviderInsightsResult): string {
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
