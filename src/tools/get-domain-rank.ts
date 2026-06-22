// SPDX-License-Identifier: BUSL-1.1

/**
 * get_domain_rank — per-domain "rank vs cohort" tool.
 *
 * Calls bv-web's C1 internal benchmark endpoint
 * (`POST /api/internal/mcp/benchmark`) with the domain's score and optional
 * country/sector to retrieve a cohort percentile: "ranks better than X% of
 * <cohort>".
 *
 * Key design decisions (per brief + contracts-frozen.md):
 * - NOT a rename of get_benchmark (that's corpus-wide profile stats).
 * - Owner-gate EXEMPT — returns public-grade cohort data only.
 * - NOT in AGENT_ALLOWED_TOOLS (keep exactly 13).
 * - Fail-soft: missing/unreachable C1 → representative response, never throws.
 * - asOf can be null even on a 200 — callers must null-check.
 * - sector forwarded to C1 but ignored by C1 until D3.
 */

import type { OutputFormat } from '../handlers/tool-args';

/** C1 response shape per contracts-frozen.md. */
export interface C1BenchmarkResponse {
	percentile: number;
	cohort: string;
	cohortSize: number;
	asOf: string | null;
	representative: boolean;
	scaleId: 'nist' | 'benchmark' | 'headers';
}

/** Result shape returned by getDomainRank. */
export interface DomainRankResult {
	/** 'ok' = real data from C1; 'representative' = illustrative; 'unavailable' = C1 unreachable */
	status: 'ok' | 'representative' | 'unavailable';
	domain: string;
	score: number;
	/** 0–100: "scores better than X% of <cohort>". Illustrative when representative=true. */
	percentile: number;
	/** ISO country code, sector, or 'global'. */
	cohort: string;
	/** Number of domains in the cohort. 0 when representative. */
	cohortSize: number;
	/** GSI snapshot date; null when representative or when C1 omits it. */
	asOf: string | null;
	/** true => illustrative result (C1 unbound / no cohort cells / fallback). */
	representative: boolean;
	/** Grade scale ID. Always 'benchmark' from C1. */
	scaleId: string;
}

const BENCHMARK_BASE_URL = 'https://bv-web-internal/api/internal/mcp/benchmark';
const TIMEOUT_MS = 8_000;

/** Representative fallback — returned whenever C1 is unreachable. */
function representativeFallback(domain: string, score: number, status: 'unavailable' | 'representative' = 'unavailable'): DomainRankResult {
	// Illustrative percentile derived from score (mirrors what C1 would return for
	// global cohort): treat score as approximately its own percentile as a rough
	// proxy until real data is available.
	const illustrativePercentile = Math.max(0, Math.min(99, Math.round(score)));
	return {
		status,
		domain,
		score,
		percentile: illustrativePercentile,
		cohort: 'global',
		cohortSize: 0,
		asOf: null,
		representative: true,
		scaleId: 'benchmark',
	};
}

/**
 * Fetch the domain's cohort percentile from bv-web's C1 benchmark endpoint.
 *
 * @param domain     - The domain whose rank is requested.
 * @param score      - The domain's current score (0–100), e.g. from scan_domain.
 * @param args       - Optional country (ISO-3166-2) and sector to narrow cohort.
 * @param bvWeb      - The BV_WEB service binding (or a compatible Fetcher). Absent → fail-soft.
 * @param opts       - Auth options. authToken = BV_WEB_INTERNAL_KEY.
 */
export async function getDomainRank(
	domain: string,
	score: number,
	args: { country?: string; sector?: string },
	bvWeb: { fetch: typeof fetch } | undefined,
	opts: { authToken?: string },
): Promise<DomainRankResult> {
	if (!bvWeb) {
		return representativeFallback(domain, score);
	}

	try {
		const headers: Record<string, string> = { 'Content-Type': 'application/json' };
		if (opts.authToken) {
			headers['Authorization'] = `Bearer ${opts.authToken}`;
		}

		const body: Record<string, unknown> = { domain, score };
		if (args.country) body.country = args.country;
		if (args.sector) body.sector = args.sector;

		const response = await Promise.race([
			bvWeb.fetch(BENCHMARK_BASE_URL, {
				method: 'POST',
				headers,
				body: JSON.stringify(body),
			}),
			new Promise<never>((_, reject) =>
				setTimeout(() => reject(new Error('C1 timeout')), TIMEOUT_MS),
			),
		]);

		if (!response.ok) {
			// Consume body to avoid leaking the connection.
			await response.text().catch(() => undefined);
			return representativeFallback(domain, score);
		}

		const data = (await response.json()) as C1BenchmarkResponse;

		const status = data.representative ? 'representative' : 'ok';
		return {
			status,
			domain,
			score,
			percentile: data.percentile,
			cohort: data.cohort,
			cohortSize: data.cohortSize,
			asOf: data.asOf ?? null, // explicit null-guard per C1 contract note
			representative: data.representative,
			scaleId: data.scaleId,
		};
	} catch {
		// Network error, timeout, JSON parse failure — all fail-soft.
		return representativeFallback(domain, score);
	}
}

/**
 * Format a DomainRankResult as human-readable text.
 */
export function formatDomainRank(result: DomainRankResult, format: OutputFormat = 'full'): string {
	const { domain, score, percentile, cohort, cohortSize, asOf, representative, status } = result;

	if (status === 'unavailable') {
		if (format === 'compact') {
			return `Rank: ${domain} — benchmark unavailable`;
		}
		return [
			`# Domain Rank: ${domain}`,
			'',
			'Benchmark data is currently unavailable. The C1 endpoint (bv-web benchmark) is unreachable.',
			'Ensure BV_WEB is bound and BV_WEB_INTERNAL_KEY is configured.',
		].join('\n');
	}

	const representativeNote = representative ? ' (illustrative — no real cohort data)' : '';
	const cohortLabel = cohortSize > 0 ? `${cohort} (n=${cohortSize.toLocaleString()})` : cohort;
	const asOfLabel = asOf ? ` as of ${asOf}` : '';

	if (format === 'compact') {
		return `Rank: ${domain} scores ${score}/100 — better than ${percentile}% of ${cohortLabel}${asOfLabel}${representativeNote}`;
	}

	const lines: string[] = [
		`# Domain Rank: ${domain}`,
		'',
		`Score: ${score}/100`,
		`Cohort: ${cohortLabel}${asOfLabel}`,
		`Percentile: ranks better than ${percentile}% of peers in this cohort`,
	];

	if (representative) {
		lines.push('');
		lines.push('Note: This is an illustrative result — the benchmark cohort has no real data for this combination yet.');
	}

	return lines.join('\n');
}
