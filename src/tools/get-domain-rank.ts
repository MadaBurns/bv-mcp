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
 * - `percentile` can be null even on a 200 (no/undersized cohort) — a percentile is
 *   reported ONLY when it was computed against real peers. See its field doc.
 * - sector forwarded to C1 but ignored by C1 until D3.
 */

import type { OutputFormat } from '../handlers/tool-args';
import { UNGRADED_DISPLAY } from '../lib/ungraded-display';

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
	/**
	 * 0–100: "scores better than X% of <cohort>", or `null` when NO usable cohort
	 * existed to rank against.
	 *
	 * `null` means "not ranked" — it is NOT a zero and it is NOT a midpoint.
	 * Consumers must exclude it from comparison, ranking and reporting; in JS
	 * `null < n` is `true` and `null - n` is `NaN`, so coercing it inverts exactly
	 * the decisions that matter. Narrow on `percentile !== null`, or read
	 * `evidenceInsufficient`.
	 *
	 * This field used to carry a fabricated number in the no-cohort case (a
	 * score-derived proxy from the local fallback, and whatever C1 returned
	 * alongside `cohortSize: 0` on the wire — in production that was a flat `50`).
	 * A consumer that dropped the `representative` flag then rendered "ranks
	 * better than 50% of peers" for a cohort of ZERO domains. Abstaining is the
	 * same rule the rest of the product follows for unmeasured things
	 * (`ScanScore.overall`, `map_compliance`'s `assessed: false`).
	 */
	percentile: number | null;
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
	/**
	 * `true` when no percentile could be computed from real cohort data, so
	 * `percentile` is `null`. Always present, so a consumer never has to infer the
	 * state from a missing field — and, unlike `representative`, it states the
	 * consequence rather than the provenance.
	 */
	evidenceInsufficient: boolean;
	/** Human-readable reason, present whenever `evidenceInsufficient` is `true`. Safe to render verbatim. */
	evidenceNote?: string;
}

const BENCHMARK_BASE_URL = 'https://bv-web-internal/api/internal/mcp/benchmark';
const TIMEOUT_MS = 8_000;

/**
 * Smallest cohort a percentile may be quoted from.
 *
 * Below this a single domain moves the reported percentile by ≥20 points, so the
 * number carries no information about where the domain actually stands — it is a
 * restatement of the cohort's own tiny membership. `0` is the case seen in
 * production (`cohortSize: 0` with a flat `percentile: 50`); the threshold
 * generalises it rather than special-casing the one value that was caught.
 */
export const MIN_MEANINGFUL_COHORT_SIZE = 5;

/** Reason text for each abstention path — one spelling per cause. */
const NO_COHORT_NOTE = 'No benchmark cohort data was available for this domain, so no percentile was computed.';
const SMALL_COHORT_NOTE = `The benchmark cohort holds fewer than ${MIN_MEANINGFUL_COHORT_SIZE} domains, which is too few to quote a percentile from.`;
const ILLUSTRATIVE_NOTE = 'The benchmark returned an illustrative (non-cohort) result, so no percentile was computed.';

/**
 * Why this result may not quote a percentile — `null` when it may.
 *
 * The ONE place the abstention rule is spelled, so the local fallback and the C1
 * response path cannot drift apart on what counts as a rankable cohort.
 */
function percentileAbstentionReason(representative: boolean, cohortSize: number, percentile: unknown): string | null {
	if (typeof percentile !== 'number' || !Number.isFinite(percentile)) return NO_COHORT_NOTE;
	if (representative) return ILLUSTRATIVE_NOTE;
	if (cohortSize <= 0) return NO_COHORT_NOTE;
	if (cohortSize < MIN_MEANINGFUL_COHORT_SIZE) return SMALL_COHORT_NOTE;
	return null;
}

/**
 * Representative fallback — returned whenever C1 is unreachable.
 *
 * Deliberately carries NO percentile. The previous implementation derived an
 * "illustrative" percentile from the domain's own score, which is a statistic
 * about nothing: it was computed without consulting a single peer domain.
 */
function representativeFallback(domain: string, score: number, status: 'unavailable' | 'representative' = 'unavailable'): DomainRankResult {
	return {
		status,
		domain,
		score,
		percentile: null,
		cohort: 'global',
		cohortSize: 0,
		asOf: null,
		representative: true,
		scaleId: 'benchmark',
		evidenceInsufficient: true,
		evidenceNote: NO_COHORT_NOTE,
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

		const fetchPromise = bvWeb.fetch(BENCHMARK_BASE_URL, {
			method: 'POST',
			headers,
			body: JSON.stringify(body),
		});
		let response: Response;
		try {
			response = await Promise.race([
				fetchPromise,
				new Promise<never>((_, reject) => setTimeout(() => reject(new Error('C1 timeout')), TIMEOUT_MS)),
			]);
		} catch (err) {
			// Timeout won the race: fetchPromise's eventual Response would otherwise
			// go undrained, which is what the platform's "stalled HTTP response ...
			// canceled to prevent deadlock" warning flags. Harmless no-op if
			// fetchPromise itself was what rejected (nothing to drain).
			fetchPromise.then((r) => void r.body?.cancel()).catch(() => undefined);
			throw err;
		}

		if (!response.ok) {
			// Consume body to avoid leaking the connection.
			await response.text().catch(() => undefined);
			return representativeFallback(domain, score);
		}

		const data = (await response.json()) as C1BenchmarkResponse;

		const status = data.representative ? 'representative' : 'ok';
		const cohortSize = Number.isFinite(data.cohortSize) ? Math.max(0, Math.trunc(data.cohortSize)) : 0;

		// A percentile is reportable only when it was actually computed against a
		// cohort. C1 returns a number in every case — including `representative: true`
		// with `cohortSize: 0`, which is the shape production served for github.com
		// (`"percentile": 50, "cohortSize": 0`). Passing that number through, even
		// flagged, is a fabricated statistic the moment a consumer reads the field
		// on its own.
		const abstention = percentileAbstentionReason(data.representative, cohortSize, data.percentile);

		return {
			status,
			domain,
			score,
			percentile: abstention === null ? data.percentile : null,
			cohort: data.cohort,
			cohortSize,
			asOf: data.asOf ?? null, // explicit null-guard per C1 contract note
			representative: data.representative,
			scaleId: data.scaleId,
			evidenceInsufficient: abstention !== null,
			...(abstention === null ? {} : { evidenceNote: abstention }),
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
	const cohortLabel = cohortSize > 0 ? `${cohort} (n=${cohortSize.toLocaleString()})` : `${cohort} (n=0)`;
	const asOfLabel = asOf ? ` as of ${asOf}` : '';
	const note = result.evidenceNote ?? NO_COHORT_NOTE;

	// The prose is the other half of the same result: a payload that abstains while
	// the text still reads "better than 50% of peers" leaves the fabricated claim
	// exactly where a customer sees it.
	if (percentile === null) {
		if (format === 'compact') {
			return `Rank: ${domain} scores ${score}/100 — percentile ${UNGRADED_DISPLAY} (${cohortLabel})${asOfLabel}`;
		}
		return [
			`# Domain Rank: ${domain}`,
			'',
			`Score: ${score}/100`,
			`Cohort: ${cohortLabel}${asOfLabel}`,
			`Percentile: ${UNGRADED_DISPLAY}`,
			'',
			`Note: ${note}`,
		].join('\n');
	}

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

	return lines.join('\n');
}
