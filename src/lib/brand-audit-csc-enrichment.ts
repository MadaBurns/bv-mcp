// SPDX-License-Identifier: BUSL-1.1

/**
 * Per-candidate MX + HTTP enrichment to feed the defensive-registration heuristic.
 *
 * For each top-N candidate (ranked by combinedConfidence, capped at MAX_ENRICH_CANDIDATES),
 * fetches in parallel:
 *   - MX records via Google DoH (safe — Google's DoH endpoint is public)
 *   - HTTP HEAD via safeFetch (manual redirect; safe-fetch enforces SSRF guards
 *     because the candidate's hostname is attacker-controllable through the
 *     discovery pipeline).
 *
 * Stamps { defensive, defensiveReason } onto each candidate based on
 * evaluateDefensiveRegistration's signal-based decision.
 *
 * Note on result mapping: evaluateDefensiveRegistration returns { defensive, reason? }
 * but the enrichment output interface uses { defensive, defensiveReason? } for
 * consistency with downstream consumers. The mapping is: reason → defensiveReason.
 *
 * Honest failure handling:
 *   - Total budget exceeded → enrichmentStatus='partial'
 *   - Any candidate's MX or HTTP fetch fails → that candidate is unenriched
 *     (no stamp), reflected in overall status.
 *
 * Worker-runtime safe — uses only Web APIs (fetch, AbortController, Headers).
 */

import { safeFetch } from './safe-fetch';
import { evaluateDefensiveRegistration, type DefensiveReason } from './brand-defensive-registration';

const MAX_ENRICH_CANDIDATES = 50;
const DEFAULT_BUDGET_MS = 8_000;
const PER_CANDIDATE_TIMEOUT_MS = 3_000;
const DOH_ENDPOINT = 'https://dns.google/resolve';

export interface EnrichInputCandidate {
	domain: string;
	combinedConfidence: number | null;
}

export interface EnrichOutputCandidate extends EnrichInputCandidate {
	defensive?: boolean;
	/** Maps from evaluateDefensiveRegistration's `reason` field. */
	defensiveReason?: DefensiveReason;
	mxRecords?: string[];
	httpRedirectLocation?: string | null;
}

export interface EnrichResult {
	candidates: EnrichOutputCandidate[];
	enrichmentStatus: 'ready' | 'partial';
}

export interface EnrichOptions {
	target: string;
	candidates: ReadonlyArray<EnrichInputCandidate>;
	budgetMs?: number;
	/** Per-candidate NS hostnames, keyed by domain. Used by evaluateDefensiveRegistration's parked-ns signal. */
	nsHosts?: Record<string, string[]>;
}

/**
 * Fetch MX records for a domain via Google DoH.
 *
 * Returns the MX hostname list on success (may be empty), or `null` when
 * the fetch fails or is aborted.
 */
async function fetchMx(domain: string, signal: AbortSignal): Promise<string[] | null> {
	try {
		const res = await fetch(`${DOH_ENDPOINT}?name=${encodeURIComponent(domain)}&type=MX`, {
			signal,
			headers: { Accept: 'application/dns-json' },
		});
		if (!res.ok) return null;
		const body = (await res.json()) as { Answer?: Array<{ data: string }> };
		if (!body.Answer) return [];
		// MX data format: "<priority> <hostname>" — extract hostname only, strip trailing dot.
		return body.Answer.map((a) => a.data.split(/\s+/).slice(-1)[0]!.replace(/\.$/, ''));
	} catch {
		return null;
	}
}

/**
 * Perform an HTTP HEAD of a candidate's root URL and return the `Location`
 * header value if the response is a redirect (3xx), `null` if the response
 * is non-redirect, or `undefined` if the fetch fails or is aborted.
 *
 * `undefined` is the "fetch failed — abstain" sentinel; `null` is "we looked,
 * no redirect." This distinction matters downstream: evaluateDefensiveRegistration
 * receives `httpRedirectLocation: undefined` → abstain, `null` → not a redirect.
 *
 * Uses safeFetch because the candidate hostname is attacker-controllable.
 */
async function fetchHttpRedirect(domain: string, signal: AbortSignal): Promise<string | null | undefined> {
	try {
		const res = await safeFetch(`https://${domain}/`, {
			method: 'HEAD',
			redirect: 'manual',
			signal,
		});
		if (res.status >= 300 && res.status < 400) {
			return res.headers.get('Location');
		}
		return null;
	} catch {
		return undefined;
	}
}

/**
 * Enrich up to MAX_ENRICH_CANDIDATES top candidates with MX records and HTTP
 * redirect signals, then annotate each with { defensive, defensiveReason }
 * based on evaluateDefensiveRegistration.
 *
 * Candidates are ranked descending by `combinedConfidence` before slicing so
 * we always enrich the most-likely candidates within the budget.
 */
export async function enrichCandidatesForDefensiveDetection(opts: EnrichOptions): Promise<EnrichResult> {
	const budget = opts.budgetMs ?? DEFAULT_BUDGET_MS;

	const ranked = [...opts.candidates]
		.sort((a, b) => (b.combinedConfidence ?? 0) - (a.combinedConfidence ?? 0))
		.slice(0, MAX_ENRICH_CANDIDATES);

	const globalController = new AbortController();
	const budgetTimer = setTimeout(() => globalController.abort(), budget);

	let anyFailed = false;

	const enriched: EnrichOutputCandidate[] = await Promise.all(
		ranked.map(async (candidate): Promise<EnrichOutputCandidate> => {
			// Each candidate gets its own controller so per-candidate timeouts don't
			// cancel the entire batch, and so the global budget abort propagates down.
			const perCandidateController = new AbortController();
			const onGlobalAbort = (): void => perCandidateController.abort();
			globalController.signal.addEventListener('abort', onGlobalAbort);
			const perTimer = setTimeout(() => perCandidateController.abort(), PER_CANDIDATE_TIMEOUT_MS);

			try {
				const [mxRecords, httpRedirectLocation] = await Promise.all([
					fetchMx(candidate.domain, perCandidateController.signal),
					fetchHttpRedirect(candidate.domain, perCandidateController.signal),
				]);

				// `null` from fetchMx means "fetch failed" — abstain rather than misfire.
				// `undefined` from fetchHttpRedirect means "fetch failed" — abstain.
				if (mxRecords === null || httpRedirectLocation === undefined) {
					anyFailed = true;
					return { ...candidate };
				}

				const evaluation = evaluateDefensiveRegistration({
					candidateDomain: candidate.domain,
					targetDomain: opts.target,
					mxRecords,
					// Narrow null → undefined so TS sees `string | undefined` matching the input type.
					httpRedirectLocation: httpRedirectLocation ?? undefined,
					nsHosts: opts.nsHosts?.[candidate.domain],
				});

				return {
					...candidate,
					mxRecords,
					httpRedirectLocation,
					defensive: evaluation.defensive,
					// Map evaluateDefensiveRegistration's `reason` to our output field `defensiveReason`.
					...(evaluation.reason ? { defensiveReason: evaluation.reason } : {}),
				};
			} catch {
				anyFailed = true;
				return { ...candidate };
			} finally {
				clearTimeout(perTimer);
				globalController.signal.removeEventListener('abort', onGlobalAbort);
			}
		}),
	);

	clearTimeout(budgetTimer);

	const status: EnrichResult['enrichmentStatus'] = anyFailed ? 'partial' : 'ready';
	return { candidates: enriched, enrichmentStatus: status };
}
