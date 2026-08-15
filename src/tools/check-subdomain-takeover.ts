// SPDX-License-Identifier: BUSL-1.1

/**
 * Subdomain Takeover / Dangling CNAME Detection Tool.
 * Thin wrapper around @blackveil/dns-checks — delegates all logic to the shared package.
 *
 * Post-augments the package result with fetch-budget awareness (issue #674). The
 * package's HTTP fingerprint probe SWALLOWS every transport failure by design — a
 * timeout is not deprovision evidence — so a probe cut short by the per-check fetch
 * budget would silently collapse into the package's clean verdict, "No dangling CNAME
 * records found" (an `info` finding, category → 100, passed). That verdict is a claim
 * of fact about a subdomain we did not finish looking at, which is exactly the
 * "slow became absent" failure the budget must not introduce. When a probe was cut and
 * nothing else was found, the category is EXCLUDED instead (`checkStatus: 'error'` plus
 * an `inconclusive` finding — never `missingControl`).
 */

import { checkSubdomainTakeover as checkSubdomainTakeoverPkg, withRobotsGate } from '@blackveil/dns-checks';
import type { FetchFunction } from '@blackveil/dns-checks';
import { makeQueryDNS } from '../lib/dns-query-adapter';
import type { QueryDnsOptions } from '../lib/dns-types';
import type { CheckResult } from '../lib/scoring';
import { buildCheckResult, createFinding } from '../lib/scoring';
import { HTTPS_TIMEOUT_MS } from '../lib/config';
import { createFetchBudget, type FetchBudget } from '../lib/fetch-budget';

export interface SubdomainTakeoverWrapperOptions {
	/**
	 * Optional explicit subdomain list — passed through to the shared-package
	 * sweeper. When provided, this list (deduped, capped at 1000) is swept
	 * instead of the built-in 15-name KNOWN_SUBDOMAINS. Caller is expected to
	 * source these from a real enumeration (CT logs, brand-audit discovery,
	 * etc.).
	 */
	subdomains?: readonly string[];
	/**
	 * Wall-clock this check's fetches may collectively spend (issue #674).
	 *
	 * The sweep is DNS-first, but each CNAME that points at a known takeover service
	 * and still resolves costs a further `https://<fqdn>` fingerprint probe carrying the
	 * package's own fixed 4s timeout — issued AFTER two sequential DNS lookups and behind
	 * a robots.txt gate worth up to another 3s on a host nothing else in the scan visits.
	 * Those sum past `scan_domain`'s 8s per-check budget, and when they do `safeCheck`
	 * discards the DNS-derived dangling-CNAME findings that had already been produced —
	 * the ones that carry this category's whole score.
	 *
	 * With a budget the probe is bounded by what the earlier legs left, so the check
	 * returns and reports its dangling CNAMEs. The cost is a fingerprint it could not
	 * confirm, which is recorded rather than silently absorbed — see the module note.
	 *
	 * Absent (every direct `check_subdomain_takeover` call) → unchanged behaviour.
	 */
	budgetMs?: number;
}

/** True for the robots.txt fetch the gate issues itself, as opposed to a fingerprint probe. */
function isRobotsFetch(url: string): boolean {
	return url.endsWith('/robots.txt');
}

/**
 * The gated fetch handed to the package, plus the flag recording whether a
 * fingerprint probe was cut short by the budget.
 *
 * No budget → literally the expression that shipped before #674, so every direct call
 * and every BSL self-host is unchanged and `cut` can never be set.
 *
 * Budgeted → gate OUTSIDE, observation in the middle, budget INNERMOST: the gate's own
 * `https://<fqdn>/robots.txt` fetch delegates down through the wrapped fetch and is
 * therefore metered too (hoisting the budget outside the gate would leave the 3s leg
 * unbounded — the specific mistake #641 called out on the sibling checks).
 */
function resolveProbeFetch(budget: FetchBudget, budgeted: boolean): { fetchFn: FetchFunction; wasCut: () => boolean } {
	if (!budgeted) return { fetchFn: withRobotsGate(fetch), wasCut: () => false };

	let cut = false;
	const budgetedFetch = budget.wrap((url: string, init?: RequestInit) => fetch(url, init));
	const observingFetch: FetchFunction = async (url, init) => {
		try {
			return await budgetedFetch(url, init);
		} catch (err) {
			// Attribute the failure to the budget by reading the budget's own state rather
			// than the error: `wrap` rejects with a plain `Error` when the deadline has already
			// passed and with an `AbortError` when it passes mid-flight, and the sentinel message
			// is deliberately not exported. `canIssueRequest()` is the same predicate `wrap`
			// applies, so the two can never disagree about where the line sits.
			//
			// Conservative in the right direction: a genuine network error that happens to land
			// with the budget spent is recorded as a cut probe (we exclude rather than claim
			// clean), while a failure with budget remaining is left exactly as the package has
			// always treated it — silent, because a plain timeout is not deprovision evidence.
			if (!isRobotsFetch(url) && !budget.canIssueRequest()) cut = true;
			throw err;
		}
	};
	return { fetchFn: withRobotsGate(observingFetch), wasCut: () => cut };
}

/**
 * A fingerprint probe was cut short. Record the gap honestly.
 *
 * Two outcomes, because they are two different claims:
 *  - Evidence survived (a dangling CNAME is DNS-derived and untouched by a cut HTTP
 *    probe): keep the result and its score, and append a NON-SCORING `info` note. An
 *    `info` finding carries a 0 penalty, so this can never move a grade.
 *  - Nothing was found: the package's clean verdict would assert an absence drawn from a
 *    measurement that never completed. Exclude the category instead — `checkStatus:
 *    'error'` is what excludes it; the finding carries `inconclusive` + `errorKind` and
 *    deliberately NOT `missingControl`, the contradiction pinned by
 *    test/audits/measured-vs-unmeasured-metadata.audit.test.ts.
 */
function markProbeInconclusive(result: CheckResult, domain: string): CheckResult {
	const note = createFinding(
		'subdomain_takeover',
		'Takeover fingerprint probe did not complete',
		'info',
		`At least one HTTP fingerprint probe for ${domain} was cut short by this check's time budget, so the CNAME target it addressed was verified as neither deprovisioned nor healthy. ` +
			`Re-run check_subdomain_takeover directly (no scan-level per-check budget) to complete the probe.`,
		{ inconclusive: true, errorKind: 'timeout' },
	);

	// Any non-`info` finding is real, measured evidence (the package only emits
	// medium/high for dangling or fingerprinted CNAMEs), so the result stands.
	if (result.findings.some((f) => f.severity !== 'info')) {
		return { ...result, findings: [...result.findings, note] };
	}

	// All-`info` means the sweep found nothing, i.e. the only finding is the package's
	// clean "No dangling CNAME records found". Dropping it is the point: keeping it would
	// re-assert the very claim the cut probe cannot support.
	return { ...buildCheckResult('subdomain_takeover', [note]), score: 0, passed: false, checkStatus: 'error' };
}

/**
 * Check for dangling CNAME records and provider-deprovisioned takeover
 * fingerprints. Default surface: 15 hardcoded "known" subdomain names. Pass
 * `subdomains` to sweep a real enumeration instead.
 */
export async function checkSubdomainTakeover(
	domain: string,
	dnsOptions?: QueryDnsOptions,
	options?: SubdomainTakeoverWrapperOptions,
): Promise<CheckResult> {
	// The clock starts before the DNS sweep on purpose: the deadline being enforced is
	// "return before `safeCheck` kills this check", which is absolute, not a per-fetch
	// allowance. Whatever the DNS legs spend is what the fingerprint probes do not get.
	const budget = createFetchBudget(options?.budgetMs);
	const { fetchFn, wasCut } = resolveProbeFetch(budget, options?.budgetMs !== undefined);

	const result = (await checkSubdomainTakeoverPkg(domain, makeQueryDNS(dnsOptions), {
		timeout: dnsOptions?.timeoutMs ?? HTTPS_TIMEOUT_MS,
		fetchFn,
		...(options?.subdomains ? { subdomains: options.subdomains } : {}),
	})) as CheckResult;

	return wasCut() ? markProbeInconclusive(result, domain) : result;
}
