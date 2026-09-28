// SPDX-License-Identifier: BUSL-1.1

/**
 * The apex-resolution predicate shared by `scan_domain` and the individual
 * `check_*` tools (#1128).
 *
 * `scan_domain` has always probed the apex NS before fanning out and abstained on
 * NXDOMAIN (`buildNonResolvingResult`): a name that does not exist in DNS has no
 * security posture, and running the matrix only fabricates "absence = missing
 * control" findings. The individual tools had no such gate, so the SAME domain in
 * the SAME session read "does not resolve" from `scan_domain` and a critical
 * "No SPF record found" (or a clean 100 from `check_subdomain_takeover`) from the
 * tool. This module is the one spelling of that predicate for both paths.
 *
 * Only a CLEAN NXDOMAIN rcode abstains. SERVFAIL is a different state (delegated
 * but broken — `scan_domain` disambiguates it separately) and a transport failure
 * is never evidence of non-existence: both fall through to the normal check, i.e.
 * fail-open, exactly as `scan_domain` does.
 */

import { buildCheckResult, createFinding, type CheckCategory, type CheckResult } from './scoring';
import type { QueryDnsOptions } from './dns-types';
import { queryDns } from './dns';

/** DNS RCODE 3. */
const RCODE_NXDOMAIN = 3;
/** DNS RCODE 2. */
const RCODE_SERVFAIL = 2;

/** How the apex NS probe answered. `answered` = any other rcode (NOERROR, REFUSED, …): not a short-circuit. */
export type ApexRcodeClass = 'nxdomain' | 'servfail' | 'answered';

/**
 * Probe the apex NS once and classify the rcode. THROWS on a transport failure —
 * the caller decides the fail-open posture (both current callers fall through).
 */
export async function probeApexRcode(domain: string, dnsOptions?: QueryDnsOptions): Promise<ApexRcodeClass> {
	const apex = await queryDns(domain, 'NS', false, dnsOptions);
	if (apex.Status === RCODE_NXDOMAIN) return 'nxdomain';
	if (apex.Status === RCODE_SERVFAIL) return 'servfail';
	return 'answered';
}

/** The one wording of "this name does not exist", shared by the scan result and the per-check abstention. */
export function describeNonResolvingDomain(domain: string): string {
	return `${domain} does not resolve (NXDOMAIN) — the domain does not exist in DNS, so there is no security posture to assess.`;
}

/**
 * True only when the apex NS probe returned a clean NXDOMAIN. A throw or any other
 * rcode is `false` (fail-open). Direct tool calls do NOT skip the secondary-resolver
 * confirmation, so an NXDOMAIN here has been corroborated where a secondary was
 * reachable — a stronger gate than `scan_domain`'s single-resolver probe.
 */
export async function isNonResolvingApex(domain: string, dnsOptions?: QueryDnsOptions): Promise<boolean> {
	try {
		return (await probeApexRcode(domain, dnsOptions)) === 'nxdomain';
	} catch {
		return false;
	}
}

/**
 * The per-check counterpart of `scan_domain`'s non-resolving result: the #946
 * not-assessed shape (`checkStatus: 'error'`, score 0, `passed: false`,
 * `partial: true`) with ONE info finding naming the reason, and no
 * `missingControl` / `controlPresent` / `recordPresent` — nothing was measured, so
 * nothing is claimed absent or present.
 *
 * `partial: true` keeps it out of the per-check cache, matching `scan_domain`,
 * which returns its non-resolving result without caching it: a just-registered
 * domain is assessed on the next call rather than after a TTL.
 */
export function buildNonResolvingCheckResult(category: CheckCategory, domain: string): CheckResult {
	const finding = createFinding(
		category,
		'Domain does not resolve (NXDOMAIN)',
		'info',
		`${describeNonResolvingDomain(domain)} This control was not assessed.`,
		{ domainResolves: false, notAssessedReason: 'domain_does_not_resolve' },
	);
	return { ...buildCheckResult(category, [finding]), score: 0, passed: false, checkStatus: 'error' as const, partial: true };
}
