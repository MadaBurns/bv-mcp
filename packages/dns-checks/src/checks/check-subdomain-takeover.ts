// SPDX-License-Identifier: BUSL-1.1

/**
 * Subdomain Takeover / Dangling CNAME Detection check.
 * Scans known/active subdomains for orphaned CNAME records pointing to
 * deleted/unresolved third-party services.
 *
 * Copyright (c) 2023-2026 BLACKVEIL Security
 * Licensed under BUSL-1.1
 */

import type { CheckResult, DNSQueryFunction, FetchFunction, Finding } from '../types';
import { buildCheckResult, buildNotAssessedResult, createFinding } from '../check-utils';
import { KNOWN_SUBDOMAINS, getNoTakeoverFinding, scanSubdomainForTakeoverInternal } from './subdomain-takeover-analysis';

/** Cap on caller-supplied subdomain lists to bound per-call DNS+HTTP cost. */
const MAX_SUBDOMAINS = 1000;

export interface SubdomainTakeoverOptions {
	timeout?: number;
	fetchFn?: FetchFunction;
	/**
	 * Optional explicit subdomain list (full FQDNs or short labels). When
	 * provided, this list is swept *instead of* the built-in 15-name
	 * `KNOWN_SUBDOMAINS`. Caller is expected to source these from a real
	 * enumeration (CT logs, brand-audit discovery, etc.). Deduped and capped
	 * at `MAX_SUBDOMAINS` per call.
	 */
	subdomains?: readonly string[];
}

/**
 * Check for dangling CNAME records and provider-deprovisioned takeover
 * fingerprints. Default surface: 15 hardcoded "known" subdomain names
 * (`www`, `app`, `api`, etc.). Pass `options.subdomains` to sweep a real
 * enumeration instead.
 *
 * Requires a fetch function for HTTP fingerprint probing.
 */
export async function checkSubdomainTakeover(
	domain: string,
	queryDNS: DNSQueryFunction,
	options?: SubdomainTakeoverOptions,
): Promise<CheckResult> {
	const timeout = options?.timeout ?? 5000;
	// Default to a no-op fetch that never matches fingerprints if no fetchFn provided
	const fetchFn: FetchFunction = options?.fetchFn ?? (async () => new Response('', { status: 200 }));
	const findings: Finding[] = [];

	const explicit = options?.subdomains
		? Array.from(new Set(options.subdomains.map((s) => s.trim()).filter(Boolean))).slice(0, MAX_SUBDOMAINS)
		: null;
	const subdomainsToScan = explicit && explicit.length > 0 ? explicit : KNOWN_SUBDOMAINS;

	const outcomes = await Promise.all(
		subdomainsToScan.map(async (subdomain) => ({
			subdomain,
			...(await scanSubdomainForTakeoverInternal(domain, subdomain, queryDNS, fetchFn, timeout)),
		})),
	);

	for (const outcome of outcomes) {
		findings.push(...outcome.findings);
	}

	const unmeasured = outcomes.filter((o) => o.cnameQueryFailed).map((o) => o.subdomain);
	const answeredCount = outcomes.length - unmeasured.length;

	// Any non-`info` finding is real, DNS-derived evidence of a dangling record. It stands
	// on its own regardless of how many sibling probes failed — positive evidence is
	// monotone, so an unmeasured neighbour cannot invalidate it.
	if (findings.some((f) => f.severity !== 'info')) {
		return buildCheckResult('subdomain_takeover', findings);
	}

	// Issue #948 — abstain when ZERO swept subdomains answered.
	//
	// Every CNAME query threw, so `getNoTakeoverFinding` below would assert "no subdomain
	// takeover vectors detected" — score 100, passed, and written to the 5-minute cache —
	// for a sweep that never reached a resolver. `checkStatus: 'error'` is what makes the
	// scoring engine EXCLUDE the category (`isCheckMeasured`, scoring/evidence.ts) and what
	// arms scan_domain's transient-zero retry (`shouldRetry` requires `'error'`; a
	// `'timeout'` status is never retried); `partial: true` keeps the non-answer out of the
	// cache. The finding carries `inconclusive` + `errorKind` and deliberately NOT
	// `missingControl` — nothing was measured, so nothing can be claimed absent (#638 law).
	if (answeredCount === 0) {
		return buildNotAssessedResult(
			'subdomain_takeover',
			createFinding(
				'subdomain_takeover',
				'Subdomain takeover not assessed — every subdomain probe failed',
				'info',
				`No CNAME lookup in the subdomain sweep for ${domain} completed: all ${outcomes.length} queries failed, so no subdomain was examined. This is not evidence that the domain is free of dangling CNAMEs — the category is excluded from scoring rather than passed. Re-run the check once name resolution is working.`,
				{
					// No `verificationStatus`: the TakeoverVerificationStatus union describes
					// outcomes of a completed probe, and nothing was probed. Matches the Worker
					// wrapper's cut-probe note, which omits it for the same reason.
					evidence: ['cname_sweep_failed'],
					inconclusive: true,
					errorKind: 'dns_error',
					subdomainsUnmeasured: unmeasured,
				},
			),
			'error',
		);
	}

	// Some probes answered: the clean verdict stands, narrowed to the subdomains that were
	// actually swept so the scope of the claim stays auditable.
	if (findings.length === 0) {
		const clean = getNoTakeoverFinding(domain);
		findings.push(
			unmeasured.length > 0
				? { ...clean, metadata: { ...(clean.metadata ?? {}), subdomainsUnmeasured: unmeasured } }
				: clean,
		);
	}

	return buildCheckResult('subdomain_takeover', findings);
}
