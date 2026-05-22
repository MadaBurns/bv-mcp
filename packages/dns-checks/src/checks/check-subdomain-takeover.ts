// SPDX-License-Identifier: BUSL-1.1

/**
 * Subdomain Takeover / Dangling CNAME Detection check.
 * Scans known/active subdomains for orphaned CNAME records pointing to
 * deleted/unresolved third-party services.
 *
 * Copyright (c) 2023-2026 BlackVeil Security Ltd.
 * Licensed under BSL 1.1
 */

import type { CheckResult, DNSQueryFunction, FetchFunction, Finding } from '../types';
import { buildCheckResult } from '../check-utils';
import { KNOWN_SUBDOMAINS, getNoTakeoverFinding, scanSubdomainForTakeover } from './subdomain-takeover-analysis';

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

	const findingsPerSubdomain = await Promise.all(
		subdomainsToScan.map((subdomain) => scanSubdomainForTakeover(domain, subdomain, queryDNS, fetchFn, timeout)),
	);

	for (const subdomainFindings of findingsPerSubdomain) {
		findings.push(...subdomainFindings);
	}

	if (findings.length === 0) {
		findings.push(getNoTakeoverFinding(domain));
	}

	return buildCheckResult('subdomain_takeover', findings);
}
