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

/**
 * Check for dangling CNAME records on known/active subdomains.
 * Flags orphaned records and potential takeover vectors.
 *
 * Requires a fetch function for HTTP fingerprint probing.
 */
export async function checkSubdomainTakeover(
	domain: string,
	queryDNS: DNSQueryFunction,
	options?: { timeout?: number; fetchFn?: FetchFunction },
): Promise<CheckResult> {
	const timeout = options?.timeout ?? 5000;
	// Default to a no-op fetch that never matches fingerprints if no fetchFn provided
	const fetchFn: FetchFunction = options?.fetchFn ?? (async () => new Response('', { status: 200 }));
	const findings: Finding[] = [];

	const findingsPerSubdomain = await Promise.all(
		KNOWN_SUBDOMAINS.map((subdomain) => scanSubdomainForTakeover(domain, subdomain, queryDNS, fetchFn, timeout)),
	);

	for (const subdomainFindings of findingsPerSubdomain) {
		findings.push(...subdomainFindings);
	}

	if (findings.length === 0) {
		findings.push(getNoTakeoverFinding(domain));
	}

	return buildCheckResult('subdomain_takeover', findings);
}
