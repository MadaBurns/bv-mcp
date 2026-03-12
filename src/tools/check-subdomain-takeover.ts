// SPDX-License-Identifier: MIT

/**
 * Subdomain Takeover / Dangling CNAME Detection Tool
 * Scans known/active subdomains for orphaned CNAME records pointing to deleted/unresolved third-party services.
 */

import type { QueryDnsOptions } from '../lib/dns-types';
import { type CheckResult, type Finding, buildCheckResult } from '../lib/scoring';
import { KNOWN_SUBDOMAINS, getNoTakeoverFinding, scanSubdomainForTakeover } from './subdomain-takeover-analysis';

/**
 * Check for dangling CNAME records on known/active subdomains.
 * Flags orphaned records and potential takeover vectors.
 */
export async function checkSubdomainTakeover(domain: string, dnsOptions?: QueryDnsOptions): Promise<CheckResult> {
	const findings: Finding[] = [];

	const findingsPerSubdomain = await Promise.all(
		KNOWN_SUBDOMAINS.map((subdomain) => scanSubdomainForTakeover(domain, subdomain, dnsOptions)),
	);

	for (const subdomainFindings of findingsPerSubdomain) {
		findings.push(...subdomainFindings);
	}

	if (findings.length === 0) {
		findings.push(getNoTakeoverFinding(domain));
	}

	return buildCheckResult('subdomain_takeover', findings);
}
