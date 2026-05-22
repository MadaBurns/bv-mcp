// SPDX-License-Identifier: BUSL-1.1

/**
 * Subdomain Takeover / Dangling CNAME Detection Tool.
 * Thin wrapper around @blackveil/dns-checks — delegates all logic to the shared package.
 */

import { checkSubdomainTakeover as checkSubdomainTakeoverPkg } from '@blackveil/dns-checks';
import { makeQueryDNS } from '../lib/dns-query-adapter';
import type { QueryDnsOptions } from '../lib/dns-types';
import type { CheckResult } from '../lib/scoring';
import { HTTPS_TIMEOUT_MS } from '../lib/config';

export interface SubdomainTakeoverWrapperOptions {
	/**
	 * Optional explicit subdomain list — passed through to the shared-package
	 * sweeper. When provided, this list (deduped, capped at 1000) is swept
	 * instead of the built-in 15-name KNOWN_SUBDOMAINS. Caller is expected to
	 * source these from a real enumeration (CT logs, brand-audit discovery,
	 * etc.).
	 */
	subdomains?: readonly string[];
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
	return checkSubdomainTakeoverPkg(domain, makeQueryDNS(dnsOptions), {
		timeout: dnsOptions?.timeoutMs ?? HTTPS_TIMEOUT_MS,
		fetchFn: fetch,
		...(options?.subdomains ? { subdomains: options.subdomains } : {}),
	}) as Promise<CheckResult>;
}
