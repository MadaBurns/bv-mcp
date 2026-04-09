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

/**
 * Check for dangling CNAME records on known/active subdomains.
 * Flags orphaned records and potential takeover vectors.
 */
export async function checkSubdomainTakeover(domain: string, dnsOptions?: QueryDnsOptions): Promise<CheckResult> {
	return checkSubdomainTakeoverPkg(
		domain,
		makeQueryDNS(dnsOptions),
		{ timeout: dnsOptions?.timeoutMs ?? HTTPS_TIMEOUT_MS, fetchFn: fetch },
	) as Promise<CheckResult>;
}
