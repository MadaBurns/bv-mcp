// SPDX-License-Identifier: BUSL-1.1

/**
 * CAA (Certificate Authority Authorization) check tool.
 * Thin wrapper around @blackveil/dns-checks — delegates all logic to the shared package.
 */

import { checkCAA } from '@blackveil/dns-checks';
import { makeQueryDNS } from '../lib/dns-query-adapter';
import type { QueryDnsOptions } from '../lib/dns-types';
import type { CheckResult } from '../lib/scoring';

/**
 * Check CAA records for a domain.
 * Validates that CAA records exist and are properly configured.
 */
export async function checkCaa(domain: string, dnsOptions?: QueryDnsOptions): Promise<CheckResult> {
	return checkCAA(
		domain,
		makeQueryDNS(dnsOptions),
		{ timeout: dnsOptions?.timeoutMs ?? 5000 },
	) as Promise<CheckResult>;
}
