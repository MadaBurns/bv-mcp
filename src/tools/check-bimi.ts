// SPDX-License-Identifier: BUSL-1.1

/**
 * BIMI (Brand Indicators for Message Identification) check tool.
 * Thin wrapper around @blackveil/dns-checks — delegates all logic to the shared package.
 */

import { checkBIMI } from '@blackveil/dns-checks';
import { makeQueryDNS } from '../lib/dns-query-adapter';
import type { QueryDnsOptions } from '../lib/dns-types';
import type { CheckResult } from '../lib/scoring';

/**
 * Check BIMI records for a domain.
 * Validates the presence and configuration of BIMI TXT records,
 * including logo URL format and VMC authority evidence.
 */
export async function checkBimi(domain: string, dnsOptions?: QueryDnsOptions): Promise<CheckResult> {
	return checkBIMI(
		domain,
		makeQueryDNS(dnsOptions),
		{ timeout: dnsOptions?.timeoutMs ?? 5000, fetchFn: fetch },
	) as Promise<CheckResult>;
}
