// SPDX-License-Identifier: BUSL-1.1

/**
 * MTA-STS (Mail Transfer Agent Strict Transport Security) check tool.
 * Thin wrapper around @blackveil/dns-checks — delegates all logic to the shared package.
 */

import { checkMTASTS } from '@blackveil/dns-checks';
import { makeQueryDNS } from '../lib/dns-query-adapter';
import type { QueryDnsOptions } from '../lib/dns-types';
import type { CheckResult } from '../lib/scoring';
import { HTTPS_TIMEOUT_MS } from '../lib/config';

/**
 * Check MTA-STS configuration for a domain.
 * Queries _mta-sts.<domain> TXT records and optionally fetches the policy file.
 */
export async function checkMtaSts(domain: string, dnsOptions?: QueryDnsOptions): Promise<CheckResult> {
	return checkMTASTS(
		domain,
		makeQueryDNS(dnsOptions),
		{ timeout: dnsOptions?.timeoutMs ?? HTTPS_TIMEOUT_MS, fetchFn: fetch },
	) as Promise<CheckResult>;
}
