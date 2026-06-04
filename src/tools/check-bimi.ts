// SPDX-License-Identifier: BUSL-1.1

/**
 * BIMI (Brand Indicators for Message Identification) check tool.
 * Thin wrapper around @blackveil/dns-checks — delegates all logic to the shared package.
 */

import { checkBIMI } from '@blackveil/dns-checks';
import { makeQueryDNS } from '../lib/dns-query-adapter';
import type { QueryDnsOptions } from '../lib/dns-types';
import { buildDnsErrorResult } from '../lib/dns-error-result';
import type { CheckResult } from '../lib/scoring';
import { safeFetch } from '../lib/safe-fetch';

/**
 * Check BIMI records for a domain.
 * Validates the presence and configuration of BIMI TXT records,
 * including logo URL format and VMC authority evidence.
 *
 * BIMI `l=` and `a=` tags are extracted from a TXT record at default._bimi.<domain>
 * and are entirely attacker-controlled. We pass safeFetch instead of the raw
 * `fetch` so the destination hostname is validated before any outbound request
 * (H2 fix from the 2026-05-08 security audit).
 */
export async function checkBimi(domain: string, dnsOptions?: QueryDnsOptions): Promise<CheckResult> {
	try {
		return (await checkBIMI(domain, makeQueryDNS(dnsOptions), { timeout: dnsOptions?.timeoutMs ?? 5000, fetchFn: safeFetch })) as CheckResult;
	} catch (err) {
		return buildDnsErrorResult('bimi', 'BIMI', err);
	}
}
