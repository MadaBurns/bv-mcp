// SPDX-License-Identifier: BUSL-1.1

/**
 * SPF (Sender Policy Framework) check tool.
 * Thin wrapper around @blackveil/dns-checks — delegates all logic to the shared package.
 */

import { checkSPF } from '@blackveil/dns-checks';
import { queryDnsRecords, queryTxtRecords } from '../lib/dns';
import type { QueryDnsOptions } from '../lib/dns-types';
import type { CheckResult } from '../lib/scoring';

/**
 * Build a DNSQueryFunction adapter that routes TXT queries through queryTxtRecords
 * (which strips surrounding quotes from DoH TXT data) and all other record types
 * through queryDnsRecords.
 */
function makeQueryDNS(dnsOptions?: QueryDnsOptions) {
	return async (domain: string, type: string): Promise<string[]> => {
		if (type === 'TXT') {
			return queryTxtRecords(domain, dnsOptions);
		}
		return queryDnsRecords(domain, type as Parameters<typeof queryDnsRecords>[1], dnsOptions);
	};
}

/**
 * Check SPF records for a domain.
 * Looks for v=spf1 TXT records and validates their configuration.
 * Recursively expands include chains to compute true DNS lookup count.
 */
export async function checkSpf(domain: string, dnsOptions?: QueryDnsOptions): Promise<CheckResult> {
	return checkSPF(
		domain,
		makeQueryDNS(dnsOptions),
		{ timeout: dnsOptions?.timeoutMs ?? 5000 },
	) as Promise<CheckResult>;
}
