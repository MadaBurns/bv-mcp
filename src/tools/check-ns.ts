// SPDX-License-Identifier: BUSL-1.1

/**
 * NS (Name Server) check tool.
 * Thin wrapper around @blackveil/dns-checks — delegates all logic to the shared package.
 */

import { checkNS } from '@blackveil/dns-checks';
import { queryDns, queryDnsRecords, queryTxtRecords } from '../lib/dns';
import type { QueryDnsOptions } from '../lib/dns-types';
import type { CheckResult } from '../lib/scoring';

function makeQueryDNS(dnsOptions?: QueryDnsOptions) {
	return async (domain: string, type: string): Promise<string[]> => {
		if (type === 'TXT') {
			return queryTxtRecords(domain, dnsOptions);
		}
		return queryDnsRecords(domain, type as Parameters<typeof queryDnsRecords>[1], dnsOptions);
	};
}

/**
 * Check nameserver configuration for a domain.
 * Validates NS records exist, checks for diversity, and verifies responsiveness.
 */
export async function checkNs(domain: string, dnsOptions?: QueryDnsOptions): Promise<CheckResult> {
	return checkNS(
		domain,
		makeQueryDNS(dnsOptions),
		{
			timeout: dnsOptions?.timeoutMs ?? 5000,
			rawQueryDNS: async (d, type, dnssecFlag) => {
				const resp = await queryDns(d, type as Parameters<typeof queryDns>[1], dnssecFlag ?? false, dnsOptions);
				return { AD: resp.AD, Answer: resp.Answer };
			},
		},
	) as Promise<CheckResult>;
}
