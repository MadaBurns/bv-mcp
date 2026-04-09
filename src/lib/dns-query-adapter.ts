// SPDX-License-Identifier: BUSL-1.1

import { queryDnsRecords, queryTxtRecords } from './dns';
import type { QueryDnsOptions } from './dns-types';

/**
 * Build a DNSQueryFunction adapter that routes TXT queries through queryTxtRecords
 * (which strips surrounding quotes from DoH TXT data) and all other record types
 * through queryDnsRecords.
 */
export function makeQueryDNS(dnsOptions?: QueryDnsOptions) {
	return async (domain: string, type: string): Promise<string[]> => {
		if (type === 'TXT') {
			return queryTxtRecords(domain, dnsOptions);
		}
		return queryDnsRecords(domain, type as Parameters<typeof queryDnsRecords>[1], dnsOptions);
	};
}
