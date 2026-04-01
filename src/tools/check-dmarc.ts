// SPDX-License-Identifier: BUSL-1.1

/**
 * DMARC (Domain-based Message Authentication, Reporting & Conformance) check tool.
 * Thin wrapper around @blackveil/dns-checks — delegates all logic to the shared package.
 */

import { checkDMARC } from '@blackveil/dns-checks';
import { queryDnsRecords, queryTxtRecords } from '../lib/dns';
import type { QueryDnsOptions } from '../lib/dns-types';
import type { CheckResult } from '../lib/scoring';

export { parseDmarcTags } from '@blackveil/dns-checks';

function makeQueryDNS(dnsOptions?: QueryDnsOptions) {
	return async (domain: string, type: string): Promise<string[]> => {
		if (type === 'TXT') {
			return queryTxtRecords(domain, dnsOptions);
		}
		return queryDnsRecords(domain, type as Parameters<typeof queryDnsRecords>[1], dnsOptions);
	};
}

/**
 * Check DMARC records for a domain.
 * Queries _dmarc.<domain> TXT records and validates policy configuration.
 */
export async function checkDmarc(domain: string, dnsOptions?: QueryDnsOptions): Promise<CheckResult> {
	return checkDMARC(
		domain,
		makeQueryDNS(dnsOptions),
		{ timeout: dnsOptions?.timeoutMs ?? 5000 },
	) as Promise<CheckResult>;
}
