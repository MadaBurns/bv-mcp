// SPDX-License-Identifier: BUSL-1.1

/**
 * SVCB/HTTPS DNS record check tool (RFC 9460).
 * Thin wrapper around @blackveil/dns-checks — delegates all logic to the shared package.
 */

import { checkSVCBHTTPS } from '@blackveil/dns-checks';
import { queryDnsRecords, queryTxtRecords } from '../lib/dns';
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
 * Check HTTPS/SVCB records (RFC 9460) for a domain.
 */
export async function checkSvcbHttps(domain: string, dnsOptions?: QueryDnsOptions): Promise<CheckResult> {
	return checkSVCBHTTPS(
		domain,
		makeQueryDNS(dnsOptions),
		{ timeout: dnsOptions?.timeoutMs ?? 5000 },
	) as Promise<CheckResult>;
}
