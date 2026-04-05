// SPDX-License-Identifier: BUSL-1.1

/**
 * SubdoMailing check tool.
 * Thin wrapper around @blackveil/dns-checks — delegates all logic to the shared package.
 */

import { checkSubdomailing as checkSubdomailingCore } from '@blackveil/dns-checks';
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
 * Check for SubdoMailing risk by analyzing SPF include chain for takeover-vulnerable domains.
 */
export async function checkSubdomailing(domain: string, dnsOptions?: QueryDnsOptions): Promise<CheckResult> {
	return checkSubdomailingCore(
		domain,
		makeQueryDNS(dnsOptions),
		{ timeout: dnsOptions?.timeoutMs ?? 5000 },
	) as Promise<CheckResult>;
}
