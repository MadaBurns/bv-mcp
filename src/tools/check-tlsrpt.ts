// SPDX-License-Identifier: BUSL-1.1

/**
 * TLS-RPT (SMTP TLS Reporting) check tool.
 * Thin wrapper around @blackveil/dns-checks — delegates all logic to the shared package.
 */

import { checkTLSRPT } from '@blackveil/dns-checks';
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
 * Check TLS-RPT records for a domain.
 * Validates the presence and configuration of SMTP TLS Reporting records.
 */
export async function checkTlsrpt(domain: string, dnsOptions?: QueryDnsOptions): Promise<CheckResult> {
	return checkTLSRPT(
		domain,
		makeQueryDNS(dnsOptions),
		{ timeout: dnsOptions?.timeoutMs ?? 5000 },
	) as Promise<CheckResult>;
}
