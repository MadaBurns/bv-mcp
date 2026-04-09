// SPDX-License-Identifier: BUSL-1.1

/**
 * DANE-HTTPS check tool.
 * Thin wrapper around @blackveil/dns-checks — delegates all logic to the shared package.
 */

import { checkDANEHTTPS } from '@blackveil/dns-checks';
import { queryDns } from '../lib/dns';
import { makeQueryDNS } from '../lib/dns-query-adapter';
import type { QueryDnsOptions } from '../lib/dns-types';
import type { CheckResult } from '../lib/scoring';

/**
 * Check DANE TLSA records for a domain's HTTPS endpoint (_443._tcp.{domain}).
 */
export async function checkDaneHttps(domain: string, dnsOptions?: QueryDnsOptions): Promise<CheckResult> {
	return checkDANEHTTPS(
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
