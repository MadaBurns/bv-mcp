// SPDX-License-Identifier: BUSL-1.1

/**
 * CAA (Certificate Authority Authorization) check tool.
 * Thin wrapper around @blackveil/dns-checks — delegates all logic to the shared package.
 */

import { checkCAA } from '@blackveil/dns-checks';
import type { ZoneContext } from '@blackveil/dns-checks';
import { queryDns } from '../lib/dns';
import { makeQueryDNS } from '../lib/dns-query-adapter';
import { resolveZoneApex } from '../lib/zone-apex';
import type { QueryDnsOptions } from '../lib/dns-types';
import type { CheckResult } from '../lib/scoring';

/**
 * Check CAA records for a domain.
 * Validates that CAA records exist and are properly configured.
 *
 * `rawQueryDNS` is injected so the check can read the CAA RRset's TTL (which sets
 * the CA/B Forum reuse window) and the response's `AD` flag (whether the policy is
 * DNSSEC-enforceable) — neither survives the `string[]` projection of
 * `makeQueryDNS`. The package routes the CAA lookup itself through this function,
 * so it adds no extra subrequest.
 */
export async function checkCaa(domain: string, dnsOptions?: QueryDnsOptions, zone?: ZoneContext): Promise<CheckResult> {
	const resolvedZone = zone ?? (await resolveZoneApex(domain, dnsOptions));
	return checkCAA(domain, makeQueryDNS(dnsOptions), {
		timeout: dnsOptions?.timeoutMs ?? 5000,
		zone: resolvedZone,
		rawQueryDNS: async (d, type, dnssecFlag) => {
			const resp = await queryDns(d, type as Parameters<typeof queryDns>[1], dnssecFlag ?? false, dnsOptions);
			return { AD: resp.AD, Answer: resp.Answer };
		},
	}) as Promise<CheckResult>;
}
