// SPDX-License-Identifier: BUSL-1.1

/**
 * DANE (DNS-Based Authentication of Named Entities) check tool.
 * Thin wrapper around @blackveil/dns-checks — delegates all logic to the shared package.
 */

import { checkDANE } from '@blackveil/dns-checks';
import { queryDns } from '../lib/dns';
import { makeQueryDNS } from '../lib/dns-query-adapter';
import type { QueryDnsOptions } from '../lib/dns-types';
import { buildDnsErrorResult } from '../lib/dns-error-result';
import type { CheckResult } from '../lib/scoring';

/**
 * Check DANE TLSA records for a domain's MX servers (SMTP DANE only; HTTPS DANE is
 * `check-dane-https.ts`).
 *
 * Top-level DNS failures are converted to a structured INCONCLUSIVE CheckResult
 * instead of a thrown error, per the DNS-failure-resilience convention in CLAUDE.md —
 * see buildDnsErrorResult. `check-dane` was the one DNS-throwing wrapper missing this
 * (#639): the package used to swallow an unresolvable MX lookup into a `low` finding
 * that scored 95 and still passed, so a DANE measurement failure could never be
 * excluded from scoring as transient, and `scan_domain`'s transient-zero retry (which
 * keys on `checkStatus === 'error'`) could never fire for it.
 */
export async function checkDane(domain: string, dnsOptions?: QueryDnsOptions): Promise<CheckResult> {
	try {
		return (await checkDANE(domain, makeQueryDNS(dnsOptions), {
			timeout: dnsOptions?.timeoutMs ?? 5000,
			rawQueryDNS: async (d, type, dnssecFlag) => {
				const resp = await queryDns(d, type as Parameters<typeof queryDns>[1], dnssecFlag ?? false, dnsOptions);
				// `Status` is the DoH rcode. It is what lets checkDANE tell a genuine
				// "no MX" (NOERROR/NODATA) from a SERVFAIL/REFUSED it must abstain on.
				return { AD: resp.AD, Answer: resp.Answer, Status: resp.Status };
			},
		})) as CheckResult;
	} catch (err) {
		return buildDnsErrorResult('dane', 'DANE', err);
	}
}
