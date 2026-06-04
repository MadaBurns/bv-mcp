// SPDX-License-Identifier: BUSL-1.1

/**
 * SPF (Sender Policy Framework) check tool.
 * Thin wrapper around @blackveil/dns-checks — delegates all logic to the shared package.
 */

import { checkSPF } from '@blackveil/dns-checks';
import { makeQueryDNS } from '../lib/dns-query-adapter';
import type { QueryDnsOptions } from '../lib/dns-types';
import { buildDnsErrorResult } from '../lib/dns-error-result';
import type { CheckResult } from '../lib/scoring';

/**
 * Check SPF records for a domain.
 * Looks for v=spf1 TXT records and validates their configuration.
 * Recursively expands include chains to compute true DNS lookup count.
 *
 * Top-level DNS failures (timeout, DoH HTTP error, SERVFAIL) are converted to a
 * structured CheckResult instead of a thrown error — see buildDnsErrorResult.
 * The `checkStatus: 'error'` shape (not `missingControl`) is what makes
 * scan_domain's transient-zero retry fire for a one-off SPF DNS hiccup.
 */
export async function checkSpf(domain: string, dnsOptions?: QueryDnsOptions): Promise<CheckResult> {
	try {
		return (await checkSPF(domain, makeQueryDNS(dnsOptions), { timeout: dnsOptions?.timeoutMs ?? 5000 })) as CheckResult;
	} catch (err) {
		return buildDnsErrorResult('spf', 'SPF', err);
	}
}
