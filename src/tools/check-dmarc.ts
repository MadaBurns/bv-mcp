// SPDX-License-Identifier: BUSL-1.1

/**
 * DMARC (Domain-based Message Authentication, Reporting & Conformance) check tool.
 * Thin wrapper around @blackveil/dns-checks — delegates all logic to the shared package.
 */

import { checkDMARC } from '@blackveil/dns-checks';
import { makeQueryDNS } from '../lib/dns-query-adapter';
import type { QueryDnsOptions } from '../lib/dns-types';
import { buildDnsErrorResult } from '../lib/dns-error-result';
import type { CheckResult } from '../lib/scoring';

export { parseDmarcTags } from '@blackveil/dns-checks';

/**
 * Check DMARC records for a domain.
 * Queries _dmarc.<domain> TXT records and validates policy configuration.
 *
 * Top-level DNS failures (timeout, DoH HTTP error, SERVFAIL) are converted to a
 * structured CheckResult instead of a thrown error — see buildDnsErrorResult.
 */
export async function checkDmarc(domain: string, dnsOptions?: QueryDnsOptions): Promise<CheckResult> {
	try {
		return (await checkDMARC(domain, makeQueryDNS(dnsOptions), { timeout: dnsOptions?.timeoutMs ?? 5000 })) as CheckResult;
	} catch (err) {
		return buildDnsErrorResult('dmarc', 'DMARC', err);
	}
}
