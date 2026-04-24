// SPDX-License-Identifier: BUSL-1.1

/**
 * SPF (Sender Policy Framework) check tool.
 * Thin wrapper around @blackveil/dns-checks — delegates all logic to the shared package.
 */

import { checkSPF } from '@blackveil/dns-checks';
import { makeQueryDNS } from '../lib/dns-query-adapter';
import type { QueryDnsOptions } from '../lib/dns-types';
import { buildCheckResult, createFinding, type CheckResult } from '../lib/scoring';

/**
 * Check SPF records for a domain.
 * Looks for v=spf1 TXT records and validates their configuration.
 * Recursively expands include chains to compute true DNS lookup count.
 *
 * Top-level DNS failures (timeout, DoH HTTP error, invalid response) are
 * converted to a high-severity finding so callers receive a structured
 * CheckResult instead of a thrown error.
 */
export async function checkSpf(domain: string, dnsOptions?: QueryDnsOptions): Promise<CheckResult> {
	try {
		return (await checkSPF(
			domain,
			makeQueryDNS(dnsOptions),
			{ timeout: dnsOptions?.timeoutMs ?? 5000 },
		)) as CheckResult;
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		const isTimeout = /timed? out|timeout/i.test(message);
		return buildCheckResult('spf', [
			createFinding(
				'spf',
				isTimeout ? 'SPF check timed out' : 'SPF check could not complete',
				'high',
				isTimeout
					? `DNS lookup for the domain timed out before the SPF record could be resolved: ${message}`
					: `DNS lookup failed before the SPF record could be resolved: ${message}`,
				{
					errorKind: isTimeout ? 'timeout' : 'dns_error',
					confidence: 'heuristic',
					missingControl: true,
				},
			),
		]);
	}
}
