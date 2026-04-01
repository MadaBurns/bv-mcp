// SPDX-License-Identifier: BUSL-1.1

/**
 * SRV Service Discovery Audit tool.
 * Probes common SRV prefixes to map a domain's DNS-visible service footprint.
 * Flags insecure protocol advertisements (plain-text IMAP/POP3 without encrypted variants).
 *
 * Workers-compatible: uses fetch API only (DNS-over-HTTPS).
 */

import { type CheckResult, type Finding, buildCheckResult, createFinding } from '../lib/scoring';
import { querySrvRecords } from '../lib/dns';
import type { QueryDnsOptions } from '../lib/dns-types';
import { SRV_PREFIXES, analyzeSrvResults } from './srv-analysis';
import type { SrvProbeResult } from './srv-analysis';

/**
 * Audit SRV service discovery records for a domain.
 *
 * Probes ~16 common SRV prefixes (email, calendar, messaging, web) in parallel
 * and analyzes discovered services for security concerns.
 *
 * @param domain - The domain to check (must already be validated and sanitized)
 * @param dnsOptions - Optional DNS query options (e.g., scan-context optimizations)
 * @returns CheckResult with SRV findings
 */
export async function checkSrv(domain: string, dnsOptions?: QueryDnsOptions): Promise<CheckResult> {
	const probes = SRV_PREFIXES.map(async (prefix) => {
		const name = `${prefix}.${domain}`;
		const records = await querySrvRecords(name, dnsOptions);
		return { prefix, records } as SrvProbeResult;
	});

	const settled = await Promise.allSettled(probes);

	const successful: SrvProbeResult[] = [];
	let failedCount = 0;

	for (const result of settled) {
		if (result.status === 'fulfilled') {
			successful.push(result.value);
		} else {
			failedCount++;
		}
	}

	// If all probes failed, report a DNS error
	if (successful.length === 0) {
		const findings: Finding[] = [
			createFinding(
				'srv',
				'SRV DNS queries failed',
				'medium',
				`All ${SRV_PREFIXES.length} SRV prefix queries failed for ${domain}. Unable to determine service footprint.`,
			),
		];
		return buildCheckResult('srv', findings);
	}

	const findings = analyzeSrvResults(successful);

	// Note partial failures if some probes failed
	if (failedCount > 0) {
		findings.push(
			createFinding(
				'srv',
				'Some SRV queries failed',
				'info',
				`${failedCount} of ${SRV_PREFIXES.length} SRV prefix queries failed. Results may be incomplete.`,
			),
		);
	}

	return buildCheckResult('srv', findings);
}
