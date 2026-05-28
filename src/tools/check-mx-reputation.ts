// SPDX-License-Identifier: BUSL-1.1

/**
 * MX Reputation check tool.
 * Resolves MX server IPs, checks against major DNSBLs (Spamhaus ZEN, SpamCop,
 * Barracuda), and validates reverse DNS (PTR) with forward-confirmed rDNS.
 *
 * Standalone tool — NOT included in scan_domain due to unpredictable DNSBL
 * response times. Daily quota of 20/day per IP with 60-minute caching.
 *
 * Workers-compatible: uses fetch API only (DNS-over-HTTPS).
 */

import { type CheckResult, type Finding, buildCheckResult, createFinding } from '../lib/scoring';
import { queryDnsRecords, queryMxRecords, queryPtrRecords } from '../lib/dns';
import type { QueryDnsOptions } from '../lib/dns-types';
import { isValidIPv4 } from '../lib/ip-utils';
import {
	analyzePtrRecords,
	analyzeDnsblResults,
	buildDnsblZones,
	classifyDnsblAnswers,
	type DnsblZoneResult,
	reverseIpForDnsbl,
	detectSharedMxProvider,
} from './mx-reputation-analysis';

/** Maximum number of MX hosts to check (bounds outbound query count). */
const MAX_MX_HOSTS = 3;

/**
 * Check mail server reputation and reverse DNS for a domain.
 *
 * For each MX host (up to 3):
 * 1. Resolves A records to get server IPs
 * 2. Validates PTR records and FCrDNS consistency
 * 3. Checks IP against major DNSBLs
 *
 * @param domain - The domain to check (must already be validated and sanitized)
 * @param dnsOptions - Optional DNS query options
 * @returns CheckResult with MX reputation findings
 */
export async function checkMxReputation(domain: string, dnsOptions?: QueryDnsOptions): Promise<CheckResult> {
	const findings: Finding[] = [];

	// Step 1: Query MX records
	let mxRecords: Array<{ priority: number; exchange: string }>;
	try {
		mxRecords = await queryMxRecords(domain, dnsOptions);
	} catch {
		findings.push(
			createFinding(
				'mx_reputation',
				'MX lookup failed',
				'medium',
				`Could not query MX records for ${domain}. Unable to check mail server reputation.`,
			),
		);
		return buildCheckResult('mx_reputation', findings);
	}

	// Step 2: No MX records — nothing to check
	if (mxRecords.length === 0) {
		findings.push(
			createFinding(
				'mx_reputation',
				'No MX records — skipping reputation check',
				'info',
				`${domain} has no MX records. Mail server reputation checks are not applicable.`,
			),
		);
		return buildCheckResult('mx_reputation', findings);
	}

	// Step 3: Check each MX host (limit to first MAX_MX_HOSTS)
	const hostsToCheck = mxRecords.slice(0, MAX_MX_HOSTS);

	for (const mx of hostsToCheck) {
		const mxHost = mx.exchange;
		if (!mxHost || mxHost === '.') continue;

		// Detect shared email provider (Google Workspace, Microsoft 365, etc.)
		// to contextualise DNSBL results — shared-infrastructure IPs don't reflect
		// the individual domain's sending reputation.
		const sharedProvider = detectSharedMxProvider(mxHost);

		try {
			// Resolve A records for MX host
			const rawIps = await queryDnsRecords(mxHost, 'A', dnsOptions);
			if (rawIps.length === 0) {
				findings.push(
					createFinding(
						'mx_reputation',
						`No A record for MX host ${mxHost}`,
						'medium',
						`MX host ${mxHost} does not resolve to any IP addresses. This mail server is unreachable.`,
						{ mxHost },
					),
				);
				continue;
			}

			const invalidIps = [...new Set(rawIps.filter((ip) => !isValidIPv4(ip)))];
			const ips = [...new Set(rawIps.filter(isValidIPv4))];
			if (ips.length === 0) {
				findings.push(
					createFinding(
						'mx_reputation',
						`No valid IPv4 address for MX host ${mxHost}`,
						'medium',
						`MX host ${mxHost} returned A record data, but none of the values were valid IPv4 addresses. Reputation checks were skipped for this host.`,
						{ mxHost, invalidIps },
					),
				);
				continue;
			}

			// Check the first valid IPv4 address of each MX host.
			const ip = ips[0];

			// PTR check
			try {
				const ptrHostnames = await queryPtrRecords(ip, dnsOptions);

				// FCrDNS verification: resolve A records for each PTR hostname
				const forwardIps: string[] = [];
				for (const ptrHost of ptrHostnames) {
					try {
						const resolved = await queryDnsRecords(ptrHost, 'A', dnsOptions);
						forwardIps.push(...resolved);
					} catch {
						// Individual PTR forward lookup failed — skip
					}
				}

				findings.push(...analyzePtrRecords(ip, ptrHostnames, forwardIps));
			} catch {
				findings.push(
					createFinding(
						'mx_reputation',
						`PTR lookup failed for ${ip}`,
						'low',
						`Could not query reverse DNS for MX server IP ${ip} (host: ${mxHost}).`,
						{ ip, mxHost },
					),
				);
			}

			// DNSBL checks — classify each zone's answer codes rather than treating
			// any A-record as a listing. Spamhaus returns 127.255.255.254 for queries
			// via public resolvers ("refused, not listed"); the scanner runs through
			// Workers' DoH (a public resolver), so without classification the refusal
			// would silently surface as a high-severity false-positive listing.
			// See `classifyDnsblAnswers` for the 127.0.0.X vs 127.255.255.X semantics.
			const dnsblZones = buildDnsblZones();
			const dnsblResults: DnsblZoneResult[] = [];

			for (const zone of dnsblZones) {
				const queryName = `${reverseIpForDnsbl(ip)}.${zone}`;
				try {
					const answers = await queryDnsRecords(queryName, 'A', dnsOptions);
					const { status, returnCodes } = classifyDnsblAnswers(answers);
					dnsblResults.push({
						zone,
						status,
						returnCodes: returnCodes.length > 0 ? returnCodes : undefined,
					});
				} catch {
					// DNSBL query failed (timeout, NXDOMAIN, etc.) — treat as not listed.
					// NXDOMAIN is the explicit "not on this blocklist" signal for most DNSBLs.
					dnsblResults.push({ zone, status: 'not_listed' });
				}
			}

			findings.push(...analyzeDnsblResults(ip, dnsblResults, sharedProvider));
		} catch {
			findings.push(
				createFinding(
					'mx_reputation',
					`Reputation check failed for ${mxHost}`,
					'low',
					`An error occurred while checking MX host ${mxHost}. Partial results may be available for other MX hosts.`,
					{ mxHost },
				),
			);
		}
	}

	// Handle edge case where all MX hosts were null/dot
	if (findings.length === 0) {
		findings.push(
			createFinding(
				'mx_reputation',
				'No valid MX hosts to check',
				'info',
				`All MX records for ${domain} point to null hosts. Mail server reputation checks are not applicable.`,
			),
		);
	}

	return buildCheckResult('mx_reputation', findings);
}
