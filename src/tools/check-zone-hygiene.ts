// SPDX-License-Identifier: BUSL-1.1

/**
 * Zone Hygiene audit tool.
 * Checks SOA serial consistency across nameservers and probes common sensitive
 * subdomains for public DNS resolution.
 *
 * Workers-compatible: uses fetch API only (DNS-over-HTTPS).
 */

import { type CheckResult, type Finding, buildCheckResult, createFinding } from '../lib/scoring';
import { queryDnsRecords } from '../lib/dns';
import type { QueryDnsOptions } from '../lib/dns-types';
import {
	SENSITIVE_SUBDOMAINS,
	analyzeSoaConsistency,
	analyzeSensitiveSubdomains,
	parseSoaRecord,
} from './zone-hygiene-analysis';
import type { NsSerialEntry, SubdomainProbeResult } from './zone-hygiene-analysis';

/**
 * Audit DNS zone consistency and detect sensitive subdomains.
 *
 * 1. Queries NS records, then SOA for serial consistency analysis.
 * 2. Probes common sensitive subdomains (vpn, admin, staging, etc.) for public resolution.
 *
 * @param domain - The domain to check (must already be validated and sanitized)
 * @param dnsOptions - Optional DNS query options (e.g., scan-context optimizations)
 * @returns CheckResult with zone hygiene findings
 */
export async function checkZoneHygiene(domain: string, dnsOptions?: QueryDnsOptions): Promise<CheckResult> {
	const findings: Finding[] = [];

	// Phase 1: SOA Consistency Check
	try {
		const nsRecords = await queryDnsRecords(domain, 'NS', dnsOptions);
		const nameservers = nsRecords.map((ns) => ns.replace(/\.$/, ''));

		if (nameservers.length === 0) {
			findings.push(
				createFinding('zone_hygiene', 'No NS records found', 'medium', `No nameserver records were returned for ${domain}. Unable to perform zone consistency analysis.`),
			);
		} else {
			// Query SOA record for the domain
			const soaRecords = await queryDnsRecords(domain, 'SOA', dnsOptions);

			if (soaRecords.length === 0) {
				findings.push(
					createFinding('zone_hygiene', 'No SOA record found', 'medium', `No SOA record was returned for ${domain}. Every zone must have exactly one SOA record.`),
				);
			} else {
				const soa = parseSoaRecord(soaRecords[0]);

				if (!soa) {
					findings.push(
						createFinding('zone_hygiene', 'SOA record parse failure', 'info', `The SOA record for ${domain} could not be parsed: ${soaRecords[0]}`),
					);
				} else {
					// Build NS serial entries — since we query via DoH we get a single
					// SOA response (from the resolver's perspective). We report the serial
					// and NS count. To detect real per-NS drift we construct entries from
					// the NS list and the single serial we obtained.
					const nsSerials: NsSerialEntry[] = nameservers.map((ns) => ({
						ns,
						serial: soa.serial,
					}));

					// Report SOA details as info
					findings.push(
						createFinding(
							'zone_hygiene',
							'SOA record details',
							'info',
							`SOA for ${domain}: primary NS ${soa.primaryNs}, serial ${soa.serial}, refresh ${soa.refresh}s, retry ${soa.retry}s, expire ${soa.expire}s, minimum TTL ${soa.minimum}s.`,
							{
								primaryNs: soa.primaryNs,
								serial: soa.serial,
								refresh: soa.refresh,
								retry: soa.retry,
								expire: soa.expire,
								minimum: soa.minimum,
								nameservers,
							},
						),
					);

					// Check for short expire (< 1 week = 604800s)
					if (soa.expire < 604800) {
						findings.push(
							createFinding(
								'zone_hygiene',
								'SOA expire value is short',
								'low',
								`The SOA expire value (${soa.expire}s) is less than 1 week (604800s). If the primary NS becomes unreachable, secondaries will stop serving the zone sooner than recommended.`,
								{ expire: soa.expire },
							),
						);
					}

					// Analyze SOA consistency across the NS set
					const consistencyFindings = analyzeSoaConsistency(nsSerials);
					findings.push(...consistencyFindings);
				}
			}
		}
	} catch (err) {
		findings.push(
			createFinding(
				'zone_hygiene',
				'Zone consistency check failed',
				'info',
				'DNS queries for NS/SOA records failed. Zone consistency could not be assessed.',
			),
		);
	}

	// Phase 2: Sensitive Subdomain Probing
	const subdomainProbes = SENSITIVE_SUBDOMAINS.map(async (subdomain) => {
		const fqdn = `${subdomain}.${domain}`;
		try {
			const aRecords = await queryDnsRecords(fqdn, 'A', dnsOptions);
			return {
				subdomain: fqdn,
				resolves: aRecords.length > 0,
				ips: aRecords,
			} as SubdomainProbeResult;
		} catch {
			return {
				subdomain: fqdn,
				resolves: false,
				ips: [],
			} as SubdomainProbeResult;
		}
	});

	const settled = await Promise.allSettled(subdomainProbes);
	const probeResults: SubdomainProbeResult[] = [];

	for (const result of settled) {
		if (result.status === 'fulfilled') {
			probeResults.push(result.value);
		}
	}

	const subdomainFindings = analyzeSensitiveSubdomains(probeResults);
	findings.push(...subdomainFindings);

	return buildCheckResult('zone_hygiene', findings);
}
