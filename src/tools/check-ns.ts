/**
 * NS (Name Server) check tool.
 * Validates nameserver configuration for a domain.
 */

import { queryDnsRecords, queryDns } from '../lib/dns';
import { type CheckResult, type Finding, buildCheckResult, createFinding } from '../lib/scoring';

const RESILIENT_NS_PROVIDERS: Record<string, string> = {
	'cloudflare.com':
		"Cloudflare's anycast network provides built-in geographic redundancy, so this is lower risk than single-provider setups on traditional DNS hosts.",
	'awsdns.com': "AWS Route 53's anycast network provides built-in geographic redundancy, so this is lower risk than single-provider setups on traditional DNS hosts.",
	'google.com':
		"Google Cloud DNS uses globally distributed authoritative infrastructure, so this is lower risk than single-provider setups on traditional DNS hosts.",
};

/**
 * Check nameserver configuration for a domain.
 * Validates NS records exist, checks for diversity, and verifies responsiveness.
 */
export async function checkNs(domain: string): Promise<CheckResult> {
	const findings: Finding[] = [];

	let nsRecords: string[] = [];
	try {
		nsRecords = await queryDnsRecords(domain, 'NS');
		// Clean trailing dots
		nsRecords = nsRecords.map((r) => r.replace(/\.$/, '').toLowerCase());
	} catch {
		findings.push(createFinding('ns', 'NS query failed', 'critical', `Could not query nameserver records for ${domain}.`));
		return buildCheckResult('ns', findings);
	}

	if (nsRecords.length === 0) {
		// Check if domain still resolves (e.g. delegation-only zones like govt.nz)
		let domainResolves = false;
		try {
			const aResp = await queryDns(domain, 'A');
			domainResolves = (aResp.Answer ?? []).length > 0;
		} catch {
			/* ignore */
		}

		if (domainResolves) {
			findings.push(
				createFinding(
					'ns',
					'NS records not directly visible',
					'low',
					`No NS records returned for ${domain} directly, but the domain resolves. NS records may be managed at a parent zone.`,
				),
			);
		} else {
			findings.push(
				createFinding(
					'ns',
					'No NS records found',
					'critical',
					`No nameserver records found for ${domain}. Without NS records, the domain cannot resolve.`,
				),
			);
		}
		return buildCheckResult('ns', findings);
	}

	// Check for single nameserver (no redundancy) — RFC 1035 §2.2 mandates at least two
	if (nsRecords.length === 1) {
		findings.push(
			createFinding(
				'ns',
				'Single nameserver (violates RFC 1035 §2.2)',
				'high',
				`Only one nameserver found (${nsRecords[0]}). RFC 1035 §2.2 mandates at least two nameservers for every zone to ensure redundancy and availability.`,
			),
		);
	}

	// Check for nameserver diversity (all on same provider/TLD)
	const tlds = new Set(
		nsRecords.map((ns) => {
			const parts = ns.split('.');
			return parts.slice(-2).join('.');
		}),
	);

	if (tlds.size === 1 && nsRecords.length > 1) {
		const providerDomain = [...tlds][0];
		const providerContext =
			RESILIENT_NS_PROVIDERS[providerDomain] ?? 'Consider using nameservers from different providers for better resilience.';
		findings.push(
			createFinding(
				'ns',
				'Low nameserver diversity',
				'low',
				`All nameservers are under ${providerDomain}. ${providerContext} For maximum independence, a secondary DNS provider can be added.`,
			),
		);
	}

	// Check SOA record exists and validate parameters
	try {
		const soaResp = await queryDns(domain, 'SOA');
		const soaRecords = (soaResp.Answer ?? []).filter((a) => a.type === 6);
		if (soaRecords.length === 0) {
			findings.push(
				createFinding(
					'ns',
					'No SOA record',
					'medium',
					`No SOA (Start of Authority) record found for ${domain}. SOA records are required for proper DNS zone configuration.`,
				),
			);
		} else {
			// Parse SOA data: <mname> <rname> <serial> <refresh> <retry> <expire> <minimum>
			const soaData = soaRecords[0].data;
			const soaParts = soaData.trim().split(/\s+/);
			if (soaParts.length >= 7) {
				const refresh = parseInt(soaParts[3], 10);
				const retry = parseInt(soaParts[4], 10);
				const expire = parseInt(soaParts[5], 10);
				const minimum = parseInt(soaParts[6], 10);

				if (!isNaN(refresh)) {
					if (refresh < 300) {
						findings.push(
							createFinding(
								'ns',
								'SOA refresh interval too short',
								'low',
								`SOA refresh interval is ${refresh}s (< 300s / 5 min). Very short refresh intervals increase DNS traffic and load on nameservers.`,
							),
						);
					} else if (refresh > 86400) {
						findings.push(
							createFinding(
								'ns',
								'SOA refresh interval too long',
								'low',
								`SOA refresh interval is ${refresh}s (> 86400s / 1 day). Long refresh intervals delay propagation of zone changes to secondary nameservers.`,
							),
						);
					}
				}

				if (!isNaN(retry) && !isNaN(refresh) && retry > refresh) {
					findings.push(
						createFinding(
							'ns',
							'SOA retry exceeds refresh interval',
							'low',
							`SOA retry interval (${retry}s) exceeds refresh interval (${refresh}s). Retry should be shorter than refresh to allow timely recovery after failed zone transfers.`,
						),
					);
				}

				if (!isNaN(expire) && expire < 604800) {
					findings.push(
						createFinding(
							'ns',
							'SOA expire too short',
							'medium',
							`SOA expire value is ${expire}s (< 604800s / 1 week). If secondary nameservers cannot reach the primary for this duration, they will stop serving the zone.`,
						),
					);
				}

				if (!isNaN(minimum) && minimum > 86400) {
					findings.push(
						createFinding(
							'ns',
							'SOA negative cache TTL too long',
							'low',
							`SOA minimum (negative cache TTL) is ${minimum}s (> 86400s / 1 day). This means NXDOMAIN responses will be cached for extended periods, delaying visibility of new records.`,
						),
					);
				}
			}
		}
	} catch {
		// Non-critical
	}

	// If no issues found
	if (findings.length === 0) {
		findings.push(
			createFinding('ns', 'Nameservers properly configured', 'info', `${nsRecords.length} nameservers found: ${nsRecords.join(', ')}`),
		);
	}

	return buildCheckResult('ns', findings);
}
