// SPDX-License-Identifier: BUSL-1.1

/**
 * Pure analysis functions for MX reputation checking.
 * Handles PTR record validation, FCrDNS verification, and DNSBL result interpretation.
 */

import type { Finding } from '../lib/scoring';
import { createFinding } from '../lib/scoring';

/** Pattern matching generic/residential PTR hostnames */
const GENERIC_PTR_PATTERN = /^(ip-|host-|static-|dynamic-|dhcp|dsl|cable|pool|customer|client|user|broadband)/i;

/**
 * Analyze PTR (reverse DNS) records for an MX server IP.
 *
 * Checks for:
 * - Missing PTR records (no reverse DNS)
 * - Forward-confirmed reverse DNS (FCrDNS) failure
 * - Generic/residential PTR hostnames
 * - Valid PTR matching forward DNS
 *
 * @param ip - The MX server IP address
 * @param ptrHostnames - PTR record hostnames for the IP
 * @param forwardIps - IPs resolved from PTR hostnames (for FCrDNS verification)
 * @returns Array of findings from PTR analysis
 */
export function analyzePtrRecords(ip: string, ptrHostnames: string[], forwardIps: string[]): Finding[] {
	const findings: Finding[] = [];

	if (ptrHostnames.length === 0) {
		findings.push(
			createFinding(
				'mx_reputation',
				`No PTR record for MX server ${ip}`,
				'medium',
				`IP ${ip} has no reverse DNS (PTR) record. Mail servers without PTR records are frequently rejected by receiving servers.`,
				{ ip },
			),
		);
		return findings;
	}

	// Check FCrDNS — PTR hostname must resolve back to the original IP
	const hasFcrDns = forwardIps.includes(ip);

	if (!hasFcrDns) {
		findings.push(
			createFinding(
				'mx_reputation',
				`PTR does not match forward DNS for ${ip}`,
				'medium',
				`IP ${ip} has PTR record(s) (${ptrHostnames.join(', ')}), but none resolve back to ${ip}. Forward-confirmed reverse DNS (FCrDNS) failure reduces deliverability.`,
				{ ip, ptrHostnames, forwardIps },
			),
		);
	}

	// Check for generic/residential PTR patterns
	for (const hostname of ptrHostnames) {
		if (GENERIC_PTR_PATTERN.test(hostname)) {
			findings.push(
				createFinding(
					'mx_reputation',
					'MX uses generic PTR hostname',
					'low',
					`PTR hostname "${hostname}" for IP ${ip} matches a generic/residential naming pattern. This may reduce email deliverability.`,
					{ ip, hostname },
				),
			);
		}
	}

	// If FCrDNS passed and no generic PTR, add info finding
	if (hasFcrDns && !ptrHostnames.some((h) => GENERIC_PTR_PATTERN.test(h))) {
		findings.push(
			createFinding(
				'mx_reputation',
				`Reverse DNS valid for ${ip}`,
				'info',
				`IP ${ip} has valid PTR record (${ptrHostnames.join(', ')}) that matches forward DNS.`,
				{ ip, ptrHostnames },
			),
		);
	}

	return findings;
}

/**
 * Analyze DNSBL lookup results for an MX server IP.
 *
 * @param ip - The MX server IP address
 * @param listings - Array of DNSBL zone check results
 * @returns Array of findings from DNSBL analysis
 */
export function analyzeDnsblResults(ip: string, listings: Array<{ zone: string; listed: boolean }>): Finding[] {
	const findings: Finding[] = [];
	const listedZones = listings.filter((l) => l.listed);

	if (listedZones.length > 0) {
		for (const listing of listedZones) {
			findings.push(
				createFinding(
					'mx_reputation',
					`MX server IP listed on ${listing.zone}`,
					'high',
					`IP ${ip} is listed on DNSBL ${listing.zone}. Blacklisted mail servers will have significantly degraded email deliverability.`,
					{ ip, zone: listing.zone },
				),
			);
		}
	} else {
		findings.push(
			createFinding(
				'mx_reputation',
				`MX reputation clean for ${ip}`,
				'info',
				`IP ${ip} is not listed on any checked DNSBLs (${listings.map((l) => l.zone).join(', ')}).`,
				{ ip, zones: listings.map((l) => l.zone) },
			),
		);
	}

	return findings;
}

/**
 * Return the list of DNSBL zones to check.
 * These are well-known, reliable blocklists with publicly queryable DNS interfaces.
 */
export function buildDnsblZones(): string[] {
	return ['zen.spamhaus.org', 'bl.spamcop.net', 'b.barracudacentral.org'];
}

/**
 * Reverse IPv4 octets for DNSBL lookup.
 * Example: `192.0.2.1` becomes `1.2.0.192`
 *
 * @param ip - IPv4 address string
 * @returns Reversed octet string
 */
export function reverseIpForDnsbl(ip: string): string {
	return ip.split('.').reverse().join('.');
}
