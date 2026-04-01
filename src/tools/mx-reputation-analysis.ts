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
 * Known shared email provider MX hostname suffixes.
 * IPs behind these hostnames are shared infrastructure — DNSBL listings reflect
 * the platform's aggregate traffic, not any individual customer domain's reputation.
 */
const SHARED_PROVIDER_MX_SUFFIXES: Array<{ suffix: string; provider: string }> = [
	{ suffix: '.google.com', provider: 'Google Workspace' },
	{ suffix: '.googlemail.com', provider: 'Google Workspace' },
	{ suffix: '.1e100.net', provider: 'Google Workspace' },
	{ suffix: '.outlook.com', provider: 'Microsoft 365' },
	{ suffix: '.protection.outlook.com', provider: 'Microsoft 365' },
	{ suffix: '.pphosted.com', provider: 'Proofpoint' },
	{ suffix: '.mimecast.com', provider: 'Mimecast' },
	{ suffix: '.mailgun.org', provider: 'Mailgun' },
	{ suffix: '.sendgrid.net', provider: 'SendGrid' },
	{ suffix: '.amazonses.com', provider: 'Amazon SES' },
	{ suffix: '.messagelabs.com', provider: 'Symantec/Broadcom' },
	{ suffix: '.fireeyecloud.com', provider: 'Trellix' },
	{ suffix: '.iphmx.com', provider: 'Cisco IronPort' },
];

/**
 * Check if an MX hostname belongs to a known shared email provider.
 *
 * @param mxHost - The MX exchange hostname (e.g., "smtp-in.l.google.com")
 * @returns The provider name if matched, or null if the host is dedicated infrastructure
 */
export function detectSharedMxProvider(mxHost: string): string | null {
	const normalized = mxHost.trim().toLowerCase().replace(/\.$/, '');
	if (!normalized) return null;
	for (const { suffix, provider } of SHARED_PROVIDER_MX_SUFFIXES) {
		if (normalized === suffix.slice(1) || normalized.endsWith(suffix)) {
			return provider;
		}
	}
	return null;
}

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
 * When the MX host belongs to a known shared email provider (e.g., Google Workspace,
 * Microsoft 365), DNSBL listings are downgraded from `high` to `info` because the
 * listed IPs are shared infrastructure — their blocklist status reflects aggregate
 * platform traffic, not the individual domain's sending reputation.
 *
 * @param ip - The MX server IP address
 * @param listings - Array of DNSBL zone check results
 * @param sharedProvider - If non-null, the name of the shared provider (triggers downgrade)
 * @returns Array of findings from DNSBL analysis
 */
export function analyzeDnsblResults(
	ip: string,
	listings: Array<{ zone: string; listed: boolean }>,
	sharedProvider?: string | null,
): Finding[] {
	const findings: Finding[] = [];
	const listedZones = listings.filter((l) => l.listed);

	if (listedZones.length > 0) {
		for (const listing of listedZones) {
			if (sharedProvider) {
				findings.push(
					createFinding(
						'mx_reputation',
						`Shared ${sharedProvider} IP listed on ${listing.zone} (informational)`,
						'info',
						`IP ${ip} is listed on DNSBL ${listing.zone}, but this is a shared ${sharedProvider} IP. DNSBL listings on shared email infrastructure reflect the provider's aggregate traffic, not your domain's individual reputation. Your sending reputation is managed at the account level by ${sharedProvider}.`,
						{ ip, zone: listing.zone, sharedProvider },
					),
				);
			} else {
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
