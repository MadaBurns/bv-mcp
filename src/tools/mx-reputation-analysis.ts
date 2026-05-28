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
 * DNSBL response classification.
 *
 * - `listed`: the IP returned a real listing code (e.g. Spamhaus 127.0.0.2-11)
 * - `inconclusive`: the DNSBL returned an operational code that does NOT indicate
 *   a real listing — most commonly Spamhaus's 127.255.255.254 ("query refused —
 *   public resolver") when the scanner runs through a non-registered public
 *   resolver. Treating these as "listed" produces high-severity false positives.
 *   Verify out-of-band before escalating.
 * - `not_listed`: the DNSBL returned no A record (typical NXDOMAIN-like result for
 *   a clean IP).
 */
export type DnsblStatus = 'listed' | 'inconclusive' | 'not_listed';

export interface DnsblZoneResult {
	zone: string;
	status: DnsblStatus;
	/** Raw answer record values (e.g. ["127.255.255.254"]) carried through for transparency. */
	returnCodes?: string[];
}

/**
 * Classify DNSBL A-record answers into a status.
 *
 * Real listing codes for the major public DNSBLs (Spamhaus ZEN, SpamCop, Barracuda)
 * all use the `127.0.0.X` range — the low byte is the listing reason (2=SBL,
 * 4-7=XBL, 10-11=PBL, etc.). The `127.255.255.X` range is reserved by Spamhaus
 * for operational return codes:
 *
 * - 127.255.255.252: domain typo / not a DNSBL zone
 * - 127.255.255.254: public/open resolver — query refused
 * - 127.255.255.255: excessive queries — rate-limited
 *
 * The 127.255.255.254 code is the most common false-positive trigger when the
 * scanner runs through a public resolver (which Workers' DoH typically does).
 *
 * @param answers - Raw A-record answer values from the DNSBL query
 * @returns Classification + the raw codes for the finding's metadata
 */
export function classifyDnsblAnswers(answers: string[]): { status: DnsblStatus; returnCodes: string[] } {
	if (answers.length === 0) {
		return { status: 'not_listed', returnCodes: [] };
	}

	// 127.0.0.X where X >= 2: real DNSBL listing code. 127.0.0.0 (network) and
	// 127.0.0.1 (loopback) would never legitimately appear; treat them like other
	// anomalies (inconclusive).
	const REAL_LISTING_RE = /^127\.0\.0\.([2-9]|\d{2,3})$/;
	const hasRealListing = answers.some((a) => REAL_LISTING_RE.test(a));
	if (hasRealListing) {
		return { status: 'listed', returnCodes: answers };
	}

	// Anything else — Spamhaus operational codes (127.255.255.*), unknown 127.x,
	// or non-127.* anomalies — is inconclusive. Carry the raw codes through so the
	// finding can name them.
	return { status: 'inconclusive', returnCodes: answers };
}

/**
 * Analyze DNSBL lookup results for an MX server IP.
 *
 * When the MX host belongs to a known shared email provider (e.g., Google Workspace,
 * Microsoft 365), DNSBL listings are downgraded from `high` to `info` because the
 * listed IPs are shared infrastructure — their blocklist status reflects aggregate
 * platform traffic, not the individual domain's sending reputation.
 *
 * **Inconclusive results are emitted as `info`-severity findings with explicit
 * "verify out-of-band at check.spamhaus.org" guidance** rather than as high-severity
 * "listed" findings — closing the public-resolver false-positive class.
 *
 * @param ip - The MX server IP address
 * @param results - Array of DNSBL zone check results
 * @param sharedProvider - If non-null, the name of the shared provider (triggers downgrade)
 * @returns Array of findings from DNSBL analysis
 */
export function analyzeDnsblResults(
	ip: string,
	results: DnsblZoneResult[],
	sharedProvider?: string | null,
): Finding[] {
	const findings: Finding[] = [];

	for (const result of results) {
		if (result.status === 'listed') {
			if (sharedProvider) {
				findings.push(
					createFinding(
						'mx_reputation',
						`Shared ${sharedProvider} IP listed on ${result.zone} (informational)`,
						'info',
						`IP ${ip} is listed on DNSBL ${result.zone}, but this is a shared ${sharedProvider} IP. DNSBL listings on shared email infrastructure reflect the provider's aggregate traffic, not your domain's individual reputation. Your sending reputation is managed at the account level by ${sharedProvider}.`,
						{ ip, zone: result.zone, sharedProvider, returnCodes: result.returnCodes },
					),
				);
			} else {
				findings.push(
					createFinding(
						'mx_reputation',
						`MX server IP listed on ${result.zone}`,
						'high',
						`IP ${ip} is listed on DNSBL ${result.zone}. Blacklisted mail servers will have significantly degraded email deliverability.`,
						{ ip, zone: result.zone, returnCodes: result.returnCodes },
					),
				);
			}
		} else if (result.status === 'inconclusive') {
			const codeList = result.returnCodes && result.returnCodes.length > 0
				? result.returnCodes.join(', ')
				: 'unknown';
			findings.push(
				createFinding(
					'mx_reputation',
					`DNSBL query inconclusive on ${result.zone}`,
					'info',
					`Query for ${ip} on ${result.zone} returned an operational code (${codeList}) rather than a listing code. This typically means the DNSBL refused the query — Spamhaus uses 127.255.255.254 to signal "public/open resolver, query blocked", which the scanner cannot distinguish from a real listing on its own. Verify out-of-band at check.spamhaus.org (or via a registered/paid resolver) before treating this as a real listing.`,
					{ ip, zone: result.zone, returnCodes: result.returnCodes, inconclusive: true },
				),
			);
		}
		// not_listed: no per-zone finding emitted; aggregated into the summary below
	}

	// Summary finding when every zone came back clean (no listings AND no inconclusive
	// queries). If ANY query was inconclusive, the summary is omitted — the user has
	// per-zone inconclusive findings to act on instead.
	const allClean = results.length > 0 && results.every((r) => r.status === 'not_listed');
	if (allClean) {
		findings.push(
			createFinding(
				'mx_reputation',
				`MX reputation clean for ${ip}`,
				'info',
				`IP ${ip} is not listed on any checked DNSBLs (${results.map((r) => r.zone).join(', ')}).`,
				{ ip, zones: results.map((r) => r.zone) },
			),
		);
	}

	return findings;
}

/**
 * Return the list of DNSBL zones to check.
 * These are well-known blocklists with publicly queryable DNS interfaces.
 *
 * Spamhaus ZEN is intentionally EXCLUDED. From the shared public resolvers
 * bv-mcp runs through, ZEN returns rate-limit/refused codes
 * (127.255.255.252/.254/.255) indistinguishable from a real verdict,
 * producing false "clean"/"listed" results. bv-mcp has no reliable ZEN query
 * path — its secondary-resolver token only drives empty-result confirmation in
 * the DoH transport, it does NOT reroute the ZEN lookup — so ZEN can never be
 * trusted here and is dropped unconditionally (neither queried nor counted).
 * All other providers are unaffected.
 */
export function buildDnsblZones(): string[] {
	return ['bl.spamcop.net', 'b.barracudacentral.org'];
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
