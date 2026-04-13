// SPDX-License-Identifier: BUSL-1.1

/**
 * Domain Blocklist (DBL) check tool.
 * Queries a domain against DNS-based Domain Block Lists:
 * - Spamhaus DBL (dbl.spamhaus.org)
 * - URIBL (multi.uribl.com)
 * - SURBL (multi.surbl.org)
 *
 * Workers-compatible: uses fetch API only (DNS-over-HTTPS).
 */

import type { CheckCategory, CheckResult, Finding } from '../lib/scoring';
import { buildCheckResult, createFinding } from '../lib/scoring';
import { queryDnsRecords } from '../lib/dns';
import type { QueryDnsOptions } from '../lib/dns-types';

/** Cast category — 'dbl' is not in the scoring CheckCategory union (intelligence-only tool). */
const CATEGORY = 'dbl' as CheckCategory;

// ---------------------------------------------------------------------------
// DBL zone definitions
// ---------------------------------------------------------------------------

interface DblZone {
	name: string;
	zone: string;
	decode: (ip: string) => DblDecodeResult | null;
	/** Default severity for a listing on this zone. */
	severity: 'high' | 'medium';
}

interface DblDecodeResult {
	label: string;
	detail: string;
}

// -- Spamhaus DBL return codes ------------------------------------------------

const SPAMHAUS_CODES: Record<string, string> = {
	'127.0.1.2': 'Spam domain',
	'127.0.1.4': 'Phishing domain',
	'127.0.1.5': 'Malware domain',
	'127.0.1.6': 'Botnet C&C domain',
	'127.0.1.102': 'Abused legit spam domain',
	'127.0.1.103': 'Abused legit spammed redirector',
	'127.0.1.104': 'Abused legit phishing domain',
	'127.0.1.105': 'Abused legit malware domain',
	'127.0.1.106': 'Abused legit botnet C&C domain',
};

function decodeSpamhaus(ip: string): DblDecodeResult | null {
	// 127.255.255.x = quota/rate limit error — NOT a listing
	if (/^127\.255\.255\./.test(ip)) return null;

	const label = SPAMHAUS_CODES[ip];
	if (label) {
		return { label, detail: `Spamhaus DBL return code ${ip}: ${label}` };
	}
	// Unknown but valid listing in the 127.0.1.x range
	if (/^127\.0\.1\./.test(ip)) {
		return { label: 'Listed (unknown code)', detail: `Spamhaus DBL return code ${ip}: unknown listing type` };
	}
	return null;
}

// -- URIBL bitmask flags ------------------------------------------------------
// Reference: https://uribl.com — 0x01 means the querier is rate-limited/blocked.

const URIBL_FLAGS: Array<{ mask: number; label: string }> = [
	{ mask: 0x02, label: 'Black' },
	{ mask: 0x04, label: 'Grey' },
	{ mask: 0x08, label: 'Red' },
];

function decodeUribl(ip: string): DblDecodeResult | null {
	const octet = parseInt(ip.split('.')[3], 10);
	if (!Number.isFinite(octet) || octet === 0) return null;

	// 0x01 = querier rate-limited/blocked by URIBL — NOT a listing
	if ((octet & 0x01) !== 0 && (octet & ~0x01) === 0) return null;

	const matched = URIBL_FLAGS.filter((f) => (octet & f.mask) !== 0).map((f) => f.label);
	if (matched.length === 0) return null;

	const labels = matched.join(', ');
	return { label: labels, detail: `URIBL flags: ${labels} (return code ${ip})` };
}

// -- SURBL bitmask flags ------------------------------------------------------

const SURBL_FLAGS: Array<{ mask: number; label: string }> = [
	{ mask: 0x02, label: 'SC (SpamCop)' },
	{ mask: 0x04, label: 'WS (sa-blacklist)' },
	{ mask: 0x08, label: 'PH (Phishing)' },
	{ mask: 0x10, label: 'MW (Malware)' },
	{ mask: 0x20, label: 'AB (AbuseButler)' },
	{ mask: 0x40, label: 'JP' },
	{ mask: 0x80, label: 'CR (Cracked)' },
];

function decodeSurbl(ip: string): DblDecodeResult | null {
	const octet = parseInt(ip.split('.')[3], 10);
	if (!Number.isFinite(octet) || octet === 0) return null;

	const matched = SURBL_FLAGS.filter((f) => (octet & f.mask) !== 0).map((f) => f.label);
	if (matched.length === 0) return null;

	const labels = matched.join(', ');
	return { label: labels, detail: `SURBL flags: ${labels} (return code ${ip})` };
}

// -- Zone registry ------------------------------------------------------------

const DBL_ZONES: DblZone[] = [
	{ name: 'Spamhaus DBL', zone: 'dbl.spamhaus.org', decode: decodeSpamhaus, severity: 'high' },
	{ name: 'URIBL', zone: 'multi.uribl.com', decode: decodeUribl, severity: 'medium' },
	{ name: 'SURBL', zone: 'multi.surbl.org', decode: decodeSurbl, severity: 'medium' },
];

// ---------------------------------------------------------------------------
// Main check function
// ---------------------------------------------------------------------------

/**
 * Check a domain against DNS-based Domain Block Lists.
 *
 * Queries the domain against Spamhaus DBL, URIBL, and SURBL. Returns listing
 * status with decoded return codes. NXDOMAIN (empty response) means the domain
 * is not listed. Spamhaus 127.255.255.x responses are treated as quota errors,
 * not listings.
 *
 * @param domain - The domain to check (used as-is, subdomains not stripped)
 * @param dnsOptions - Optional DNS query options
 * @returns CheckResult with DBL findings
 */
export async function checkDbl(domain: string, dnsOptions?: QueryDnsOptions): Promise<CheckResult> {
	const findings: Finding[] = [];

	// Query all zones in parallel
	const results = await Promise.allSettled(
		DBL_ZONES.map(async (zone) => {
			const queryName = `${domain}.${zone.zone}`;
			const answers = await queryDnsRecords(queryName, 'A', dnsOptions);
			return { zone, answers };
		}),
	);

	let listedCount = 0;
	let checkedCount = 0;

	for (const result of results) {
		if (result.status === 'rejected') {
			// DNS error for this zone — report and continue with partial results
			const zoneIndex = results.indexOf(result);
			const zone = DBL_ZONES[zoneIndex];
			findings.push(
				createFinding(
					CATEGORY,
					`${zone.name} lookup error`,
					'low',
					`DNS query error for ${domain} on ${zone.name} (${zone.zone}). Partial results may be available from other blocklists.`,
					{ zone: zone.zone, error: true },
				),
			);
			continue;
		}

		checkedCount++;
		const { zone, answers } = result.value;

		if (answers.length === 0) {
			// Not listed on this zone (NXDOMAIN / empty)
			continue;
		}

		const ip = answers[0];

		// Spamhaus quota/error detection
		if (zone.zone === 'dbl.spamhaus.org' && /^127\.255\.255\./.test(ip)) {
			findings.push(
				createFinding(
					CATEGORY,
					`${zone.name} query rate-limited`,
					'low',
					`Spamhaus DBL returned ${ip}, indicating a query quota or rate limit. This is not a listing. Results from this zone are unavailable.`,
					{ zone: zone.zone, returnCode: ip, quotaError: true },
				),
			);
			continue;
		}

		// URIBL rate-limit/blocked detection (last octet == 1, i.e. only 0x01 set)
		if (zone.zone === 'multi.uribl.com') {
			const uriblOctet = parseInt(ip.split('.')[3], 10);
			if (uriblOctet === 1) {
				findings.push(
					createFinding(
						CATEGORY,
						`${zone.name} query rate-limited`,
						'info',
						`URIBL returned ${ip}, indicating the querier is rate-limited or blocked. This is not a listing. Results from this zone are unavailable.`,
						{ zone: zone.zone, returnCode: ip, quotaError: true },
					),
				);
				continue;
			}
		}

		// Decode the return code
		const decoded = zone.decode(ip);
		if (decoded) {
			listedCount++;
			findings.push(
				createFinding(
					CATEGORY,
					`Listed on ${zone.name}`,
					zone.severity,
					`${domain} is listed on ${zone.name}: ${decoded.detail}`,
					{ zone: zone.zone, returnCode: ip, labels: decoded.label },
				),
			);
		}
	}

	// If no listings and no errors produced findings, add a clean summary
	if (listedCount === 0 && findings.length === 0) {
		findings.push(
			createFinding(
				CATEGORY,
				'Domain not listed on any blocklist',
				'info',
				`${domain} is not listed on any of the ${checkedCount} checked DNS-based domain blocklists (Spamhaus DBL, URIBL, SURBL).`,
				{ zonesChecked: checkedCount },
			),
		);
	} else if (listedCount === 0 && findings.every((f) => f.severity === 'low')) {
		// Only errors/quota — add an info note that no actual listings were found
		findings.push(
			createFinding(
				CATEGORY,
				'Domain not listed on any blocklist',
				'info',
				`${domain} was not found on any of the successfully queried blocklists.`,
				{ zonesChecked: checkedCount },
			),
		);
	}

	return buildCheckResult(CATEGORY, findings) as CheckResult;
}
