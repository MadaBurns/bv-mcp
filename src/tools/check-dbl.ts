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
import { buildDnsErrorResult } from '../lib/dns-error-result';
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

type SpamhausStubKind = 'typo' | 'public_resolver' | 'excessive_queries' | 'unknown';

/**
 * Spamhaus 127.255.255.x answers are three distinct non-verdict conditions, not one "quota":
 * .252 = typing error in the DNSBL name, .254 = query refused because it arrived via a public/open
 * resolver, .255 = excessive query volume. Anything else in the range is an unrecognised error code.
 * The public-resolver refusal is PERSISTENT from a DoH vantage (our resolvers are public resolvers).
 */
function describeSpamhausStub(ip: string): { stubKind: SpamhausStubKind; detail: string } {
	const tail = 'This is not a listing. Results from this zone are unavailable.';
	switch (ip) {
		case '127.255.255.252':
			return {
				stubKind: 'typo',
				detail: `Spamhaus DBL returned ${ip}, indicating a typing error in the DNSBL name that was queried. ${tail}`,
			};
		case '127.255.255.254':
			return {
				stubKind: 'public_resolver',
				detail: `Spamhaus DBL returned ${ip}: the query was refused because it arrived via a public/open DNS resolver, not a quota or rate limit. This persists from a DNS-over-HTTPS vantage rather than clearing on retry. ${tail}`,
			};
		case '127.255.255.255':
			return {
				stubKind: 'excessive_queries',
				detail: `Spamhaus DBL returned ${ip}, indicating excessive query volume (a quota or rate limit). ${tail}`,
			};
		default:
			return { stubKind: 'unknown', detail: `Spamhaus DBL returned ${ip}, indicating a query quota or rate limit. ${tail}` };
	}
}

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
	let zoneErrors = 0;
	/** Zones that answered only with a quota/rate-limit stub — a response, but not a verdict. */
	let quotaLimited = 0;
	/** Zones that answered with a non-empty code no decoder recognises — also not a verdict. */
	let unrecognized = 0;

	for (const result of results) {
		if (result.status === 'rejected') {
			// DNS error for this zone — report and continue with partial results
			zoneErrors++;
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
			quotaLimited++;
			const { stubKind, detail } = describeSpamhausStub(ip);
			findings.push(
				createFinding(CATEGORY, `${zone.name} query rate-limited`, 'low', detail, {
					zone: zone.zone,
					returnCode: ip,
					quotaError: true,
					stubKind,
				}),
			);
			continue;
		}

		// URIBL rate-limit/blocked detection (last octet == 1, i.e. only 0x01 set)
		if (zone.zone === 'multi.uribl.com') {
			const uriblOctet = parseInt(ip.split('.')[3], 10);
			if (uriblOctet === 1) {
				quotaLimited++;
				findings.push(
					createFinding(
						CATEGORY,
						`${zone.name} query rate-limited`,
						'low',
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
				createFinding(CATEGORY, `Listed on ${zone.name}`, zone.severity, `${domain} is listed on ${zone.name}: ${decoded.detail}`, {
					zone: zone.zone,
					returnCode: ip,
					labels: decoded.label,
				}),
			);
		} else {
			// A non-empty answer no decoder recognises is not "not listed" — flag it and keep it out of the usable count.
			unrecognized++;
			findings.push(
				createFinding(
					CATEGORY,
					`${zone.name} returned an unrecognised code`,
					'low',
					`${zone.name} (${zone.zone}) returned ${ip} for ${domain}, which this check does not recognise. This is not treated as a verdict from this zone.`,
					{ zone: zone.zone, returnCode: ip, unrecognizedResponse: true },
				),
			);
		}
	}

	if (checkedCount === 0) {
		// Every zone rejected the lookup, so nothing was measured. The tail below would
		// still emit an affirmative "Domain not listed on any blocklist" with `zonesChecked: 0`,
		// scoring 85 / `passed: true` and — because check_dbl caches for 3600 s and the result
		// was not `partial` — pinning that non-answer for an hour (#900).
		return buildDnsErrorResult(
			CATEGORY,
			'DBL',
			new Error(`DNS query failed: all ${DBL_ZONES.length} blocklist lookups for ${domain} errored`),
		) as CheckResult;
	}

	// Zones that gave a usable verdict: answered, and not with a stub or an unrecognised code.
	const usable = checkedCount - quotaLimited - unrecognized;

	if (listedCount === 0 && usable === 0) {
		// Every zone answered, but none with a verdict (e.g. Spamhaus' public-resolver refusal
		// plus a URIBL rate-limit stub plus an unrecognised SURBL code). Nothing was measured, so
		// this is the same abstention as the all-errored case above — not a `low` "found on the
		// 0 blocklist(s)" sentence that still scores as a pass (#1197). The per-zone findings are
		// kept so the caller can see WHY; the note carries `inconclusive` + `errorKind` and never
		// `missingControl`, and `partial` keeps the non-answer out of the 3600 s cache.
		findings.push(
			createFinding(
				CATEGORY,
				'DBL not assessed — no blocklist returned a usable verdict',
				'info',
				`All ${checkedCount} blocklist zones answered for ${domain}, but ${quotaLimited} returned a rate-limit or access stub and ${unrecognized} returned an unrecognised code, so no zone gave a verdict. This is not evidence that the domain is clean or listed.`,
				{
					inconclusive: true,
					errorKind: 'dns_error',
					zonesChecked: 0,
					unansweredZones: zoneErrors,
					quotaLimited,
					unrecognizedResponses: unrecognized,
				},
			),
		);
		return { ...buildCheckResult(CATEGORY, findings), score: 0, passed: false, checkStatus: 'error', partial: true } as CheckResult;
	}

	// No listings: claim clean only when every zone actually answered.
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
		// Only errors/quota/unrecognised codes — bound the claim to the zones that gave a usable verdict
		findings.push(
			createFinding(
				CATEGORY,
				'No listings on the zones that answered',
				'low',
				`${domain} was not found on the ${usable} blocklist(s) that returned a usable answer; ${zoneErrors} errored, ${quotaLimited} were rate-limited and ${unrecognized} returned an unrecognised code.`,
				{ zonesChecked: usable, unansweredZones: zoneErrors, quotaLimited, unrecognizedResponses: unrecognized },
			),
		);
	}

	return buildCheckResult(CATEGORY, findings) as CheckResult;
}
