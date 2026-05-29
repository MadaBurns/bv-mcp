// SPDX-License-Identifier: BUSL-1.1

/**
 * NSEC3 Parameter Analysis tool.
 * Assesses zone walkability risk by analyzing NSEC3PARAM configuration via DoH.
 *
 * Workers-compatible: uses fetch API only (DNS-over-HTTPS).
 */

import { queryDnsRecords } from '../lib/dns';
import type { QueryDnsOptions } from '../lib/dns-types';
import { buildCheckResult, createFinding } from '../lib/scoring';
import type { CheckResult, CheckCategory } from '../lib/scoring';

const CATEGORY = 'nsec_walkability' as CheckCategory;

/** NSEC3 hash algorithm names (RFC 5155 §11). Only algorithm 1 is defined. */
const NSEC3_HASH_ALGORITHMS: Record<number, string> = {
	1: 'SHA-1',
};

/** Parsed NSEC3PARAM fields. */
interface Nsec3Params {
	algorithm: number;
	algorithmName: string;
	flags: number;
	iterations: number;
	salt: string; // "-" means empty
}

/**
 * Parse an NSEC3PARAM data string: "algorithm flags iterations salt"
 * Salt of "-" indicates an empty salt (RFC 5155 §4.2).
 */
function parseNsec3Param(data: string): Nsec3Params | null {
	const parts = data.trim().split(/\s+/);
	if (parts.length < 4) return null;

	const algorithm = parseInt(parts[0], 10);
	const flags = parseInt(parts[1], 10);
	const iterations = parseInt(parts[2], 10);
	const salt = parts[3];

	if (!Number.isFinite(algorithm) || !Number.isFinite(flags) || !Number.isFinite(iterations)) {
		return null;
	}

	return {
		algorithm,
		algorithmName: NSEC3_HASH_ALGORITHMS[algorithm] ?? `Unknown (${algorithm})`,
		flags,
		iterations,
		salt,
	};
}

/**
 * Determine whether a zone is DNSSEC-signed by probing for DNSKEY records, with
 * a DS lookup as a backstop. NSEC/NSEC3 records only exist in signed zones, so
 * this gate prevents reporting an unsigned (DNSSEC-absent) zone as "walkable".
 *
 * Conservative: if both lookups error, we treat the zone as unsigned so the
 * tool does not raise a high-severity walkability finding on weak evidence.
 */
async function isZoneSigned(domain: string, dnsOptions?: QueryDnsOptions): Promise<boolean> {
	try {
		const dnskey = await queryDnsRecords(domain, 'DNSKEY', dnsOptions);
		if (dnskey.length > 0) return true;
	} catch {
		// fall through to DS backstop
	}
	try {
		const ds = await queryDnsRecords(domain, 'DS', dnsOptions);
		return ds.length > 0;
	} catch {
		return false;
	}
}

/**
 * Assess NSEC3 zone walkability risk by analyzing NSEC3PARAM records.
 *
 * Limitations (disclosed in findings):
 * - Cannot probe for actual NSEC/NSEC3 denial records via DoH
 * - Cannot definitively confirm plain NSEC vs. absent NSEC3PARAM
 * - Analyzes configuration parameters only
 *
 * @param domain - The domain to check (must already be validated and sanitized)
 * @param dnsOptions - Optional DNS query options
 * @returns CheckResult with NSEC3 walkability findings
 */
export async function checkNsecWalkability(domain: string, dnsOptions?: QueryDnsOptions): Promise<CheckResult> {
	const findings: ReturnType<typeof createFinding>[] = [];

	let nsec3Records: string[] = [];
	try {
		nsec3Records = await queryDnsRecords(domain, 'NSEC3PARAM', dnsOptions);
	} catch {
		findings.push(
			createFinding(
				CATEGORY,
				'NSEC3PARAM query failed',
				'info',
				`DNS query for NSEC3PARAM records at ${domain} failed. Unable to assess zone walkability. Note: this analysis cannot probe for actual NSEC/NSEC3 denial records via DoH and analyzes configuration parameters only.`,
				{ domain },
			),
		);
		return buildCheckResult(CATEGORY, findings) as CheckResult;
	}

	if (nsec3Records.length === 0) {
		// NSEC and NSEC3 only exist in DNSSEC-signed zones. An unsigned zone has no
		// NSEC chain at all, so "fully walkable" is a false positive. Gate the high
		// severity behind confirmed signing: check for DNSKEY (and DS as a backstop)
		// before concluding the zone uses plain NSEC.
		const signed = await isZoneSigned(domain, dnsOptions);

		if (!signed) {
			findings.push(
				createFinding(
					CATEGORY,
					'Zone not DNSSEC-signed — walkability N/A',
					'info',
					`No NSEC3PARAM record was found for ${domain}, and no DNSKEY/DS records were found either, so the zone is not DNSSEC-signed. NSEC/NSEC3 denial-of-existence records only exist in signed zones, so there is no NSEC chain to walk. Zone-walking risk does not apply here. (To gain DNSSEC's spoofing/cache-poisoning protections, the zone would need to be signed — at which point NSEC3 should be used to prevent enumeration.)`,
					{ domain, walkable: false, dnssecSigned: false },
				),
			);
			return buildCheckResult(CATEGORY, findings) as CheckResult;
		}

		findings.push(
			createFinding(
				CATEGORY,
				'No NSEC3PARAM record found',
				'high',
				`The zone for ${domain} is DNSSEC-signed (DNSKEY/DS present) but publishes no NSEC3PARAM record. The signed zone therefore likely uses plain NSEC, which makes it fully walkable — an attacker can enumerate all zone contents by following NSEC chain links. Limitation: DoH cannot probe for actual NSEC/NSEC3 denial-of-existence records, so this assessment is based on the absence of NSEC3PARAM configuration only.`,
				{ domain, walkable: true, dnssecSigned: true },
			),
		);
		return buildCheckResult(CATEGORY, findings) as CheckResult;
	}

	// Parse the first NSEC3PARAM record (zones should have exactly one)
	const params = parseNsec3Param(nsec3Records[0]);

	if (!params) {
		findings.push(
			createFinding(
				CATEGORY,
				'Unparseable NSEC3PARAM',
				'info',
				`NSEC3PARAM record for ${domain} could not be parsed: ${nsec3Records[0]}`,
				{ domain, raw: nsec3Records[0] },
			),
		);
		return buildCheckResult(CATEGORY, findings) as CheckResult;
	}

	const hasSalt = params.salt !== '-';
	const hasIterations = params.iterations > 0;

	// Check opt-out flag (bit 0 of flags)
	if (params.flags & 1) {
		findings.push(
			createFinding(
				CATEGORY,
				'NSEC3 opt-out enabled',
				'low',
				`NSEC3PARAM for ${domain} has the opt-out flag set (flags=${params.flags}). Opt-out allows unsigned delegations to be omitted from the NSEC3 chain, which may leave some subdomains without denial-of-existence protection.`,
				{ domain, flags: params.flags, optOut: true },
			),
		);
	}

	// Assess walkability risk based on parameters
	if (!hasIterations && !hasSalt) {
		// RFC 9276 default: 0 iterations, no salt — low enumeration cost
		findings.push(
			createFinding(
				CATEGORY,
				'NSEC3 with minimal parameters',
				'medium',
				`NSEC3PARAM for ${domain} uses 0 iterations and no salt (RFC 9276 recommended defaults). While NSEC3 prevents trivial zone walking, the low enumeration cost means offline dictionary attacks against the hashed names are feasible. Algorithm: ${params.algorithmName}. Note: this tool analyzes NSEC3PARAM configuration only and cannot probe for actual NSEC3 denial records via DoH.`,
				{
					domain,
					algorithm: params.algorithmName,
					algorithmId: params.algorithm,
					iterations: params.iterations,
					salt: params.salt,
					hasSalt: false,
				},
			),
		);
	} else {
		// Has salt and/or iterations > 0 — standard NSEC3 configuration
		findings.push(
			createFinding(
				CATEGORY,
				'NSEC3 parameters configured',
				'info',
				`NSEC3PARAM for ${domain}: algorithm ${params.algorithmName}, ${params.iterations} iteration${params.iterations !== 1 ? 's' : ''}, salt ${hasSalt ? params.salt : 'none'}. Zone uses NSEC3 hashed denial-of-existence, which mitigates trivial zone walking. Note: this tool analyzes configuration parameters only.`,
				{
					domain,
					algorithm: params.algorithmName,
					algorithmId: params.algorithm,
					iterations: params.iterations,
					salt: params.salt,
					hasSalt,
				},
			),
		);
	}

	return buildCheckResult(CATEGORY, findings) as CheckResult;
}
