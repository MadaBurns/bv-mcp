/**
 * DNSSEC (DNS Security Extensions) check tool.
 * Validates DNSSEC by checking the AD flag, querying for DNSKEY/DS records,
 * and auditing algorithm and digest type security.
 */

import { checkDnssec as dnsCheckDnssec, queryDnsRecords } from '../lib/dns';
import { type CheckResult, type Finding, buildCheckResult, createFinding } from '../lib/scoring';

/** DNSKEY algorithm number to human-readable name and security status */
const DNSKEY_ALGORITHMS: Record<number, { name: string; deprecated: boolean }> = {
	5: { name: 'RSA/SHA-1', deprecated: true },
	7: { name: 'RSASHA1-NSEC3', deprecated: true },
	8: { name: 'RSA/SHA-256', deprecated: false },
	10: { name: 'RSA/SHA-512', deprecated: false },
	13: { name: 'ECDSA P-256', deprecated: false },
	14: { name: 'ECDSA P-384', deprecated: false },
	15: { name: 'Ed25519', deprecated: false },
};

/** Modern algorithm numbers that warrant a positive info finding */
const MODERN_ALGORITHMS = new Set([13, 14, 15]);

/** DS digest types considered deprecated */
const DEPRECATED_DS_DIGESTS: Record<number, string> = {
	1: 'SHA-1',
};

/**
 * Parse the algorithm number from a DNSKEY record data string.
 * Format: "flags protocol algorithm <base64key>" e.g. "257 3 13 mdsswUyr3DPW..."
 */
export function parseDnskeyAlgorithm(data: string): number | null {
	const parts = data.trim().split(/\s+/);
	if (parts.length < 3) return null;
	const algo = parseInt(parts[2], 10);
	return isNaN(algo) ? null : algo;
}

/**
 * Parse algorithm and digest type from a DS record data string.
 * Format: "keytag algorithm digesttype <hex-digest>" e.g. "12345 13 2 abc123..."
 */
export function parseDsRecord(data: string): { algorithm: number; digestType: number } | null {
	const parts = data.trim().split(/\s+/);
	if (parts.length < 3) return null;
	const algorithm = parseInt(parts[1], 10);
	const digestType = parseInt(parts[2], 10);
	if (isNaN(algorithm) || isNaN(digestType)) return null;
	return { algorithm, digestType };
}

/**
 * Audit DNSKEY algorithm numbers and produce findings for deprecated or modern algorithms.
 */
function auditDnskeyAlgorithms(domain: string, dnskeyRecords: string[]): Finding[] {
	const findings: Finding[] = [];
	const seenAlgorithms = new Set<number>();

	for (const record of dnskeyRecords) {
		const algo = parseDnskeyAlgorithm(record);
		if (algo === null || seenAlgorithms.has(algo)) continue;
		seenAlgorithms.add(algo);

		const known = DNSKEY_ALGORITHMS[algo];
		if (known?.deprecated) {
			findings.push(
				createFinding(
					'dnssec',
					`Deprecated DNSKEY algorithm (${known.name})`,
					'high',
					`${domain} uses DNSKEY algorithm ${algo} (${known.name}), which is deprecated and may be vulnerable to collision attacks. Upgrade to ECDSA (algorithm 13/14) or Ed25519 (algorithm 15).`,
				),
			);
		} else if (MODERN_ALGORITHMS.has(algo)) {
			findings.push(
				createFinding(
					'dnssec',
					`Modern DNSSEC algorithm (${known!.name})`,
					'info',
					`${domain} uses DNSKEY algorithm ${algo} (${known!.name}), which is a modern and secure choice.`,
				),
			);
		} else if (!known) {
			findings.push(
				createFinding(
					'dnssec',
					`Unknown DNSKEY algorithm (${algo})`,
					'medium',
					`${domain} uses DNSKEY algorithm ${algo}, which is not a commonly recognized DNSSEC algorithm. Verify this is intentional.`,
				),
			);
		}
		// Algorithms 8, 10 are acceptable — no finding needed
	}

	return findings;
}

/**
 * Audit DS digest types and produce findings for deprecated digests.
 */
function auditDsDigestTypes(domain: string, dsRecords: string[]): Finding[] {
	const findings: Finding[] = [];
	const seenDigestTypes = new Set<number>();

	for (const record of dsRecords) {
		const parsed = parseDsRecord(record);
		if (parsed === null) continue;

		const { digestType } = parsed;
		if (seenDigestTypes.has(digestType)) continue;
		seenDigestTypes.add(digestType);

		const deprecatedName = DEPRECATED_DS_DIGESTS[digestType];
		if (deprecatedName) {
			findings.push(
				createFinding(
					'dnssec',
					`Deprecated DS digest type (${deprecatedName})`,
					'medium',
					`${domain} uses DS digest type ${digestType} (${deprecatedName}), which is deprecated. Use SHA-256 (type 2) or SHA-384 (type 4) instead.`,
				),
			);
		}
		// Digest types 2 (SHA-256) and 4 (SHA-384) are good — no finding needed
	}

	return findings;
}

/**
 * Check DNSSEC configuration for a domain.
 * Verifies the AD (Authenticated Data) flag, checks for DNSKEY/DS records,
 * and audits algorithm and digest type security.
 */
export async function checkDnssec(domain: string): Promise<CheckResult> {
	const findings: Finding[] = [];

	// Check AD flag via DoH
	let adFlag = false;
	try {
		adFlag = await dnsCheckDnssec(domain);
	} catch {
		findings.push(
			createFinding('dnssec', 'DNSSEC check failed', 'medium', `Could not verify DNSSEC status for ${domain}. The DNS query failed.`),
		);
		return buildCheckResult('dnssec', findings);
	}

	if (!adFlag) {
		findings.push(
			createFinding(
				'dnssec',
				'DNSSEC not validated',
				'high',
				`DNSSEC validation failed for ${domain}. The AD (Authenticated Data) flag is not set, meaning DNS responses are not cryptographically verified.`,
			),
		);
	}

	// Check for DNSKEY records and audit algorithms
	try {
		const dnskeyRecords = await queryDnsRecords(domain, 'DNSKEY');
		if (dnskeyRecords.length === 0 && !adFlag) {
			findings.push(
				createFinding(
					'dnssec',
					'No DNSKEY records',
					'high',
					`No DNSKEY records found for ${domain}. DNSSEC requires DNSKEY records to be published in the zone.`,
				),
			);
		} else if (dnskeyRecords.length > 0) {
			findings.push(...auditDnskeyAlgorithms(domain, dnskeyRecords));
		}
	} catch {
		// Non-critical: DNSKEY query failure
	}

	// Check for DS records and audit digest types
	try {
		const dsRecords = await queryDnsRecords(domain, 'DS');
		if (dsRecords.length === 0 && !adFlag) {
			findings.push(
				createFinding(
					'dnssec',
					'No DS records',
					'medium',
					`No DS (Delegation Signer) records found for ${domain}. DS records in the parent zone are needed to establish the DNSSEC chain of trust.`,
				),
			);
		} else if (dsRecords.length > 0) {
			findings.push(...auditDsDigestTypes(domain, dsRecords));
		}
	} catch {
		// Non-critical: DS query failure
	}

	// If DNSSEC is valid and no issues found (only info findings at most)
	if (findings.length === 0) {
		findings.push(
			createFinding(
				'dnssec',
				'DNSSEC enabled and validated',
				'info',
				`DNSSEC is properly configured for ${domain}. DNS responses are cryptographically verified.`,
			),
		);
	}

	return buildCheckResult('dnssec', findings);
}
