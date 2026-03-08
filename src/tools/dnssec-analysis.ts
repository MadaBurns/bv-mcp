import { type Finding, createFinding } from '../lib/scoring';

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
	const algorithm = parseInt(parts[2], 10);
	return isNaN(algorithm) ? null : algorithm;
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
export function auditDnskeyAlgorithms(domain: string, dnskeyRecords: string[]): Finding[] {
	const findings: Finding[] = [];
	const seenAlgorithms = new Set<number>();

	for (const record of dnskeyRecords) {
		const algorithm = parseDnskeyAlgorithm(record);
		if (algorithm === null || seenAlgorithms.has(algorithm)) continue;
		seenAlgorithms.add(algorithm);

		const known = DNSKEY_ALGORITHMS[algorithm];
		if (known?.deprecated) {
			findings.push(
				createFinding(
					'dnssec',
					`Deprecated DNSKEY algorithm (${known.name})`,
					'high',
					`${domain} uses DNSKEY algorithm ${algorithm} (${known.name}), which is deprecated and may be vulnerable to collision attacks. Upgrade to ECDSA (algorithm 13/14) or Ed25519 (algorithm 15).`,
				),
			);
		} else if (MODERN_ALGORITHMS.has(algorithm)) {
			findings.push(
				createFinding(
					'dnssec',
					`Modern DNSSEC algorithm (${known!.name})`,
					'info',
					`${domain} uses DNSKEY algorithm ${algorithm} (${known!.name}), which is a modern and secure choice.`,
				),
			);
		} else if (!known) {
			findings.push(
				createFinding(
					'dnssec',
					`Unknown DNSKEY algorithm (${algorithm})`,
					'medium',
					`${domain} uses DNSKEY algorithm ${algorithm}, which is not a commonly recognized DNSSEC algorithm. Verify this is intentional.`,
				),
			);
		}
	}

	return findings;
}

/**
 * Audit DS digest types and produce findings for deprecated digests.
 */
export function auditDsDigestTypes(domain: string, dsRecords: string[]): Finding[] {
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
	}

	return findings;
}