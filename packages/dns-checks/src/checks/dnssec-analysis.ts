// SPDX-License-Identifier: BUSL-1.1

/**
 * DNSSEC analysis helpers.
 * Pure functions for auditing DNSKEY algorithms and DS digest types.
 *
 * Copyright (c) 2023-2026 BlackVeil Security Ltd.
 * Licensed under BSL 1.1
 */

import type { Finding } from '../types';
import { createFinding } from '../check-utils';

/**
 * DNSKEY algorithm registry per RFC 8624 (Algorithm Implementation Requirements).
 * deprecated: RFC 8624 MUST NOT sign/validate — flag as high severity.
 * notRecommended: RFC 8624 NOT RECOMMENDED for signing — flag as low advisory.
 */
const DNSKEY_ALGORITHMS: Record<number, { name: string; deprecated: boolean; notRecommended?: boolean }> = {
	1: { name: 'RSAMD5', deprecated: true },           // RFC 8624: MUST NOT sign/validate
	3: { name: 'DSA', deprecated: true },              // RFC 8624: MUST NOT sign/validate
	5: { name: 'RSA/SHA-1', deprecated: true },        // RFC 8624: NOT RECOMMENDED (effectively deprecated)
	6: { name: 'DSA-NSEC3-SHA1', deprecated: true },   // RFC 8624: MUST NOT sign/validate
	7: { name: 'RSASHA1-NSEC3', deprecated: true },    // RFC 8624: NOT RECOMMENDED (effectively deprecated)
	8: { name: 'RSA/SHA-256', deprecated: false },     // RFC 8624: MUST sign/validate
	10: { name: 'RSA/SHA-512', deprecated: false, notRecommended: true }, // RFC 8624: NOT RECOMMENDED for signing
	12: { name: 'ECC-GOST', deprecated: true },        // RFC 8624: MUST NOT sign; MAY validate
	13: { name: 'ECDSA P-256', deprecated: false },    // RFC 8624: MUST sign/validate
	14: { name: 'ECDSA P-384', deprecated: false },    // RFC 8624: MAY sign; RECOMMENDED validate
	15: { name: 'Ed25519', deprecated: false },        // RFC 8624: RECOMMENDED sign/validate
	16: { name: 'Ed448', deprecated: false },          // RFC 8080/8624: MAY sign; RECOMMENDED validate
};

/** Modern algorithm numbers that warrant a positive info finding */
const MODERN_ALGORITHMS = new Set([13, 14, 15, 16]);

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
					`${domain} uses DNSKEY algorithm ${algorithm} (${known.name}), which is deprecated per RFC 8624 and should not be used. Upgrade to ECDSA (algorithm 13/14), Ed25519 (algorithm 15), or Ed448 (algorithm 16).`,
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
		} else if (known?.notRecommended) {
			findings.push(
				createFinding(
					'dnssec',
					`DNSKEY algorithm not recommended for signing (${known.name})`,
					'low',
					`${domain} uses DNSKEY algorithm ${algorithm} (${known.name}), which RFC 8624 marks as NOT RECOMMENDED for new DNSSEC deployments. Consider migrating to ECDSA (algorithm 13/14) or Ed25519 (algorithm 15).`,
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
 * Parse an NSEC3PARAM record data string.
 * Format: "algorithm flags iterations salt" — e.g. "1 0 0 -" or "1 0 150 deadbeef"
 * Salt "-" indicates an empty salt per RFC 5155.
 */
export function parseNsec3Param(data: string): { algorithm: number; flags: number; iterations: number; salt: string } | null {
	const parts = data.trim().split(/\s+/);
	if (parts.length < 4) return null;
	const algorithm = parseInt(parts[0], 10);
	const flags = parseInt(parts[1], 10);
	const iterations = parseInt(parts[2], 10);
	const salt = parts[3];
	if (isNaN(algorithm) || isNaN(flags) || isNaN(iterations)) return null;
	return { algorithm, flags, iterations, salt };
}

/**
 * Audit NSEC3PARAM records per RFC 9276 guidance on NSEC3 parameter settings.
 *
 * RFC 9276 recommends:
 *   - iterations = 0  (non-zero adds CPU cost without security benefit and enables DoS)
 *   - salt = empty ("-")  (salts provide no meaningful rainbow-table protection for DNS)
 */
export function auditNsec3Params(domain: string, nsec3ParamRecords: string[]): Finding[] {
	const findings: Finding[] = [];
	let highIterationsFlagged = false;
	let nonEmptySaltFlagged = false;

	for (const record of nsec3ParamRecords) {
		const parsed = parseNsec3Param(record);
		if (!parsed) continue;

		const { iterations, salt } = parsed;

		if (!highIterationsFlagged) {
			if (iterations > 100) {
				findings.push(
					createFinding(
						'dnssec',
						`NSEC3 iteration count excessive (${iterations})`,
						'high',
						`${domain} uses NSEC3 with ${iterations} hash iterations. RFC 9276 §3.3 recommends 0 iterations; values above 100 enable CPU-exhaustion attacks against resolvers. Reduce to 0 immediately.`,
					),
				);
				highIterationsFlagged = true;
			} else if (iterations > 0) {
				findings.push(
					createFinding(
						'dnssec',
						`NSEC3 iteration count non-zero (${iterations})`,
						'medium',
						`${domain} uses NSEC3 with ${iterations} hash iterations. RFC 9276 recommends 0 iterations. Non-zero values add computational overhead without meaningful security benefit.`,
					),
				);
				highIterationsFlagged = true;
			}
		}

		// "-" = empty salt (RFC 5155 §3.3), empty string also counts
		const isEmptySalt = salt === '-' || salt === '';
		if (!isEmptySalt && !nonEmptySaltFlagged) {
			findings.push(
				createFinding(
					'dnssec',
					'NSEC3 uses non-empty salt',
					'low',
					`${domain} uses NSEC3 with a non-empty salt. RFC 9276 §3.1 recommends an empty salt (denoted "-"). Salts provide no effective protection against offline dictionary attacks on NSEC3-hashed owner names.`,
				),
			);
			nonEmptySaltFlagged = true;
		}
	}

	if (findings.length === 0) {
		findings.push(
			createFinding(
				'dnssec',
				'NSEC3 parameters RFC 9276 compliant',
				'info',
				`${domain} uses NSEC3 with 0 iterations and an empty salt, as recommended by RFC 9276.`,
			),
		);
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
