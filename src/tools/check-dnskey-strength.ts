// SPDX-License-Identifier: BUSL-1.1

/**
 * DNSKEY algorithm-strength check tool.
 *
 * Audits the signing algorithms advertised in a domain's DNSKEY RRset against
 * RFC 8624 (Algorithm Implementation Requirements for DNSSEC). This is distinct
 * from `check_dnssec`, which verifies DNSSEC *presence* / chain-of-trust — here we
 * grade the cryptographic *strength* of the keys, independent of whether the chain
 * validates. Hardening-tier (bonus-only): a domain with no DNSKEY records simply
 * earns no bonus, it is not penalised as a missing control.
 */

import { parseDnskeyAlgorithm } from '@blackveil/dns-checks';
import { queryDnsRecords, DnsQueryError } from '../lib/dns';
import type { QueryDnsOptions } from '../lib/dns-types';
import { buildCheckResult, createFinding } from '../lib/scoring';
import type { CheckResult, Finding } from '../lib/scoring';

/**
 * DNSKEY algorithm registry per RFC 8624.
 * `deprecated` → MUST NOT / NOT RECOMMENDED for signing (high severity).
 * `notRecommended` → discouraged for new deployments (low advisory).
 * `modern` → ECDSA / EdDSA, the recommended choices (positive info).
 */
const DNSKEY_ALGORITHMS: Record<number, { name: string; deprecated?: boolean; notRecommended?: boolean; modern?: boolean }> = {
	1: { name: 'RSAMD5', deprecated: true },
	3: { name: 'DSA', deprecated: true },
	5: { name: 'RSA/SHA-1', deprecated: true },
	6: { name: 'DSA-NSEC3-SHA1', deprecated: true },
	7: { name: 'RSASHA1-NSEC3', deprecated: true },
	8: { name: 'RSA/SHA-256' },
	10: { name: 'RSA/SHA-512', notRecommended: true },
	12: { name: 'ECC-GOST', deprecated: true },
	13: { name: 'ECDSA P-256', modern: true },
	14: { name: 'ECDSA P-384', modern: true },
	15: { name: 'Ed25519', modern: true },
	16: { name: 'Ed448', modern: true },
};

/**
 * Check DNSKEY algorithm strength for a domain.
 * Queries the DNSKEY RRset and grades each distinct signing algorithm per RFC 8624.
 *
 * @param domain - Domain to inspect.
 * @param dnsOptions - Optional DNS query options (timeout, secondary DoH).
 * @returns CheckResult under the `dnskey_strength` category.
 */
export async function checkDnskeyStrength(domain: string, dnsOptions?: QueryDnsOptions): Promise<CheckResult> {
	try {
		const records = await queryDnsRecords(domain, 'DNSKEY', dnsOptions);

		if (records.length === 0) {
			// No DNSKEY published — DNSSEC not deployed at this label. Hardening bonus simply not earned.
			return buildCheckResult('dnskey_strength', [
				createFinding(
					'dnskey_strength',
					'No DNSKEY records published',
					'info',
					`${domain} publishes no DNSKEY records, so DNSKEY algorithm strength cannot be assessed. Deploy DNSSEC with a modern algorithm (ECDSA P-256 / Ed25519) to earn this hardening credit.`,
					{ confidence: 'deterministic' },
				),
			]);
		}

		const findings: Finding[] = [];
		const seen = new Set<number>();

		for (const record of records) {
			const algorithm = parseDnskeyAlgorithm(record);
			if (algorithm === null || seen.has(algorithm)) continue;
			seen.add(algorithm);

			const known = DNSKEY_ALGORITHMS[algorithm];
			if (!known) {
				findings.push(
					createFinding(
						'dnskey_strength',
						`Unknown DNSKEY algorithm (${algorithm})`,
						'medium',
						`${domain} signs with DNSKEY algorithm ${algorithm}, which is not a recognised DNSSEC algorithm. Verify this is intentional.`,
						{ confidence: 'deterministic' },
					),
				);
			} else if (known.deprecated) {
				findings.push(
					createFinding(
						'dnskey_strength',
						`Deprecated DNSKEY algorithm (${known.name})`,
						'high',
						`${domain} signs with DNSKEY algorithm ${algorithm} (${known.name}), deprecated by RFC 8624. Migrate to ECDSA P-256 (13), Ed25519 (15), or Ed448 (16).`,
						{ confidence: 'deterministic' },
					),
				);
			} else if (known.notRecommended) {
				findings.push(
					createFinding(
						'dnskey_strength',
						`DNSKEY algorithm not recommended (${known.name})`,
						'low',
						`${domain} signs with DNSKEY algorithm ${algorithm} (${known.name}), which RFC 8624 marks NOT RECOMMENDED for new deployments. Prefer ECDSA P-256 (13) or Ed25519 (15).`,
						{ confidence: 'deterministic' },
					),
				);
			} else if (known.modern) {
				findings.push(
					createFinding(
						'dnskey_strength',
						`Modern DNSKEY algorithm (${known.name})`,
						'info',
						`${domain} signs with DNSKEY algorithm ${algorithm} (${known.name}), a modern and recommended choice.`,
						{ confidence: 'deterministic' },
					),
				);
			} else {
				// Acceptable but not "modern" (e.g. RSA/SHA-256).
				findings.push(
					createFinding(
						'dnskey_strength',
						`Acceptable DNSKEY algorithm (${known.name})`,
						'info',
						`${domain} signs with DNSKEY algorithm ${algorithm} (${known.name}), which is acceptable. ECDSA P-256 (13) or Ed25519 (15) offer smaller keys and signatures.`,
						{ confidence: 'deterministic' },
					),
				);
			}
		}

		return buildCheckResult('dnskey_strength', findings);
	} catch (err) {
		if (err instanceof DnsQueryError) {
			return {
				...buildCheckResult('dnskey_strength', [
					createFinding(
						'dnskey_strength',
						'DNSKEY strength check could not complete',
						'info',
						`DNS query failed (${err.message}). DNSKEY algorithm strength unknown.`,
						{ dnsError: err.message, checkStatus: 'error', confidence: 'heuristic' },
					),
				]),
				checkStatus: 'error' as const,
			};
		}
		throw err;
	}
}
