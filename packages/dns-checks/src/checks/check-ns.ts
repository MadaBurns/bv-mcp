// SPDX-License-Identifier: BUSL-1.1

/**
 * NS (Name Server) check.
 * Validates nameserver configuration for a domain.
 *
 * Copyright (c) 2023-2026 BlackVeil Security Ltd.
 * Licensed under BSL 1.1
 */

import type { CheckResult, DNSQueryFunction, Finding, RawDNSQueryFunction } from '../types';
import { buildCheckResult, createFinding } from '../check-utils';
import {
	getNameserverDiversityFinding,
	getNsConfiguredFinding,
	getNsVisibilityFinding,
	getSingleNsFinding,
	getSoaValidationFindings,
	normalizeNsRecords,
	parseSoaValues,
} from './ns-analysis';

/**
 * Check nameserver configuration for a domain.
 * Validates NS records exist, checks for diversity, and verifies SOA configuration.
 *
 * Requires rawQueryDNS for SOA record parsing (needs answer type filtering)
 * and for domain resolution check (A record check for delegation-only zones).
 */
export async function checkNS(
	domain: string,
	queryDNS: DNSQueryFunction,
	options?: { timeout?: number; rawQueryDNS?: RawDNSQueryFunction },
): Promise<CheckResult> {
	const timeout = options?.timeout ?? 5000;
	const rawQueryDNS = options?.rawQueryDNS;
	const findings: Finding[] = [];

	let nsRecords: string[] = [];
	try {
		nsRecords = normalizeNsRecords(await queryDNS(domain, 'NS', { timeout }));
	} catch {
		findings.push(createFinding('ns', 'NS query failed', 'critical', `Could not query nameserver records for ${domain}.`));
		return buildCheckResult('ns', findings);
	}

	if (nsRecords.length === 0) {
		// Check if domain still resolves (e.g. delegation-only zones like govt.nz)
		let domainResolves = false;
		if (rawQueryDNS) {
			try {
				const aResp = await rawQueryDNS(domain, 'A', false, { timeout });
				domainResolves = (aResp.Answer ?? []).length > 0;
			} catch {
				/* ignore */
			}
		} else {
			// Fallback: try resolving A records via queryDNS
			try {
				const aRecords = await queryDNS(domain, 'A', { timeout });
				domainResolves = aRecords.length > 0;
			} catch {
				/* ignore */
			}
		}

		findings.push(getNsVisibilityFinding(domain, domainResolves));
		return buildCheckResult('ns', findings);
	}

	// Check for single nameserver (no redundancy) — RFC 1035 §2.2 mandates at least two
	const singleNsFinding = getSingleNsFinding(nsRecords);
	if (singleNsFinding) {
		findings.push(singleNsFinding);
	}

	const diversityFinding = getNameserverDiversityFinding(nsRecords);
	if (diversityFinding) {
		findings.push(diversityFinding);
	}

	// Check SOA record exists and validate parameters
	if (rawQueryDNS) {
		try {
			const soaResp = await rawQueryDNS(domain, 'SOA', false, { timeout });
			const soaRecords = (soaResp.Answer ?? []).filter((a) => a.type === 6);
			if (soaRecords.length === 0) {
				findings.push(
					createFinding(
						'ns',
						'No SOA record',
						'medium',
						`No SOA (Start of Authority) record found for ${domain}. SOA records are required for proper DNS zone configuration.`,
					),
				);
			} else {
				const soaValues = parseSoaValues(soaRecords[0].data);
				if (soaValues) {
					findings.push(...getSoaValidationFindings(soaValues));
				}
			}
		} catch {
			// Non-critical
		}
	}

	// Wildcard DNS detection — probe a random subdomain
	try {
		const probeId = Math.random().toString(36).substring(2, 10);
		const probeFqdn = `_bv-probe-${probeId}.${domain}`;
		const probeRecords = await queryDNS(probeFqdn, 'A', { timeout });
		if (probeRecords.length > 0) {
			findings.push(
				createFinding(
					'ns',
					'Wildcard DNS detected',
					'medium',
					`Domain responds to arbitrary subdomains, indicating a wildcard DNS record (*.${domain}). Wildcard records can mask dangling CNAMEs, complicate subdomain enumeration defences, and make subdomain takeover detection unreliable.`,
					{ wildcardDetected: true, probeSubdomain: probeFqdn },
				),
			);
		}
	} catch {
		// Non-critical — wildcard detection failure should not affect NS check
	}

	// If no issues found
	if (findings.length === 0) {
		findings.push(getNsConfiguredFinding(nsRecords));
	}

	return buildCheckResult('ns', findings);
}
