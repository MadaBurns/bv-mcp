/**
 * NS (Name Server) check tool.
 * Validates nameserver configuration for a domain.
 */

import { queryDnsRecords, queryDns } from '../lib/dns';
import { type CheckResult, type Finding, buildCheckResult, createFinding } from '../lib/scoring';
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
 * Validates NS records exist, checks for diversity, and verifies responsiveness.
 */
export async function checkNs(domain: string): Promise<CheckResult> {
	const findings: Finding[] = [];

	let nsRecords: string[] = [];
	try {
		nsRecords = normalizeNsRecords(await queryDnsRecords(domain, 'NS'));
	} catch {
		findings.push(createFinding('ns', 'NS query failed', 'critical', `Could not query nameserver records for ${domain}.`));
		return buildCheckResult('ns', findings);
	}

	if (nsRecords.length === 0) {
		// Check if domain still resolves (e.g. delegation-only zones like govt.nz)
		let domainResolves = false;
		try {
			const aResp = await queryDns(domain, 'A');
			domainResolves = (aResp.Answer ?? []).length > 0;
		} catch {
			/* ignore */
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
	try {
		const soaResp = await queryDns(domain, 'SOA');
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

	// If no issues found
	if (findings.length === 0) {
		findings.push(getNsConfiguredFinding(nsRecords));
	}

	return buildCheckResult('ns', findings);
}
