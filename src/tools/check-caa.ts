// SPDX-License-Identifier: MIT

/**
 * CAA (Certificate Authority Authorization) check tool.
 * Validates CAA DNS records that restrict which CAs can issue certificates.
 */

import { queryCaaRecords, type CaaRecord } from '../lib/dns';
import { type CheckResult, type Finding, buildCheckResult, createFinding } from '../lib/scoring';
import { getCaaConfiguredFinding, getCaaValidationFindings, summarizeCaaTags } from './caa-analysis';

/**
 * Check CAA records for a domain.
 * Validates that CAA records exist and are properly configured.
 */
export async function checkCaa(domain: string): Promise<CheckResult> {
	const findings: Finding[] = [];

	let caaRecords: CaaRecord[] = [];
	try {
		caaRecords = await queryCaaRecords(domain);
	} catch {
		findings.push(createFinding('caa', 'CAA query failed', 'medium', `Could not query CAA records for ${domain}.`));
		return buildCheckResult('caa', findings);
	}

	if (caaRecords.length === 0) {
		findings.push(
			createFinding(
				'caa',
				'No CAA records',
				'medium',
				`No CAA records found for ${domain}. CAA records restrict which Certificate Authorities can issue certificates for your domain, preventing unauthorized issuance.`,
			),
		);
		return buildCheckResult('caa', findings);
	}

	findings.push(...getCaaValidationFindings(summarizeCaaTags(caaRecords)));

	// If no issues found
	if (findings.length === 0) {
		findings.push(getCaaConfiguredFinding());
	}

	return buildCheckResult('caa', findings);
}
