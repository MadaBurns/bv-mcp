// SPDX-License-Identifier: BUSL-1.1

/**
 * CAA (Certificate Authority Authorization) check.
 * Validates CAA DNS records that restrict which CAs can issue certificates.
 *
 * Copyright (c) 2023-2026 BLACKVEIL Security
 * Licensed under BUSL-1.1
 */

import type { CheckResult, DNSQueryFunction, Finding } from '../types';
import { buildCheckResult, createFinding } from '../check-utils';
import { type CaaRecord, parseCaaRecord, getCaaConfiguredFinding, getCaaValidationFindings, summarizeCaaTags } from './caa-analysis';

/**
 * Check CAA records for a domain.
 * Validates that CAA records exist and are properly configured.
 *
 * Queries CAA record type and parses the raw DNS data into structured records.
 */
export async function checkCAA(
	domain: string,
	queryDNS: DNSQueryFunction,
	options?: { timeout?: number },
): Promise<CheckResult> {
	const timeout = options?.timeout ?? 5000;
	const findings: Finding[] = [];

	let rawRecords: string[];
	try {
		rawRecords = await queryDNS(domain, 'CAA', { timeout });
	} catch {
		findings.push(createFinding('caa', 'CAA query failed', 'medium', `Could not query CAA records for ${domain}.`));
		return buildCheckResult('caa', findings);
	}

	// Parse raw CAA record data into structured records
	const caaRecords: CaaRecord[] = rawRecords
		.map(parseCaaRecord)
		.filter((record): record is CaaRecord => record !== null);

	if (caaRecords.length === 0) {
		// RFC 8659: absence of CAA means ANY CA may issue — a real defense-in-depth gap,
		// but NOT a zeroed control (CA/B-Forum hardening, not a NIST-DNS baseline). MEDIUM
		// (→85), no missingControl. Severity MUST stay medium: at high/critical the
		// "no … record" text would trip scoreIndicatesMissingControl and re-zero it.
		// (D3: a managed-CDN domain still owes a CAA record listing its CDN's CA.)
		findings.push(
			createFinding(
				'caa',
				'No CAA records',
				'medium',
				`No CAA records found for ${domain}. CAA records restrict which Certificate Authorities can issue certificates for your domain, preventing unauthorized issuance.`,
			),
		);
		// No CAA records observed → control absent (a query failure above leaves controlPresent undefined).
		return buildCheckResult('caa', findings, false);
	}

	findings.push(...getCaaValidationFindings(summarizeCaaTags(caaRecords)));

	// If no issues found
	if (findings.length === 0) {
		findings.push(getCaaConfiguredFinding());
	}

	// CAA records present → control present.
	return buildCheckResult('caa', findings, true);
}
