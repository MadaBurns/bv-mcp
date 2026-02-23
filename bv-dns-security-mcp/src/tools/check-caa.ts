/**
 * CAA (Certificate Authority Authorization) check tool.
 * Validates CAA DNS records that restrict which CAs can issue certificates.
 */

import { queryCaaRecords, type CaaRecord } from '../lib/dns';
import { type CheckResult, type Finding, buildCheckResult, createFinding } from '../lib/scoring';

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

	// Parse and validate CAA records
	let hasIssue = false;
	let hasIssuewild = false;
	let hasIodef = false;

	for (const record of caaRecords) {
		if (record.tag === 'issue') {
			hasIssue = true;
		}
		if (record.tag === 'issuewild') {
			hasIssuewild = true;
		}
		if (record.tag === 'iodef') {
			hasIodef = true;
		}
	}

	if (!hasIssue) {
		findings.push(
			createFinding(
				'caa',
				'No CAA issue tag',
				'medium',
				`CAA records exist but no "issue" tag found. The "issue" tag specifies which CAs are authorized to issue certificates.`,
			),
		);
	}

	if (!hasIssuewild) {
		findings.push(
			createFinding(
				'caa',
				'No CAA issuewild tag',
				'low',
				`No "issuewild" CAA tag found. Consider adding one to control wildcard certificate issuance separately.`,
			),
		);
	}

	if (!hasIodef) {
		findings.push(
			createFinding(
				'caa',
				'No CAA iodef tag',
				'low',
				`No "iodef" CAA tag found. The iodef tag specifies where CAs should report policy violations.`,
			),
		);
	}

	// If no issues found
	if (findings.length === 0) {
		findings.push(
			createFinding('caa', 'CAA properly configured', 'info', `CAA records found with issue, issuewild, and iodef tags configured.`),
		);
	}

	return buildCheckResult('caa', findings);
}
