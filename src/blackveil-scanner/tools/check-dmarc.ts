/**
 * DMARC (Domain-based Message Authentication, Reporting & Conformance) check tool for BLACKVEIL Scanner npm package.
 * Queries _dmarc TXT records and validates the policy.
 */

import { queryTxtRecords } from '../lib/dns';
import { buildCheckResult, createFinding, type CheckResult, type Finding } from '../lib/scoring';

function parseDmarcTags(record: string): Map<string, string> {
	const tags = new Map<string, string>();
	for (const part of record.split(';')) {
		const [key, value] = part.trim().split('=');
		if (key && value) tags.set(key.trim(), value.trim());
	}
	return tags;
}

/**
 * Check DMARC records for a domain.
 * Queries _dmarc.<domain> TXT records and validates policy configuration.
 */
export async function checkDmarc(domain: string): Promise<CheckResult> {
	const findings: Finding[] = [];
	const txtRecords = await queryTxtRecords(`_dmarc.${domain}`);

	const dmarcRecords = txtRecords.filter((r) => r.toLowerCase().startsWith('v=dmarc1'));

	if (dmarcRecords.length === 0) {
		findings.push(
			createFinding(
				'dmarc',
				'No DMARC record found',
				'critical',
				`No DMARC record found at _dmarc.${domain}. Without DMARC, receivers cannot verify email authentication and spoofing is easier.`,
			),
		);
		return buildCheckResult('dmarc', findings);
	}

	if (dmarcRecords.length > 1) {
		findings.push(
			createFinding(
				'dmarc',
				'Multiple DMARC records',
				'high',
				`Found ${dmarcRecords.length} DMARC records. Only one DMARC record should exist per domain.`,
			),
		);
	}

	const dmarc = dmarcRecords[0];
	const tags = parseDmarcTags(dmarc);

	const policy = tags.get('p');
	if (!policy) {
		findings.push(
			createFinding(
				'dmarc',
				'Missing DMARC policy',
				'critical',
				`DMARC record is missing the required "p=" tag. Without a policy, DMARC provides no protection.`
			)
		);
	} else if (policy === 'none') {
		findings.push(
			createFinding(
				'dmarc',
				'DMARC policy is none',
				'medium',
				`DMARC policy is set to "none". ISPs aren't enforcing any policy on spoofed mail.`
			)
		);
	}

	return buildCheckResult('dmarc', findings);
}
