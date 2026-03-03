/**
 * DMARC (Domain-based Message Authentication, Reporting & Conformance) check tool.
 * Queries _dmarc TXT records and validates the policy.
 */

import { queryTxtRecords } from '../lib/dns';
import { type CheckResult, type Finding, buildCheckResult, createFinding } from '../lib/scoring';

/**
 * Check DMARC records for a domain.
 * Queries _dmarc.<domain> TXT records and validates policy configuration.
 */
export async function checkDmarc(domain: string): Promise<CheckResult> {
	const findings: Finding[] = [];
	const txtRecords = await queryTxtRecords(`_dmarc.${domain}`);

	// Filter for DMARC records
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

	// Check policy (p= tag)
	const policy = tags.get('p');
	if (!policy) {
		findings.push(
			createFinding(
				'dmarc',
				'Missing DMARC policy',
				'critical',
				`DMARC record is missing the required "p=" tag. Without a policy, DMARC provides no protection.`,
			),
		);
	} else if (policy === 'none') {
		findings.push(
			createFinding(
				'dmarc',
				'DMARC policy set to none',
				'high',
				`DMARC policy is "none" which only monitors but does not reject or quarantine spoofed emails. Consider upgrading to "quarantine" or "reject".`,
			),
		);
	} else if (policy === 'quarantine') {
		findings.push(
			createFinding(
				'dmarc',
				'DMARC policy set to quarantine',
				'low',
				`DMARC policy is "quarantine". Consider upgrading to "reject" for maximum protection once you've verified legitimate email flows.`,
			),
		);
	}
	// "reject" is the strongest setting - no finding needed

	// Check subdomain policy (sp= tag)
	const sp = tags.get('sp');
	if (!sp && policy === 'reject') {
		findings.push(
			createFinding(
				'dmarc',
				'No subdomain policy',
				'low',
				`No subdomain policy (sp=) specified. Subdomains inherit the main policy ("${policy}"), but explicitly setting sp= is recommended.`,
			),
		);
	}

	// Check percentage (pct= tag)
	const pct = tags.get('pct');
	if (pct && parseInt(pct, 10) < 100) {
		findings.push(
			createFinding(
				'dmarc',
				'DMARC not applied to all emails',
				'medium',
				`DMARC pct=${pct} means the policy only applies to ${pct}% of emails. Set pct=100 for full coverage.`,
			),
		);
	}

	// Check for reporting (rua= tag)
	const rua = tags.get('rua');
	if (!rua) {
		findings.push(
			createFinding(
				'dmarc',
				'No aggregate reporting',
				'medium',
				`No aggregate report URI (rua=) specified. Without reporting, you cannot monitor DMARC authentication results.`,
			),
		);
	}

	// If no issues found, add info
	if (findings.length === 0) {
		findings.push(
			createFinding(
				'dmarc',
				'DMARC properly configured',
				'info',
				`DMARC record found with policy "${policy}": ${dmarc.substring(0, 100)}${dmarc.length > 100 ? '...' : ''}`,
			),
		);
	}

	return buildCheckResult('dmarc', findings);
}

/** Parse DMARC tag-value pairs from a DMARC record string */
export function parseDmarcTags(record: string): Map<string, string> {
	const tags = new Map<string, string>();
	const parts = record.split(';');
	for (const part of parts) {
		const trimmed = part.trim();
		const eqIndex = trimmed.indexOf('=');
		if (eqIndex > 0) {
			const key = trimmed.substring(0, eqIndex).trim().toLowerCase();
			const value = trimmed
				.substring(eqIndex + 1)
				.trim()
				.toLowerCase();
			tags.set(key, value);
		}
	}
	return tags;
}
