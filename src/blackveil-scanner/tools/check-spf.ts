/**
 * SPF (Sender Policy Framework) check tool for BLACKVEIL Scanner npm package.
 * Queries TXT records for SPF and validates the policy.
 */

import { queryTxtRecords } from '../lib/dns';
import { buildCheckResult, createFinding, type CheckResult, type Finding } from '../lib/scoring';

const RISKY_MECHANISMS = ['+all', '?all'];

/**
 * Check SPF records for a domain.
 * Looks for v=spf1 TXT records and validates their configuration.
 */
export async function checkSpf(domain: string): Promise<CheckResult> {
	const findings: Finding[] = [];
	const txtRecords = await queryTxtRecords(domain);

	const spfRecords = txtRecords.filter((r) => r.toLowerCase().startsWith('v=spf1'));

	if (spfRecords.length === 0) {
		findings.push(
			createFinding(
				'spf',
				'No SPF record found',
				'critical',
				`No SPF (v=spf1) TXT record found for ${domain}. Without SPF, any server can send email claiming to be from your domain.`,
			),
		);
		return buildCheckResult('spf', findings);
	}

	if (spfRecords.length > 1) {
		findings.push(
			createFinding(
				'spf',
				'Multiple SPF records',
				'high',
				`Found ${spfRecords.length} SPF records. RFC 7208 requires exactly one SPF record per domain. Multiple records cause unpredictable behavior.`,
			),
		);
	}

	const spf = spfRecords[0];

	const allMechanism = spf.match(/[+?~-]all/i);
	if (allMechanism) {
		const qualifier = allMechanism[0];
		if (RISKY_MECHANISMS.includes(qualifier.toLowerCase())) {
			findings.push(
				createFinding(
					'spf',
					`Permissive SPF: ${qualifier}`,
					'critical',
					`SPF record uses "${qualifier}" which allows any server to send email as ${domain}. Use "-all" (hard fail) or "~all" (soft fail) instead.`,
				),
			);
		}
	}

	return buildCheckResult('spf', findings);
}
