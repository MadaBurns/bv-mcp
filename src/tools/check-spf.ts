/**
 * SPF (Sender Policy Framework) check tool.
 * Queries TXT records for SPF and validates the policy.
 */

import { queryTxtRecords } from '../lib/dns';
import { type CheckResult, type Finding, buildCheckResult, createFinding } from '../lib/scoring';

/** Known risky SPF mechanisms that allow broad sending */
const RISKY_MECHANISMS = ['+all', '?all'];

function extractSpfSignalDomains(spfRecord: string): { includeDomains: string[]; redirectDomain?: string } {
	const includeDomains = Array.from(spfRecord.matchAll(/\binclude:([^\s]+)/gi))
		.map((m) => m[1].trim().toLowerCase())
		.filter((d) => d.length > 0);

	const redirectMatch = spfRecord.match(/\bredirect=([^\s]+)/i);
	const redirectDomain = redirectMatch?.[1]?.trim().toLowerCase();

	return {
		includeDomains,
		...(redirectDomain ? { redirectDomain } : {}),
	};
}

/**
 * Check SPF records for a domain.
 * Looks for v=spf1 TXT records and validates their configuration.
 */
export async function checkSpf(domain: string): Promise<CheckResult> {
	const findings: Finding[] = [];
	const txtRecords = await queryTxtRecords(domain);

	// Filter for SPF records
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
	const spfSignals = extractSpfSignalDomains(spf);
	const spfMetadata = {
		signalType: 'spf',
		includeDomains: spfSignals.includeDomains,
		...(spfSignals.redirectDomain ? { redirectDomain: spfSignals.redirectDomain } : {}),
	};

	// Check for overly permissive +all or ?all
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
					spfMetadata,
				),
			);
		} else if (qualifier.toLowerCase() === '~all') {
			findings.push(
				createFinding(
					'spf',
					'SPF soft fail (~all)',
					'low',
					`SPF record uses "~all" (soft fail). Consider upgrading to "-all" (hard fail) for stricter enforcement once you've verified all legitimate senders are included.`,
					spfMetadata,
				),
			);
		}
		// -all is the recommended setting, no finding needed
	} else {
		findings.push(
			createFinding(
				'spf',
				"No 'all' mechanism",
				'medium',
				`SPF record does not end with an "all" mechanism. Without it, the default behavior is neutral, which provides weak protection.`,
				spfMetadata,
			),
		);
	}

	// Check for too many DNS lookups (max 10 per RFC 7208)
	const lookupMechanisms = spf.match(/\b(include:|a:|mx:|ptr:|exists:|redirect=)/gi);
	if (lookupMechanisms && lookupMechanisms.length > 10) {
		findings.push(
			createFinding(
				'spf',
				'Too many DNS lookups',
				'high',
				`SPF record contains ${lookupMechanisms.length} DNS lookup mechanisms. RFC 7208 limits SPF to 10 DNS lookups. Exceeding this causes permanent errors.`,
				spfMetadata,
			),
		);
	}

	// Check for deprecated ptr mechanism
	if (/\bptr\b/i.test(spf)) {
		findings.push(
			createFinding(
				'spf',
				'Deprecated ptr mechanism',
				'medium',
				`SPF record uses the "ptr" mechanism which is deprecated in RFC 7208 due to performance and reliability issues.`,
				spfMetadata,
			),
		);
	}

	// If no issues found, add an info finding
	if (findings.length === 0) {
		findings.push(
			createFinding(
				'spf',
				'SPF record configured',
				'info',
				`SPF record found and properly configured: ${spf.substring(0, 100)}${spf.length > 100 ? '...' : ''}`,
				spfMetadata,
			),
		);
	}

	return buildCheckResult('spf', findings);
}
