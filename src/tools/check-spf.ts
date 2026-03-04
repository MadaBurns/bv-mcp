/**
 * SPF (Sender Policy Framework) check tool.
 * Queries TXT records for SPF and validates the policy.
 */

import { queryTxtRecords } from '../lib/dns';
import { type CheckResult, type Finding, buildCheckResult, createFinding } from '../lib/scoring';

/** Known risky SPF mechanisms that allow broad sending */
const RISKY_MECHANISMS = ['+all', '?all'];

type SpfLookupAnalysis = {
	count: number;
	mechanisms: string[];
};

/**
 * Count SPF mechanisms that consume DNS lookups.
 * RFC 7208 limits evaluation to 10 DNS-mechanism lookups.
 */
function analyzeSpfLookupBudget(spfRecord: string): SpfLookupAnalysis {
	const mechanisms: string[] = [];
	for (const token of spfRecord.split(/\s+/)) {
		if (!token) continue;
		const normalized = token.replace(/^[+\-~?]/, '').toLowerCase();
		if (normalized.startsWith('include:')) mechanisms.push('include');
		else if (normalized === 'a' || normalized.startsWith('a:') || normalized.startsWith('a/')) mechanisms.push('a');
		else if (normalized === 'mx' || normalized.startsWith('mx:') || normalized.startsWith('mx/')) mechanisms.push('mx');
		else if (normalized === 'ptr' || normalized.startsWith('ptr:')) mechanisms.push('ptr');
		else if (normalized.startsWith('exists:')) mechanisms.push('exists');
		else if (normalized.startsWith('redirect=')) mechanisms.push('redirect');
	}

	return { count: mechanisms.length, mechanisms };
}

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

	// Check DNS lookup budget (RFC 7208 max: 10)
	const lookupBudget = analyzeSpfLookupBudget(spf);
	if (lookupBudget.count > 10) {
		findings.push(
			createFinding(
				'spf',
				'Too many DNS lookups',
				'critical',
				`SPF record requires ${lookupBudget.count} DNS lookups (limit: 10). Receivers may return PermError and reject legitimate mail.`,
				{ ...spfMetadata, lookupCount: lookupBudget.count, lookupMechanisms: lookupBudget.mechanisms },
			),
		);
	} else if (lookupBudget.count >= 9) {
		findings.push(
			createFinding(
				'spf',
				'SPF lookup budget near limit',
				'high',
				`SPF record requires ${lookupBudget.count}/10 DNS lookups. Any future sender additions may push this domain into permanent SPF failures.`,
				{ ...spfMetadata, lookupCount: lookupBudget.count, lookupMechanisms: lookupBudget.mechanisms },
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
