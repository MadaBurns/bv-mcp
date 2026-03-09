/**
 * DMARC (Domain-based Message Authentication, Reporting & Conformance) check tool.
 * Queries _dmarc TXT records and validates the policy.
 */

import { queryTxtRecords } from '../lib/dns';
import { type CheckResult, type Finding, buildCheckResult, createFinding } from '../lib/scoring';
import { checkRuaAuthorization, detectThirdPartyAggregators, isValidDmarcUri, parseDmarcTags } from './dmarc-utils';

export { parseDmarcTags } from './dmarc-utils';

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
	const validPolicies = new Set(['none', 'quarantine', 'reject']);

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
	} else if (!validPolicies.has(policy)) {
		findings.push(
			createFinding(
				'dmarc',
				'Invalid DMARC policy value',
				'high',
				`DMARC policy value "${policy}" is invalid. Allowed values are none, quarantine, or reject.`,
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
	} else if (!sp && policy === 'none') {
		findings.push(
			createFinding(
				'dmarc',
				'Subdomains inherit p=none policy',
				'info',
				'No subdomain policy (sp=) specified. Subdomains inherit the "none" policy, which provides no protection against spoofing.',
			),
		);
	} else if (sp) {
		if (!validPolicies.has(sp)) {
			findings.push(
				createFinding(
					'dmarc',
					'Invalid subdomain policy value',
					'medium',
					`DMARC subdomain policy value "${sp}" is invalid. Allowed values are none, quarantine, or reject.`,
				),
			);
		} else if (policy === 'reject' && sp === 'none') {
			findings.push(
				createFinding(
					'dmarc',
					'Subdomain policy weaker than parent policy',
					'high',
					'Subdomain policy is set to "none" while parent policy is "reject". This leaves subdomains vulnerable to spoofing.',
				),
			);
		} else if (policy === 'reject' && sp === 'quarantine') {
			findings.push(
				createFinding(
					'dmarc',
					'Subdomain policy weaker than parent policy',
					'low',
					'Subdomain policy is "quarantine" while parent policy is "reject". Consider using sp=reject for consistent enforcement.',
				),
			);
		} else if (policy === 'quarantine' && sp === 'none') {
			findings.push(
				createFinding(
					'dmarc',
					'Subdomain policy weaker than domain policy',
					'medium',
					'Subdomain policy is set to "none" while domain policy is "quarantine". Subdomains are unprotected against spoofing.',
				),
			);
		}
	}

	// Check percentage (pct= tag)
	const pct = tags.get('pct');
	if (pct) {
		const pctValue = Number.parseInt(pct, 10);
		if (!Number.isFinite(pctValue) || Number.isNaN(pctValue) || pctValue < 0 || pctValue > 100) {
			findings.push(
				createFinding(
					'dmarc',
					'Invalid DMARC percentage value',
					'medium',
					`DMARC pct value "${pct}" is invalid. Allowed range is 0-100.`,
				),
			);
		} else if (pctValue < 100) {
		findings.push(
			createFinding(
				'dmarc',
				'DMARC not applied to all emails',
				'medium',
				`DMARC pct=${pctValue} means the policy only applies to ${pctValue}% of emails. Set pct=100 for full coverage.`,
			),
		);
		}
	}

	// Check forensic failure reporting options (fo=)
	const fo = tags.get('fo');
	if (fo) {
		const allowedFoValues = new Set(['0', '1', 'd', 's']);
		const foValues = fo
			.split(':')
			.map((v) => v.trim())
			.filter((v) => v.length > 0);

		const invalidFo = foValues.filter((v) => !allowedFoValues.has(v));
		if (foValues.length === 0 || invalidFo.length > 0) {
			findings.push(
				createFinding(
					'dmarc',
					'Invalid DMARC failure reporting options',
					'medium',
					`DMARC fo value "${fo}" contains unsupported option(s): ${invalidFo.join(', ') || 'none'}. Allowed values: 0, 1, d, s.`,
				),
			);
		} else if (foValues.length === 1 && foValues[0] === '0') {
			findings.push(
				createFinding(
					'dmarc',
					'Limited DMARC failure reporting coverage',
					'low',
					'DMARC fo=0 only generates forensic reports when both SPF and DKIM fail. Consider fo=1 for broader failure visibility.',
				),
			);
		}
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
	} else {
		// Validate rua= URI format
		const ruaUris = rua.split(',').map((u) => u.trim());
		const invalidRuaUris = ruaUris.filter((uri) => !isValidDmarcUri(uri));
		if (invalidRuaUris.length > 0) {
			findings.push(
				createFinding(
					'dmarc',
					'Invalid aggregate report URI format',
					'medium',
					`DMARC aggregate report URI(s) invalid: ${invalidRuaUris.join(', ')}. Must use mailto: scheme.`,
				),
			);
		}

		// Check for third-party aggregator services
		const aggregators = detectThirdPartyAggregators(ruaUris);
		if (aggregators.length > 0) {
			findings.push(
				createFinding(
					'dmarc',
					'Third-party DMARC aggregator detected',
					'info',
					`Using third-party aggregator(s): ${aggregators.join(', ')}. Ensure these services are authorized to receive your DMARC reports.`,
					{ aggregators },
				),
			);
		}

		// Cross-domain RUA authorization check (RFC 7489 §7.1)
		const ruaAuthFindings = await checkRuaAuthorization(domain, ruaUris);
		findings.push(...ruaAuthFindings);
	}

	// Check forensic reporting (ruf= tag)
	const ruf = tags.get('ruf');
	if (ruf) {
		const rufUris = ruf.split(',').map((u) => u.trim());
		const invalidRufUris = rufUris.filter((uri) => !isValidDmarcUri(uri));
		if (invalidRufUris.length > 0) {
			findings.push(
				createFinding(
					'dmarc',
					'Invalid forensic report URI format',
					'medium',
					`DMARC forensic report URI(s) invalid: ${invalidRufUris.join(', ')}. Must use mailto: scheme.`,
				),
			);
		}
	} else if (rua) {
		// rua= is present but ruf= is not
		findings.push(
			createFinding(
				'dmarc',
				'No forensic reporting configured (ruf= absent)',
				'low',
				'Aggregate reporting (rua=) is configured but forensic reporting (ruf=) is not. Forensic reports provide detailed failure information useful for troubleshooting.',
			),
		);
	}

	// Check DKIM alignment mode (adkim= tag)
	const adkim = tags.get('adkim');
	if (adkim && adkim !== 'r' && adkim !== 's') {
		findings.push(
			createFinding(
				'dmarc',
				'Invalid DKIM alignment mode',
				'medium',
				`DMARC adkim value "${adkim}" is invalid. Allowed values are "r" (relaxed) or "s" (strict).`,
			),
		);
	} else if (!adkim || adkim === 'r') {
		findings.push(
			createFinding(
				'dmarc',
				'Relaxed DKIM alignment',
				'low',
				`DKIM alignment mode is relaxed (adkim=r or unset). Consider adkim=s (strict) for stronger authentication.`,
			),
		);
	}

	// Check SPF alignment mode (aspf= tag)
	const aspf = tags.get('aspf');
	if (aspf && aspf !== 'r' && aspf !== 's') {
		findings.push(
			createFinding(
				'dmarc',
				'Invalid SPF alignment mode',
				'medium',
				`DMARC aspf value "${aspf}" is invalid. Allowed values are "r" (relaxed) or "s" (strict).`,
			),
		);
	} else if (!aspf || aspf === 'r') {
		findings.push(
			createFinding(
				'dmarc',
				'Relaxed SPF alignment',
				'low',
				`SPF alignment mode is relaxed (aspf=r or unset). Consider aspf=s (strict) for stronger authentication.`,
			),
		);
	}

	// If no critical, high, or medium issues found, add info
	const hasSignificantIssues = findings.some((f) => f.severity === 'critical' || f.severity === 'high' || f.severity === 'medium');
	if (!hasSignificantIssues) {
		findings.push(
			createFinding(
				'dmarc',
				'DMARC properly configured',
				'info',
				`DMARC record found with policy "${policy}" and valid core tags.`,
			),
		);
	}

	return buildCheckResult('dmarc', findings);
}
