// SPDX-License-Identifier: BUSL-1.1

/**
 * SubdoMailing check.
 * Detects the SubdoMailing attack vector where SPF include/redirect domains
 * can be taken over via dangling CNAME, hijackable NS delegation, or expired domains.
 *
 * Reference: Guardio Labs SubdoMailing report (Feb 2024).
 *
 * Copyright (c) 2023-2026 BLACKVEIL Security
 * Licensed under BUSL-1.1
 */

import type { CheckResult, DNSQueryFunction, Finding } from '../types';
import { buildCheckResult, buildNotAssessedResult, createFinding } from '../check-utils';
import { extractSpfIncludeChain, probeAllIncludes } from './subdomailing-analysis';

/**
 * Check for SubdoMailing risk by analyzing SPF include chain for takeover-vulnerable domains.
 *
 * Algorithm:
 * 1. Fetch SPF record and recursively extract all include/redirect domains (depth 3, cap 15)
 * 2. For each included domain, probe for dangling CNAME, hijackable NS, or void include
 * 3. Classify findings by risk type and severity
 */
export async function checkSubdomailing(
	domain: string,
	queryDNS: DNSQueryFunction,
	options?: { timeout?: number },
): Promise<CheckResult> {
	const timeout = options?.timeout ?? 5000;
	const findings: Finding[] = [];

	// Extract all SPF include/redirect domains recursively.
	// `extractSpfIncludeChain` throws when the ROOT domain's own TXT lookup throws (transport
	// error / timeout). That is not a measured "No SPF record", so it abstains here in the
	// not-assessed shape rather than scoring a verdict nobody measured (SQ-201; #1103 for the
	// include-level twin). A thrown lookup for an INCLUDED domain is still absorbed by the walk
	// and accounted by `probeAllIncludes`' unmeasured count below.
	let chainResult: { domains: Map<string, string>; spfRecord: string | null };
	try {
		chainResult = await extractSpfIncludeChain(domain, queryDNS, { timeout });
	} catch {
		return buildNotAssessedResult(
			'subdomailing',
			createFinding(
				'subdomailing',
				'SubdoMailing not assessed — SPF include chain could not be resolved',
				'info',
				`Could not resolve the SPF include chain for ${domain}. This is not evidence that the domain is free of SubdoMailing risk — the category is excluded from scoring rather than passed. Re-run the check once name resolution is working.`,
				{ inconclusive: true, errorKind: 'dns_error' },
			),
			'error',
		);
	}

	// No SPF record → not applicable
	if (!chainResult.spfRecord) {
		findings.push(
			createFinding('subdomailing', 'No SPF record', 'info', `No SPF record found for ${domain}. SubdoMailing analysis is not applicable.`),
		);
		return buildCheckResult('subdomailing', findings);
	}

	// No external includes → no SubdoMailing risk
	if (chainResult.domains.size === 0) {
		findings.push(
			createFinding('subdomailing', 'No external SPF includes', 'info', `SPF record for ${domain} has no include or redirect mechanisms. No SubdoMailing risk.`),
		);
		return buildCheckResult('subdomailing', findings);
	}

	// Probe all include domains for takeover risks
	const {
		findings: riskFindings,
		probedCount,
		unmeasuredCount,
		macroTemplateCount,
	} = await probeAllIncludes(chainResult.domains, queryDNS, { timeout });
	findings.push(...riskFindings);

	// Nothing in the chain could be assessed and at least one target was a macro template (#1200):
	// a template is deliberately never queried, so there is no measurement to pass. Abstain.
	if (macroTemplateCount > 0 && unmeasuredCount + macroTemplateCount === probedCount) {
		return buildNotAssessedResult(
			'subdomailing',
			createFinding(
				'subdomailing',
				'SubdoMailing not assessed — SPF includes are not resolvable out-of-band',
				'info',
				`No SPF include/redirect domain in the chain for ${domain} could be assessed: ${macroTemplateCount} macro-template include(s) (RFC 7208 §7) were not probed because only a receiving MTA can expand them, and ${unmeasuredCount} hit a DNS lookup that threw. This is not evidence that the domain is free of SubdoMailing risk — the category is excluded from scoring rather than passed.`,
				{ inconclusive: true, errorKind: 'dns_error', includeCount: probedCount, unmeasuredCount, macroTemplateCount },
			),
			'error',
		);
	}

	// Every include probe was unmeasured (a thrown lookup, never an answered-empty result) —
	// abstain rather than assert a clean verdict over a chain nothing actually resolved
	// (subdomain_takeover precedent, #956/#1006).
	if (unmeasuredCount > 0 && unmeasuredCount === probedCount) {
		return buildNotAssessedResult(
			'subdomailing',
			createFinding(
				'subdomailing',
				'SubdoMailing not assessed — every SPF include probe failed',
				'info',
				`No SPF include/redirect domain in the chain for ${domain} could be assessed: all ${probedCount} probe(s) hit a DNS lookup that threw rather than answering. This is not evidence that the domain is free of SubdoMailing risk — the category is excluded from scoring rather than passed. Re-run the check once name resolution is working.`,
				{ inconclusive: true, errorKind: 'dns_error', includeCount: probedCount },
			),
			'error',
		);
	}

	// If no risks found, add a passing finding — but don't claim full coverage when some
	// includes could not be queried (#1103).
	if (findings.length === 0) {
		findings.push(
			unmeasuredCount > 0 || macroTemplateCount > 0
				? createFinding(
						'subdomailing',
						'No SubdoMailing risk detected',
						'info',
						`Analyzed ${probedCount} SPF include/redirect domain(s) for ${domain}. ${probedCount - unmeasuredCount - macroTemplateCount} of ${probedCount} resolved with no takeover indicators${unmeasuredCount > 0 ? `; ${unmeasuredCount} could not be queried (DNS lookup failure) and are not confirmed safe` : ''}${macroTemplateCount > 0 ? `; ${macroTemplateCount} macro-template include(s) not probed (RFC 7208 §7: only a receiving MTA can expand them) and not confirmed safe` : ''}.`,
						{
							includeCount: probedCount,
							...(unmeasuredCount > 0 ? { unmeasuredCount } : {}),
							...(macroTemplateCount > 0 ? { macroTemplateCount } : {}),
						},
					)
				: createFinding(
						'subdomailing',
						'No SubdoMailing risk detected',
						'info',
						`Analyzed ${probedCount} SPF include/redirect domain(s) for ${domain}. All resolve correctly with no takeover indicators.`,
						{ includeCount: probedCount },
					),
		);
	}

	return buildCheckResult('subdomailing', findings);
}
