// SPDX-License-Identifier: BUSL-1.1

/**
 * SubdoMailing check.
 * Detects the SubdoMailing attack vector where SPF include/redirect domains
 * can be taken over via dangling CNAME, hijackable NS delegation, or expired domains.
 *
 * Reference: Guardio Labs SubdoMailing report (Feb 2024).
 *
 * Copyright (c) 2023-2026 BlackVeil Security Ltd.
 * Licensed under BSL 1.1
 */

import type { CheckResult, DNSQueryFunction, Finding } from '../types';
import { buildCheckResult, createFinding } from '../check-utils';
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

	// Extract all SPF include/redirect domains recursively
	let chainResult: { domains: Map<string, string>; spfRecord: string | null };
	try {
		chainResult = await extractSpfIncludeChain(domain, queryDNS, { timeout });
	} catch {
		findings.push(createFinding('subdomailing', 'SubdoMailing check failed', 'medium', `Could not resolve SPF include chain for ${domain}.`));
		return buildCheckResult('subdomailing', findings);
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
	const riskFindings = await probeAllIncludes(chainResult.domains, queryDNS, { timeout });
	findings.push(...riskFindings);

	// If no risks found, add a passing finding
	if (findings.length === 0) {
		findings.push(
			createFinding(
				'subdomailing',
				'No SubdoMailing risk detected',
				'info',
				`Analyzed ${chainResult.domains.size} SPF include/redirect domain(s) for ${domain}. All resolve correctly with no takeover indicators.`,
				{ includeCount: chainResult.domains.size },
			),
		);
	}

	return buildCheckResult('subdomailing', findings);
}
