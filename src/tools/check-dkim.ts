// SPDX-License-Identifier: BUSL-1.1

/**
 * DKIM (DomainKeys Identified Mail) check tool.
 * Thin wrapper around @blackveil/dns-checks — delegates all logic to the shared package.
 * Retains applyProviderDkimContext for scan_domain post-processing.
 */

import { checkDKIM, createFinding, buildCheckResult } from '@blackveil/dns-checks';
import { makeQueryDNS } from '../lib/dns-query-adapter';
import type { QueryDnsOptions } from '../lib/dns-types';
import type { CheckResult } from '../lib/scoring';

/**
 * Email providers with high confidence of default DKIM signing.
 */
const HIGH_CONFIDENCE_DKIM_PROVIDERS = new Set([
	'amazon ses',
	'sendgrid',
	'mailgun',
	'postmark',
	'google workspace',
	'microsoft 365',
]);

/**
 * Email providers that typically sign with DKIM but vary by configuration.
 */
const MEDIUM_CONFIDENCE_DKIM_PROVIDERS = new Set(['proofpoint', 'mimecast']);

/**
 * Check DKIM records for a domain.
 * Probes common selectors at <selector>._domainkey.<domain>.
 * Optionally accepts a specific selector to check.
 */
export async function checkDkim(domain: string, selector?: string, dnsOptions?: QueryDnsOptions): Promise<CheckResult> {
	return checkDKIM(
		domain,
		makeQueryDNS(dnsOptions),
		{ timeout: dnsOptions?.timeoutMs ?? 5000, selector },
	) as Promise<CheckResult>;
}

/**
 * Apply provider-informed context to DKIM results.
 * Called as a post-processing step in scan_domain after MX-based provider detection completes.
 * When a known DKIM-signing provider is detected, downgrades the "No DKIM records found"
 * finding from HIGH to MEDIUM since the provider likely signs outbound mail by default.
 */
export function applyProviderDkimContext(dkimResult: CheckResult, provider: string): CheckResult {
	const normalizedProvider = provider.toLowerCase();
	const notFoundIdx = dkimResult.findings.findIndex(
		(f) => /No DKIM records found/i.test(f.title) && f.severity === 'high',
	);
	if (notFoundIdx === -1) return dkimResult;

	const selectorsChecked = (dkimResult.findings[notFoundIdx].metadata?.selectorsChecked as string[]) ?? [];
	const newFindings = [...dkimResult.findings];

	if (HIGH_CONFIDENCE_DKIM_PROVIDERS.has(normalizedProvider)) {
		newFindings[notFoundIdx] = createFinding(
			'dkim',
			'DKIM selector not discovered',
			'medium',
			`No DKIM selectors were found among the tested set, but ${provider} is detected as the email provider and signs outbound mail by default. DKIM is likely present with a custom selector.`,
			{
				confidence: 'heuristic',
				detectionMethod: 'provider-implied',
				provider: normalizedProvider,
				selectorsChecked,
			},
		);
	} else if (MEDIUM_CONFIDENCE_DKIM_PROVIDERS.has(normalizedProvider)) {
		newFindings[notFoundIdx] = createFinding(
			'dkim',
			'DKIM selector not discovered',
			'medium',
			`No DKIM selectors were found among the tested set. ${provider} is detected as the email provider and typically signs outbound mail.`,
			{
				confidence: 'heuristic',
				detectionMethod: 'provider-implied',
				provider: normalizedProvider,
				selectorsChecked,
			},
		);
		newFindings.push(
			createFinding(
				'dkim',
				'DKIM provider signing unverified',
				'low',
				`${provider} signing policy varies by configuration — DKIM presence cannot be confirmed without selector discovery.`,
				{ confidence: 'heuristic' },
			),
		);
	}

	return buildCheckResult('dkim', newFindings) as CheckResult;
}
