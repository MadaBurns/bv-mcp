// SPDX-License-Identifier: BUSL-1.1

/**
 * DNSSEC (DNS Security Extensions) check tool.
 * Thin wrapper around @blackveil/dns-checks — delegates all logic to the shared package.
 */

import { checkDNSSEC } from '@blackveil/dns-checks';
import { queryDns, queryDnsRecords, queryTxtRecords } from '../lib/dns';
import type { QueryDnsOptions } from '../lib/dns-types';
import { buildCheckResult, createFinding } from '../lib/scoring';
import type { CheckResult } from '../lib/scoring';

export { parseDnskeyAlgorithm, parseDsRecord } from '@blackveil/dns-checks';

function makeQueryDNS(dnsOptions?: QueryDnsOptions) {
	return async (domain: string, type: string): Promise<string[]> => {
		if (type === 'TXT') {
			return queryTxtRecords(domain, dnsOptions);
		}
		return queryDnsRecords(domain, type as Parameters<typeof queryDnsRecords>[1], dnsOptions);
	};
}

/**
 * Check DNSSEC configuration for a domain.
 * Verifies the AD (Authenticated Data) flag, checks for DNSKEY/DS records,
 * and audits algorithm and digest type security.
 * Augments results with dnssecSource metadata: 'domain_configured' or 'tld_inherited'.
 */
export async function checkDnssec(domain: string, dnsOptions?: QueryDnsOptions): Promise<CheckResult> {
	const baseResult = await checkDNSSEC(
		domain,
		makeQueryDNS(dnsOptions),
		{
			timeout: dnsOptions?.timeoutMs ?? 5000,
			rawQueryDNS: async (d, type, dnssecFlag) => {
				const resp = await queryDns(d, type as Parameters<typeof queryDns>[1], dnssecFlag ?? false, dnsOptions);
				return { AD: resp.AD, Answer: resp.Answer };
			},
		},
	) as CheckResult;

	// Skip augmentation only when DNSSEC is definitively absent or the check failed
	const dnssecAbsent =
		baseResult.findings.some((f) => f.title === 'DNSSEC not enabled') ||
		baseResult.findings.some((f) => f.title === 'DNSSEC check failed');
	if (dnssecAbsent) {
		return baseResult;
	}

	// Detect whether the domain has its own DNSKEY/DS (domain_configured) or inherits from TLD
	const [dnskeyResult, dsResult] = await Promise.allSettled([
		queryDnsRecords(domain, 'DNSKEY', dnsOptions),
		queryDnsRecords(domain, 'DS', dnsOptions),
	]);

	const hasDnskey = dnskeyResult.status === 'fulfilled' && dnskeyResult.value.length > 0;
	const hasDs = dsResult.status === 'fulfilled' && dsResult.value.length > 0;
	const dnssecSource = hasDnskey && hasDs ? 'domain_configured' : 'tld_inherited';

	if (dnssecSource === 'tld_inherited') {
		const inheritedFinding = createFinding(
			'dnssec',
			'DNSSEC inherited from TLD',
			'info',
			`DNSSEC validation passes but ${domain} does not have its own DNSKEY or DS records. DNSSEC protection is inherited from the TLD registry, not configured by the domain owner.`,
			{ dnssecSource: 'tld_inherited' },
		);
		return buildCheckResult('dnssec', [...baseResult.findings, inheritedFinding]);
	}

	// domain_configured — tag the first non-info finding with the source, or add a carrier finding
	if (baseResult.findings.length > 0) {
		const [first, ...rest] = baseResult.findings;
		const tagged = { ...first, metadata: { ...(first.metadata ?? {}), dnssecSource: 'domain_configured' } };
		return buildCheckResult('dnssec', [tagged, ...rest]);
	}

	const configuredFinding = createFinding(
		'dnssec',
		'DNSSEC configured by domain owner',
		'info',
		`${domain} has DNSKEY and DS records — DNSSEC is explicitly configured by the domain owner.`,
		{ dnssecSource: 'domain_configured' },
	);
	return buildCheckResult('dnssec', [configuredFinding]);
}
