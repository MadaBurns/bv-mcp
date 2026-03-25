// SPDX-License-Identifier: BUSL-1.1

/**
 * MX record check tool for MCP server.
 * Thin wrapper around @blackveil/dns-checks — delegates core logic to the shared package.
 * Adds provider detection post-processing on top of the package result.
 */

import { checkMX, createFinding } from '@blackveil/dns-checks';
import type { CheckResult } from '../lib/scoring';
import { queryDnsRecords, queryTxtRecords } from '../lib/dns';
import type { QueryDnsOptions } from '../lib/dns-types';
import { detectProviderMatches, loadProviderSignatures } from '../lib/provider-signatures';

export interface CheckMxOptions {
	providerSignaturesUrl?: string;
	providerSignaturesAllowedHosts?: string[];
	providerSignaturesSha256?: string;
}

function makeQueryDNS(dnsOptions?: QueryDnsOptions) {
	return async (domain: string, type: string): Promise<string[]> => {
		if (type === 'TXT') {
			return queryTxtRecords(domain, dnsOptions);
		}
		return queryDnsRecords(domain, type as Parameters<typeof queryDnsRecords>[1], dnsOptions);
	};
}

/** Check MX record configuration for a domain */
export async function checkMx(domain: string, options?: CheckMxOptions, dnsOptions?: QueryDnsOptions): Promise<CheckResult> {
	const timeout = dnsOptions?.timeoutMs ?? 5000;

	// Run core MX check from shared package
	const baseResult = await checkMX(
		domain,
		makeQueryDNS(dnsOptions),
		{ timeout },
	) as CheckResult;

	// Early return if MX check already returned critical/error findings (no MX records, etc.)
	// Only add provider detection when we have meaningful MX records
	const hasCritical = baseResult.findings.some((f) => f.severity === 'critical');
	const hasMediumQueryFailed = baseResult.findings.some((f) => f.title === 'DNS query failed');
	if (hasCritical || hasMediumQueryFailed) {
		return baseResult;
	}

	// Provider detection post-processing
	const findings = [...baseResult.findings];

	try {
		// Re-query MX records to get raw strings for provider matching
		const mxAnswers = await queryDnsRecords(domain, 'MX', dnsOptions);
		const mxTargets = mxAnswers.map((answer) => {
			const parts = answer.split(' ');
			return (parts.slice(1).join(' ') || '').replace(/\.$/, '').toLowerCase();
		}).filter(Boolean);

		if (mxTargets.length > 0) {
			const providerSignatures = await loadProviderSignatures({
				sourceUrl: options?.providerSignaturesUrl,
				allowedHosts: options?.providerSignaturesAllowedHosts,
				expectedSha256: options?.providerSignaturesSha256,
			});
			const inboundMatches = detectProviderMatches(mxTargets, providerSignatures.inbound);

			if (inboundMatches.length > 0) {
				const providerNames = inboundMatches.map((m) => m.provider).join(', ');
				const evidence = inboundMatches.map((m) => `${m.provider}: ${m.matches.join(', ')}`).join('; ');
				const providerConfidence = providerSignatures.source === 'runtime' ? 0.95 : providerSignatures.source === 'stale' ? 0.75 : 0.7;

				findings.push(
					createFinding('mx', 'Managed email provider detected', 'info', `Inbound provider(s): ${providerNames}. Evidence: ${evidence}.`, {
						detectionType: 'inbound',
						providers: inboundMatches.map((m) => ({ name: m.provider, matches: m.matches })),
						providerConfidence,
						signatureSource: providerSignatures.source,
						signatureVersion: providerSignatures.version,
						signatureFetchedAt: providerSignatures.fetchedAt,
					}) as (typeof findings)[0],
				);
			}

			if (providerSignatures.degraded) {
				findings.push(
					createFinding(
						'mx',
						'Provider signature source unavailable',
						'info',
						`Provider detection used ${providerSignatures.source === 'stale' ? 'stale cached' : 'built-in fallback'} signatures.`,
						{
							detectionType: 'inbound',
							providerConfidence: providerSignatures.source === 'stale' ? 0.55 : 0.45,
							signatureSource: providerSignatures.source,
							signatureVersion: providerSignatures.version,
							signatureFetchedAt: providerSignatures.fetchedAt,
						},
					) as (typeof findings)[0],
				);
			}
		}
	} catch {
		// Provider detection failure is non-critical — return base result
	}

	return { ...baseResult, findings };
}
