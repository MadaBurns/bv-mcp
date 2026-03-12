// SPDX-License-Identifier: MIT

/**
 * MX record check tool for MCP server.
 * Validates presence and quality of MX records for a domain.
 * Returns CheckResult with findings including RFC compliance, redundancy, and provider detection.
 */
import type { CheckResult, Finding } from '../lib/scoring';
import { createFinding, buildCheckResult } from '../lib/scoring';
import { queryDnsRecords } from '../lib/dns';
import type { QueryDnsOptions } from '../lib/dns-types';
import { detectProviderMatches, loadProviderSignatures } from '../lib/provider-signatures';
import { getIpTargetFindings, getNullMxFinding, getPresenceFinding, getSingleMxFinding, isNullMxRecord, parseMxRecords } from './mx-analysis';

export interface CheckMxOptions {
	providerSignaturesUrl?: string;
	providerSignaturesAllowedHosts?: string[];
	providerSignaturesSha256?: string;
}

/** Check MX record configuration for a domain */
export async function checkMx(domain: string, options?: CheckMxOptions, dnsOptions?: QueryDnsOptions): Promise<CheckResult> {
	let answers;
	try {
		answers = await queryDnsRecords(domain, 'MX', dnsOptions);
	} catch {
		return buildCheckResult('mx', [createFinding('mx', 'DNS query failed', 'medium', 'MX record lookup failed')]);
	}

	if (!answers || answers.length === 0) {
		return buildCheckResult('mx', [
			createFinding(
				'mx',
				'No MX records found',
				'medium',
				'No mail exchange records present. If this domain does not handle email, consider publishing a null MX record (RFC 7505).',
			),
		]);
	}

	const findings: Finding[] = [];

	const mxRecords = parseMxRecords(answers);

	// Check for null MX (RFC 7505: priority 0, exchange ".")
	const nullMx = mxRecords.find(isNullMxRecord);
	if (nullMx) {
		findings.push(getNullMxFinding());
		return buildCheckResult('mx', findings);
	}

	findings.push(getPresenceFinding(mxRecords));

	findings.push(...getIpTargetFindings(mxRecords));

	// Check for dangling MX records (hostnames that don't resolve)
	const ipPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
	const hostnameRecords = mxRecords.filter((r) => !ipPattern.test(r.exchange));
	const resolutions = await Promise.all(
		hostnameRecords.map(async (r) => {
			try {
				const [a, aaaa] = await Promise.all([
					queryDnsRecords(r.exchange, 'A', dnsOptions).catch(() => []),
					queryDnsRecords(r.exchange, 'AAAA', dnsOptions).catch(() => []),
				]);
				return { record: r, resolved: a.length > 0 || aaaa.length > 0 };
			} catch {
				return { record: r, resolved: false };
			}
		}),
	);
	for (const { record, resolved } of resolutions) {
		if (!resolved) {
			findings.push(
				createFinding(
					'mx',
					'Dangling MX record',
					'medium',
					`MX target "${record.exchange}" does not resolve to any A or AAAA record. Mail delivery to this host will fail.`,
				),
			);
		}
	}

	// Check for single MX (no redundancy)
	const singleMxFinding = getSingleMxFinding(mxRecords);
	if (singleMxFinding) {
		findings.push(singleMxFinding);
	}

	// Duplicate MX priorities are valid and commonly used for load balancing.

	const mxTargets = mxRecords.map((r) => r.exchange);
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
			}),
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
			),
		);
	}

	return buildCheckResult('mx', findings);
}
