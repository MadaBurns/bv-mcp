/**
 * MX record check tool for MCP server.
 * Validates presence and quality of MX records for a domain.
 * Returns CheckResult with findings including RFC compliance, redundancy, and provider detection.
 */
import type { CheckResult, Finding } from '../lib/scoring';
import { createFinding, buildCheckResult } from '../lib/scoring';
import { queryDnsRecords } from '../lib/dns';
import { detectProviderMatches, loadProviderSignatures } from '../lib/provider-signatures';

interface CheckMxOptions {
	providerSignaturesUrl?: string;
	providerSignaturesAllowedHosts?: string[];
	providerSignaturesSha256?: string;
}

/** Check MX record configuration for a domain */
export async function checkMx(domain: string, options?: CheckMxOptions): Promise<CheckResult> {
	let answers;
	try {
		answers = await queryDnsRecords(domain, 'MX');
	} catch {
		return buildCheckResult('mx', [createFinding('mx', 'DNS query failed', 'high', 'MX record lookup failed')]);
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

	// Parse MX records into priority + exchange pairs
	const mxRecords = answers.map((a) => {
		const parts = a.split(' ');
		const priority = parseInt(parts[0], 10);
		const exchange = (parts.slice(1).join(' ') || '').replace(/\.$/, '').toLowerCase();
		return { priority, exchange, raw: a };
	});

	// Check for null MX (RFC 7505: priority 0, exchange ".")
	const nullMx = mxRecords.find((r) => r.exchange === '' || r.exchange === '.');
	if (nullMx) {
		findings.push(
			createFinding('mx', 'Null MX record (RFC 7505)', 'info', 'Domain explicitly declares it does not accept email via null MX record.'),
		);
		return buildCheckResult('mx', findings);
	}

	findings.push(createFinding('mx', 'MX records found', 'info', `${mxRecords.length} mail exchange record(s) present.`));

	// Check for MX pointing to IP address (invalid per RFC 5321 §5.1)
	const ipPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
	for (const mx of mxRecords) {
		if (ipPattern.test(mx.exchange)) {
			findings.push(
				createFinding(
					'mx',
					'MX points to IP address',
					'high',
					`MX record "${mx.raw}" points to an IP address. MX targets must be hostnames per RFC 5321.`,
				),
			);
		}
	}

	// Check for single MX (no redundancy)
	if (mxRecords.length === 1) {
		findings.push(createFinding('mx', 'Single MX record', 'low', 'Only one MX record found. Consider adding a backup MX for redundancy.'));
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
