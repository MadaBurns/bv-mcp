// SPDX-License-Identifier: BUSL-1.1

/**
 * TLS-RPT (SMTP TLS Reporting) check.
 * Queries TXT records at _smtp._tls.<domain> and validates
 * reporting configuration per RFC 8460.
 *
 * Copyright (c) 2023-2026 BlackVeil Security Ltd.
 * Licensed under BSL 1.1
 */

import type { CheckResult, DNSQueryFunction, Finding } from '../types';
import { buildCheckResult, createFinding } from '../check-utils';

/**
 * Check TLS-RPT records for a domain.
 * Validates the presence and configuration of SMTP TLS Reporting records.
 */
export async function checkTLSRPT(
	domain: string,
	queryDNS: DNSQueryFunction,
	options?: { timeout?: number },
): Promise<CheckResult> {
	const timeout = options?.timeout ?? 5000;
	const findings: Finding[] = [];
	const tlsrptDomain = `_smtp._tls.${domain}`;
	const txtRecords = await queryDNS(tlsrptDomain, 'TXT', { timeout });

	// Concatenate all TXT records to handle cases where TLS-RPT data is split across multiple records
	const concatenatedTxt = txtRecords.join('');

	// Extract TLS-RPT record from concatenated TXT data
	const tlsrptMatch = concatenatedTxt.match(/v=tlsrptv1[^]*/i);
	const tlsrptRecords = tlsrptMatch ? [tlsrptMatch[0]] : [];

	if (tlsrptRecords.length === 0) {
		findings.push(
			createFinding(
				'tlsrpt',
				'No TLS-RPT record found',
				'low',
				`No TLS-RPT (v=TLSRPTv1) record found at ${tlsrptDomain}. TLS-RPT enables your domain to receive reports about SMTP TLS failures, complementing MTA-STS. Without it, you have no visibility into email delivery security issues.`,
			),
		);
		return buildCheckResult('tlsrpt', findings);
	}

	// Check for multiple TLS-RPT records in the concatenated data
	const tlsrptMatches = concatenatedTxt.match(/v=tlsrptv1/gi);
	if (tlsrptMatches && tlsrptMatches.length > 1) {
		findings.push(
			createFinding(
				'tlsrpt',
				'Multiple TLS-RPT records',
				'medium',
				`Found ${tlsrptMatches.length} TLS-RPT records at ${tlsrptDomain}. There should be exactly one TLS-RPT record per domain.`,
			),
		);
	}

	const record = tlsrptRecords[0];

	// Check for rua= tag
	const ruaMatch = record.match(/\brua=([^\s;]+)/i);
	if (!ruaMatch) {
		findings.push(
			createFinding(
				'tlsrpt',
				'TLS-RPT record missing reporting URI',
				'medium',
				`TLS-RPT record at ${tlsrptDomain} does not contain a reporting URI (rua= tag). Without a reporting destination, TLS failure reports cannot be delivered.`,
			),
		);
		return buildCheckResult('tlsrpt', findings);
	}

	const ruaValue = ruaMatch[1];
	// Split comma-separated URIs and validate each
	const uris = ruaValue.split(',').map((u) => u.trim());
	const invalidUris: string[] = [];

	for (const uri of uris) {
		if (!uri.toLowerCase().startsWith('mailto:') && !uri.toLowerCase().startsWith('https://')) {
			invalidUris.push(uri);
		}
	}

	if (invalidUris.length > 0) {
		findings.push(
			createFinding(
				'tlsrpt',
				'TLS-RPT invalid reporting URI scheme',
				'medium',
				`TLS-RPT reporting URI(s) use invalid scheme: ${invalidUris.join(', ')}. Only mailto: and https:// schemes are supported per RFC 8460.`,
			),
		);
	}

	// If record is valid
	if (invalidUris.length === 0 && tlsrptRecords.length <= 1) {
		findings.push(
			createFinding(
				'tlsrpt',
				'TLS-RPT record configured',
				'info',
				`TLS-RPT record found and configured at ${tlsrptDomain}: ${record.substring(0, 120)}${record.length > 120 ? '...' : ''}`,
			),
		);
	}

	return buildCheckResult('tlsrpt', findings);
}
