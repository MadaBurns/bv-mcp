// SPDX-License-Identifier: MIT

/**
 * TLS-RPT (SMTP TLS Reporting) check tool.
 * Queries TXT records at _smtp._tls.<domain> and validates
 * reporting configuration per RFC 8460.
 */

import { queryTxtRecords } from '../lib/dns';
import type { QueryDnsOptions } from '../lib/dns-types';
import type { CheckResult, Finding } from '../lib/scoring';
import { buildCheckResult, createFinding } from '../lib/scoring';

/**
 * Check TLS-RPT records for a domain.
 * Validates the presence and configuration of SMTP TLS Reporting records.
 */
export async function checkTlsrpt(domain: string, dnsOptions?: QueryDnsOptions): Promise<CheckResult> {
	const findings: Finding[] = [];
	const tlsrptDomain = `_smtp._tls.${domain}`;
	const txtRecords = await queryTxtRecords(tlsrptDomain, dnsOptions);

	const tlsrptRecords = txtRecords.filter((r) => r.toLowerCase().startsWith('v=tlsrptv1'));

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

	if (tlsrptRecords.length > 1) {
		findings.push(
			createFinding(
				'tlsrpt',
				'Multiple TLS-RPT records',
				'medium',
				`Found ${tlsrptRecords.length} TLS-RPT records at ${tlsrptDomain}. There should be exactly one TLS-RPT record per domain.`,
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
