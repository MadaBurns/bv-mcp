// SPDX-License-Identifier: MIT

/**
 * BIMI (Brand Indicators for Message Identification) check tool.
 * Queries TXT records at default._bimi.<domain> and validates
 * logo URL and authority evidence configuration.
 */

import { queryTxtRecords } from '../lib/dns';
import type { QueryDnsOptions } from '../lib/dns-types';
import type { CheckResult, Finding } from '../lib/scoring';
import { buildCheckResult, createFinding } from '../lib/scoring';

/**
 * Check BIMI records for a domain.
 * Validates the presence and configuration of BIMI TXT records,
 * including logo URL format and VMC authority evidence.
 */
export async function checkBimi(domain: string, dnsOptions?: QueryDnsOptions): Promise<CheckResult> {
	const findings: Finding[] = [];
	const bimiDomain = `default._bimi.${domain}`;
	const txtRecords = await queryTxtRecords(bimiDomain, dnsOptions);

	const bimiRecords = txtRecords.filter((r) => r.toLowerCase().startsWith('v=bimi1'));

	if (bimiRecords.length === 0) {
		// Check DMARC enforcement status to provide context
		const dmarcRecords = await queryTxtRecords(`_dmarc.${domain}`, dnsOptions);
		const dmarcRecord = dmarcRecords.find((r) => r.toLowerCase().startsWith('v=dmarc1'));
		const isEnforcing =
			dmarcRecord && (/\bp=reject\b/i.test(dmarcRecord) || /\bp=quarantine\b/i.test(dmarcRecord));

		if (!isEnforcing) {
			findings.push(
				createFinding(
					'bimi',
					'No BIMI record (DMARC not enforcing)',
					'info',
					`No BIMI record found at ${bimiDomain}. BIMI requires DMARC enforcement (p=quarantine or p=reject) before a BIMI record can be validated by mail clients. Set up DMARC enforcement first.`,
				),
			);
		} else {
			findings.push(
				createFinding(
					'bimi',
					'No BIMI record found',
					'low',
					`No BIMI record found at ${bimiDomain}. This domain has DMARC enforcement and is eligible for BIMI. Publishing a BIMI record allows email clients like Gmail and Apple Mail to display your brand logo next to your emails.`,
				),
			);
		}
		return buildCheckResult('bimi', findings);
	}

	if (bimiRecords.length > 1) {
		findings.push(
			createFinding(
				'bimi',
				'Multiple BIMI records',
				'medium',
				`Found ${bimiRecords.length} BIMI records at ${bimiDomain}. There should be exactly one BIMI record.`,
			),
		);
	}

	const bimi = bimiRecords[0];

	// Extract l= tag (logo URL)
	const logoMatch = bimi.match(/\bl=([^\s;]+)/i);
	const logoUrl = logoMatch?.[1];

	if (!logoUrl) {
		findings.push(
			createFinding(
				'bimi',
				'BIMI record missing logo URL',
				'medium',
				`BIMI record at ${bimiDomain} does not contain a logo URL (l= tag). The logo URL is required for email clients to display your brand indicator.`,
			),
		);
	} else {
		// Validate logo URL format
		const isHttps = logoUrl.toLowerCase().startsWith('https://');
		const isSvg = logoUrl.toLowerCase().endsWith('.svg');

		if (!isHttps || !isSvg) {
			const issues: string[] = [];
			if (!isHttps) issues.push('must use HTTPS');
			if (!isSvg) issues.push('must be an SVG file (SVG Tiny PS format)');
			findings.push(
				createFinding(
					'bimi',
					'BIMI logo URL invalid format',
					'medium',
					`BIMI logo URL "${logoUrl}" is invalid: ${issues.join(' and ')}. BIMI requires an HTTPS URL pointing to an SVG Tiny PS image.`,
				),
			);
		}
	}

	// Extract a= tag (VMC/authority evidence URL)
	const authMatch = bimi.match(/\ba=([^\s;]+)/i);
	const authUrl = authMatch?.[1];

	if (!authUrl) {
		findings.push(
			createFinding(
				'bimi',
				'No BIMI authority evidence (VMC)',
				'info',
				`BIMI record at ${bimiDomain} does not include an authority evidence URL (a= tag). A Verified Mark Certificate (VMC) is optional but required by Gmail to display your logo. Consider obtaining a VMC from a certificate authority like DigiCert or Entrust.`,
			),
		);
	} else {
		findings.push(
			createFinding(
				'bimi',
				'BIMI authority evidence present',
				'info',
				`BIMI record includes a Verified Mark Certificate (VMC) reference: ${authUrl}`,
			),
		);
	}

	// If logo URL is valid and present, add a positive finding
	if (logoUrl && logoUrl.toLowerCase().startsWith('https://') && logoUrl.toLowerCase().endsWith('.svg')) {
		findings.push(
			createFinding(
				'bimi',
				'BIMI record configured',
				'info',
				`BIMI record found and configured at ${bimiDomain} with a valid HTTPS SVG logo reference.`,
			),
		);
	}

	return buildCheckResult('bimi', findings);
}
