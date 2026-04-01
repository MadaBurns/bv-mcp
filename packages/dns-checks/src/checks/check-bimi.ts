// SPDX-License-Identifier: BUSL-1.1

/**
 * BIMI (Brand Indicators for Message Identification) check.
 * Queries TXT records at default._bimi.<domain> and validates
 * logo URL and authority evidence configuration.
 *
 * Copyright (c) 2023-2026 BlackVeil Security Ltd.
 * Licensed under BSL 1.1
 */

import type { CheckResult, DNSQueryFunction, Finding } from '../types';
import { buildCheckResult, createFinding } from '../check-utils';

/**
 * Check BIMI records for a domain.
 * Validates the presence and configuration of BIMI TXT records,
 * including logo URL format and VMC authority evidence.
 */
export async function checkBIMI(
	domain: string,
	queryDNS: DNSQueryFunction,
	options?: { timeout?: number },
): Promise<CheckResult> {
	const timeout = options?.timeout ?? 5000;
	const findings: Finding[] = [];
	const bimiDomain = `default._bimi.${domain}`;
	const txtRecords = await queryDNS(bimiDomain, 'TXT', { timeout });

	const bimiRecords = txtRecords.filter((r) => r.toLowerCase().startsWith('v=bimi1'));

	// Check DMARC enforcement status — BIMI requires p=quarantine or p=reject
	const dmarcRecords = await queryDNS(`_dmarc.${domain}`, 'TXT', { timeout });
	const dmarcRecord = dmarcRecords.find((r) => r.toLowerCase().startsWith('v=dmarc1'));
	const isEnforcing =
		dmarcRecord && (/\bp=reject\b/i.test(dmarcRecord) || /\bp=quarantine\b/i.test(dmarcRecord));

	if (bimiRecords.length === 0) {
		if (!isEnforcing) {
			findings.push(
				createFinding(
					'bimi',
					'No BIMI record (DMARC not enforcing)',
					'low',
					`No BIMI record found at ${bimiDomain}. BIMI requires DMARC enforcement (p=quarantine or p=reject) before a BIMI record can be validated by mail clients. Set up DMARC enforcement first.`,
					{ missingControl: true },
				),
			);
		} else {
			findings.push(
				createFinding(
					'bimi',
					'No BIMI record found',
					'low',
					`No BIMI record found at ${bimiDomain}. This domain has DMARC enforcement and is eligible for BIMI. Publishing a BIMI record allows email clients like Gmail and Apple Mail to display your brand logo next to your emails.`,
					{ missingControl: true },
				),
			);
		}
		return buildCheckResult('bimi', findings);
	}

	// BIMI record exists but DMARC is not enforcing — record is non-functional
	if (!isEnforcing) {
		findings.push(
			createFinding(
				'bimi',
				'BIMI record ineffective (DMARC not enforcing)',
				'medium',
				`BIMI record found at ${bimiDomain} but DMARC policy is not set to quarantine or reject. Mail clients will not display the BIMI logo until DMARC enforcement is enabled.`,
				{ missingControl: true },
			),
		);
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
