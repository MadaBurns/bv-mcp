// SPDX-License-Identifier: BUSL-1.1

/**
 * BIMI (Brand Indicators for Message Identification) check.
 * Queries TXT records at default._bimi.<domain> and validates
 * logo URL and authority evidence configuration.
 *
 * Copyright (c) 2023-2026 BlackVeil Security Ltd.
 * Licensed under BSL 1.1
 */

import type { CheckResult, DNSQueryFunction, FetchFunction, Finding } from '../types';
import { buildCheckResult, createFinding } from '../check-utils';

/** BIMI logo fetch timeout (ms). */
const BIMI_FETCH_TIMEOUT_MS = 4_000;

/** BIMI group recommendation: logos should be ≤ 32 KB. */
const BIMI_SVG_MAX_BYTES = 32 * 1024;

/**
 * Fetch and validate a BIMI SVG logo per the BIMI SVG Tiny PS specification.
 * Checks Content-Type, file size, baseProfile attribute, and absence of script tags.
 */
async function validateBimiSvg(logoUrl: string, fetchFn: FetchFunction, timeout: number): Promise<Finding[]> {
	const findings: Finding[] = [];

	try {
		const response = await fetchFn(logoUrl, {
			method: 'GET',
			redirect: 'manual',
			signal: AbortSignal.timeout(timeout),
		});

		if (response.status >= 300 && response.status < 400) {
			findings.push(
				createFinding(
					'bimi',
					'BIMI logo URL redirects',
					'low',
					`BIMI logo URL "${logoUrl}" returns a redirect (HTTP ${response.status}). The logo should be served directly without redirects.`,
				),
			);
			return findings;
		}

		if (!response.ok) {
			findings.push(
				createFinding(
					'bimi',
					'BIMI logo URL not accessible',
					'low',
					`BIMI logo URL "${logoUrl}" returned HTTP ${response.status}. The logo must be publicly accessible over HTTPS.`,
				),
			);
			return findings;
		}

		// Validate Content-Type
		const contentType = response.headers.get('content-type') ?? '';
		if (!contentType.toLowerCase().includes('image/svg+xml')) {
			findings.push(
				createFinding(
					'bimi',
					'BIMI logo wrong Content-Type',
					'medium',
					`BIMI logo at "${logoUrl}" is served with Content-Type "${contentType || '(none)'}". BIMI logos must be served as "image/svg+xml".`,
				),
			);
		}

		// Check Content-Length before fetching body
		const contentLength = parseInt(response.headers.get('content-length') ?? '0', 10);
		if (contentLength > BIMI_SVG_MAX_BYTES) {
			findings.push(
				createFinding(
					'bimi',
					'BIMI logo exceeds 32 KB',
					'low',
					`BIMI logo is ${Math.round(contentLength / 1024)} KB. The BIMI specification recommends logos be under 32 KB for reliable display in email clients.`,
				),
			);
			return findings;
		}

		const body = await response.text();

		if (body.length > BIMI_SVG_MAX_BYTES) {
			findings.push(
				createFinding(
					'bimi',
					'BIMI logo exceeds 32 KB',
					'low',
					`BIMI logo is ${Math.round(body.length / 1024)} KB. The BIMI specification recommends logos be under 32 KB for reliable display in email clients.`,
				),
			);
			return findings;
		}

		// Security check: script tags are prohibited in BIMI SVG
		if (/<script[\s>]/i.test(body)) {
			findings.push(
				createFinding(
					'bimi',
					'BIMI logo contains script tags',
					'high',
					`BIMI logo at "${logoUrl}" contains <script> elements. Scripts are prohibited in BIMI SVG files and will cause mail clients to reject the logo.`,
				),
			);
		}

		// Format check: SVG Tiny PS profile declaration required by BIMI spec
		if (!/baseProfile\s*=\s*["']tiny-ps["']/i.test(body)) {
			findings.push(
				createFinding(
					'bimi',
					'BIMI logo missing baseProfile="tiny-ps"',
					'medium',
					`BIMI logo at "${logoUrl}" does not declare baseProfile="tiny-ps". The BIMI specification requires SVG Tiny 1.2 Profile (PS subset). Add baseProfile="tiny-ps" to the root <svg> element.`,
				),
			);
		}

		if (findings.length === 0) {
			findings.push(
				createFinding(
					'bimi',
					'BIMI logo SVG validated',
					'info',
					`BIMI logo at "${logoUrl}" passed Content-Type, size, security, and SVG Tiny PS format checks.`,
				),
			);
		}
	} catch (err) {
		const isTimeout = err instanceof Error && (err.message.includes('timeout') || err.message.includes('abort'));
		findings.push(
			createFinding(
				'bimi',
				`BIMI logo fetch ${isTimeout ? 'timed out' : 'failed'}`,
				'low',
				`Could not fetch BIMI logo from "${logoUrl}". The logo URL must be publicly accessible over HTTPS.`,
			),
		);
	}

	return findings;
}

/**
 * Check BIMI records for a domain.
 * Validates the presence and configuration of BIMI TXT records,
 * including logo URL format and VMC authority evidence.
 */
export async function checkBIMI(
	domain: string,
	queryDNS: DNSQueryFunction,
	options?: { timeout?: number; fetchFn?: FetchFunction },
): Promise<CheckResult> {
	const timeout = options?.timeout ?? 5000;
	const fetchFn = options?.fetchFn;
	const findings: Finding[] = [];
	const bimiDomain = `default._bimi.${domain}`;
	const txtRecords = await queryDNS(bimiDomain, 'TXT', { timeout });

	// Concatenate all TXT records to handle cases where BIMI data is split across multiple records
	const concatenatedTxt = txtRecords.join('');

	// Extract BIMI record from concatenated TXT data
	const bimiMatch = concatenatedTxt.match(/v=bimi1[^]*/i);
	const bimiRecords = bimiMatch ? [bimiMatch[0]] : [];

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

	// Check for multiple BIMI records in the concatenated data
	const bimiMatches = concatenatedTxt.match(/v=bimi1/gi);
	if (bimiMatches && bimiMatches.length > 1) {
		findings.push(
			createFinding(
				'bimi',
				'Multiple BIMI records',
				'medium',
				`Found ${bimiMatches.length} BIMI records at ${bimiDomain}. There should be exactly one BIMI record.`,
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
				'low',
				`BIMI record at ${bimiDomain} does not include an authority evidence URL (a= tag). A Verified Mark Certificate (VMC) is required by Gmail and Apple Mail to display your brand logo. Without a VMC, BIMI logos will not appear in most major email clients. Obtain a VMC from DigiCert or Entrust.`,
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

	// If logo URL is valid and present, validate the SVG content
	if (logoUrl && logoUrl.toLowerCase().startsWith('https://') && logoUrl.toLowerCase().endsWith('.svg')) {
		if (fetchFn) {
			findings.push(...await validateBimiSvg(logoUrl, fetchFn, BIMI_FETCH_TIMEOUT_MS));
		} else {
			findings.push(
				createFinding(
					'bimi',
					'BIMI record configured',
					'info',
					`BIMI record found and configured at ${bimiDomain} with a valid HTTPS SVG logo reference.`,
				),
			);
		}
	}

	return buildCheckResult('bimi', findings);
}
