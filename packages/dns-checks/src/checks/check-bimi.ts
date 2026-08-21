// SPDX-License-Identifier: BUSL-1.1

/**
 * BIMI (Brand Indicators for Message Identification) check.
 * Queries TXT records at default._bimi.<domain> and validates
 * logo URL and authority evidence configuration.
 *
 * Copyright (c) 2023-2026 BLACKVEIL Security
 * Licensed under BUSL-1.1
 */

import type { CheckResult, DNSQueryFunction, FetchFunction, Finding } from '../types';
import { buildCheckResult, createFinding } from '../check-utils';
import { RobotsDisallowedError, describeRobotsScope, robotsAbstentionMetadata } from '../robots-gate';
import { isNoSendPolicy } from './spf-analysis';

/** BIMI logo fetch timeout (ms). */
const BIMI_FETCH_TIMEOUT_MS = 4_000;

/**
 * Best-effort probe for "this domain cannot send email".
 *
 * Reads the apex TXT RRset and looks for an SPF record with a no-send policy.
 * Fail-soft in every direction: a query failure, a missing SPF record, or any
 * SPF that authorizes a sender all return `false` (= "assume it may send"), so
 * the pre-existing wording is what a degraded lookup falls back to.
 */
async function detectNoSendPolicy(domain: string, queryDNS: DNSQueryFunction, timeout: number): Promise<boolean> {
	try {
		const txtRecords = await queryDNS(domain, 'TXT', { timeout });
		const spf = txtRecords.find((record) => record.toLowerCase().startsWith('v=spf1'));
		return spf ? isNoSendPolicy(spf) : false;
	} catch {
		return false;
	}
}

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
			// Consume the unread body so workerd doesn't cancel a "stalled HTTP response".
			void response.body?.cancel();
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
			void response.body?.cancel();
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
			void response.body?.cancel();
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
		if (err instanceof RobotsDisallowedError) {
			findings.push(
				createFinding(
					'bimi',
					'BIMI logo not independently validated (robots.txt)',
					'info',
					`${logoUrl} could not be fetched: the domain's robots.txt ${describeRobotsScope(err.scope)}. The BIMI record itself is still validated from DNS; only the logo file's own contents were not checked.`,
					robotsAbstentionMetadata(err.scope),
				),
			);
			return findings;
		}
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
 * including logo URL format and mark-certificate authority evidence.
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
	const isEnforcing = dmarcRecord && (/\bp=reject\b/i.test(dmarcRecord) || /\bp=quarantine\b/i.test(dmarcRecord));

	if (bimiRecords.length === 0) {
		if (!isEnforcing) {
			findings.push(
				createFinding(
					'bimi',
					'No BIMI record (DMARC not enforcing)',
					// BIMI is an advisory brand-display control (IETF draft, no RFC/NIST mandate),
					// so absence is NOT a deficiency → low, no missingControl. Score ~95. (The
					// DMARC-not-enforcing aspect belongs to the DMARC check, not double-counted here.)
					'low',
					`No BIMI record found at ${bimiDomain}. BIMI requires DMARC enforcement (p=quarantine or p=reject) before a BIMI record can be validated by mail clients. Set up DMARC enforcement first.`,
				),
			);
		} else {
			// DMARC is enforcing, which is BIMI's *prerequisite* — but it is not the
			// whole eligibility test. BIMI logos only ever render beside mail the
			// domain SENDS, so a domain that publishes an explicit no-send SPF policy
			// is not "eligible for BIMI" in any useful sense, and telling it to publish
			// a BIMI record is bad advice. Probe for that before recommending BIMI.
			// Severity is `low` on BOTH branches — this is a wording fix, not a
			// scoring change.
			const cannotSend = await detectNoSendPolicy(domain, queryDNS, timeout);
			findings.push(
				createFinding(
					'bimi',
					'No BIMI record found',
					// Advisory control — absence is not a deficiency → low, no missingControl (~95).
					'low',
					cannotSend
						? `No BIMI record found at ${bimiDomain}. This domain publishes an SPF policy that authorizes no senders ("-all" with no authorizing mechanisms), so it does not send email and BIMI is not applicable — BIMI logos are only displayed beside messages a domain sends. No action is needed unless this domain starts sending mail.`
						: `No BIMI record found at ${bimiDomain}. This domain has DMARC enforcement and is eligible for BIMI. Publishing a BIMI record allows email clients like Gmail and Apple Mail to display your brand logo next to your emails.`,
				),
			);
		}
		// No BIMI record observed → control absent.
		return buildCheckResult('bimi', findings, false, false);
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

	// Extract a= tag (mark-certificate / authority evidence URL).
	//
	// The a= tag carries a URL and nothing else. A Common Mark Certificate (CMC)
	// publishes it identically to a Verified Mark Certificate (VMC), and telling
	// the two apart would mean fetching and parsing the certificate — a live PKI
	// fetch this DNS check has no budget for. So this branch reports PRESENCE
	// only and must not name the certificate type. Wording-only: severities,
	// finding count and controlPresent/recordPresent are unchanged on both
	// branches, so no score moves (check-bimi-remediation-accuracy.test.ts).
	const authMatch = bimi.match(/\ba=([^\s;]+)/i);
	const authUrl = authMatch?.[1];

	if (!authUrl) {
		findings.push(
			createFinding(
				'bimi',
				'No BIMI authority evidence (VMC or CMC)',
				'low',
				`BIMI record at ${bimiDomain} does not include an authority evidence URL (a= tag). Gmail displays BIMI logos backed by either a Verified Mark Certificate (VMC) or the lower-cost Common Mark Certificate (CMC); Apple Mail accepts a VMC only. Without a mark certificate, BIMI logos will not appear in most major email clients. Both certificate types are issued by CAs such as DigiCert; check current issuers before purchasing, as the market changes.`,
			),
		);
	} else {
		findings.push(
			createFinding(
				'bimi',
				'BIMI authority evidence present',
				'info',
				`BIMI record includes a mark certificate reference (a= authority evidence): ${authUrl}. The certificate type is not determined from the URL alone.`,
			),
		);
	}

	// If logo URL is valid and present, validate the SVG content
	if (logoUrl && logoUrl.toLowerCase().startsWith('https://') && logoUrl.toLowerCase().endsWith('.svg')) {
		if (fetchFn) {
			findings.push(...(await validateBimiSvg(logoUrl, fetchFn, BIMI_FETCH_TIMEOUT_MS)));
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

	// controlPresent: a BIMI record exists AND DMARC is enforcing (the record can actually function).
	// A record published without DMARC enforcement is non-functional → not an active hardening signal.
	// recordPresent is the orthogonal publication question and is unconditionally true here: this
	// branch is only reached with a BIMI record in hand, DMARC enforcement notwithstanding.
	return buildCheckResult('bimi', findings, Boolean(isEnforcing), true);
}
