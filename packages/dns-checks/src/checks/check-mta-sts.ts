// SPDX-License-Identifier: BUSL-1.1

/**
 * MTA-STS (Mail Transfer Agent Strict Transport Security) check.
 * Queries _mta-sts TXT records and validates the MTA-STS policy.
 *
 * Copyright (c) 2023-2026 BLACKVEIL Security
 * Licensed under BUSL-1.1
 */

import type { CheckResult, DNSQueryFunction, FetchFunction, Finding, ZoneContext } from '../types';
import { buildCheckResult, createFinding } from '../check-utils';
import { isNullMxRecord, parseMxRecords } from './mx-analysis';
import {
	finalizeMissingMtaStsRecordFinding,
	finalizeMissingTlsRptRecordFinding,
	extractPolicyMxPatterns,
	getMtaStsPolicyFindings,
	getMtaStsTxtFindings,
	getTlsRptRecordFindings,
	getUncoveredMxHostFindings,
	shouldSummarizeMissingMailProtections,
} from './mta-sts-analysis';

/** Default HTTPS timeout (ms) */
const HTTPS_TIMEOUT_MS = 4_000;

/**
 * Parse MX records from raw DNS response strings.
 * MX data format: "priority exchange"
 */
function parseMxFromRaw(answers: string[]): Array<{ exchange: string }> {
	return answers.map((answer) => {
		const parts = answer.split(' ');
		const exchange = (parts.slice(1).join(' ') || '').replace(/\.$/, '').toLowerCase();
		return { exchange };
	});
}

/**
 * Check MTA-STS configuration for a domain.
 * Queries _mta-sts.<domain> TXT records and optionally fetches the policy file.
 */
export async function checkMTASTS(
	domain: string,
	queryDNS: DNSQueryFunction,
	options?: { timeout?: number; fetchFn?: FetchFunction; zone?: ZoneContext },
): Promise<CheckResult> {
	const timeout = options?.timeout ?? 5000;
	const fetchFn = options?.fetchFn;
	let findings: Finding[] = [];

	// Check for _mta-sts TXT record
	let hasTxtRecord = false;
	try {
		const txtRecords = await queryDNS(`_mta-sts.${domain}`, 'TXT', { timeout });
		const txtAnalysis = getMtaStsTxtFindings(txtRecords);
		hasTxtRecord = txtAnalysis.hasTxtRecord;
		findings.push(...finalizeMissingMtaStsRecordFinding(txtAnalysis.findings, domain));
	} catch {
		findings = [];
		findings.push(createFinding('mta_sts', 'MTA-STS DNS query failed', 'low', `Could not query MTA-STS TXT record for ${domain}.`));
	}

	// Try to fetch the MTA-STS policy file (only if fetch function provided)
	if (hasTxtRecord && fetchFn) {
		try {
			const policyUrl = `https://mta-sts.${domain}/.well-known/mta-sts.txt`;
			const response = await fetchFn(policyUrl, {
				method: 'GET',
				redirect: 'manual',
				signal: AbortSignal.timeout(HTTPS_TIMEOUT_MS),
			});

			if ([301, 302, 303, 307, 308].includes(response.status)) {
				findings.push(
					createFinding(
						'mta_sts',
						'MTA-STS policy redirects',
						'high',
						`MTA-STS policy file at ${policyUrl} returned HTTP ${response.status} redirect. The policy must be served directly at the well-known URL without redirects.`,
					),
				);
				// Body unread on this branch — release it so workerd doesn't cancel a stalled response.
				void response.body?.cancel();
			} else if (!response.ok) {
				findings.push(
					createFinding(
						'mta_sts',
						'MTA-STS policy file not accessible',
						'high',
						`MTA-STS policy file at ${policyUrl} returned HTTP ${response.status}. The policy file must be accessible over HTTPS.`,
					),
				);
				void response.body?.cancel();
			} else {
				const MAX_BODY_BYTES = 65_536; // 64 KB — RFC 8461 max for MTA-STS
				const contentLength = parseInt(response.headers?.get('content-length') ?? '0', 10);
				if (contentLength > MAX_BODY_BYTES) {
					findings.push(
						createFinding(
							'mta_sts',
							'MTA-STS policy file oversized',
							'high',
							`MTA-STS policy file at ${policyUrl} exceeds 64 KB (Content-Length: ${contentLength}). This is abnormally large for an MTA-STS policy and was not fetched.`,
						),
					);
					void response.body?.cancel();
				} else {
					const body = await response.text();
					if (body.length > MAX_BODY_BYTES) {
						findings.push(
							createFinding(
								'mta_sts',
								'MTA-STS policy file oversized',
								'high',
								`MTA-STS policy file at ${policyUrl} exceeds 64 KB. This is abnormally large for an MTA-STS policy and was not parsed.`,
							),
						);
					} else {
						findings.push(...getMtaStsPolicyFindings(body, policyUrl));

						const policyMxPatterns = extractPolicyMxPatterns(body);
						const modeMatch = body.match(/mode:\s*(enforce|testing|none)/i);
						const policyMode = modeMatch ? modeMatch[1].toLowerCase() : '';
						if (policyMxPatterns.length > 0 && (policyMode === 'enforce' || policyMode === 'testing')) {
							try {
								const mxAnswers = await queryDNS(domain, 'MX', { timeout });
								const mxRecords = parseMxFromRaw(mxAnswers);
								findings.push(
									...getUncoveredMxHostFindings(mxRecords.map((mx) => mx.exchange), policyMxPatterns),
								);
							} catch {
								// MX query failed; skip coverage cross-check.
							}
						}
					}
				}
			}
		} catch {
			findings.push(
				createFinding(
					'mta_sts',
					'MTA-STS policy fetch failed',
					'medium',
					`Could not fetch MTA-STS policy file from https://mta-sts.${domain}/.well-known/mta-sts.txt`,
				),
			);
		}
	}

	// Check for TLSRPT record
	let hasTlsRptRecord = false;
	let tlsRptChecked = false;
	try {
		const tlsrptRecords = await queryDNS(`_smtp._tls.${domain}`, 'TXT', { timeout });
		tlsRptChecked = true;
		const tlsRptAnalysis = getTlsRptRecordFindings(tlsrptRecords);
		hasTlsRptRecord = tlsRptAnalysis.hasTlsRptRecord;
		findings.push(...finalizeMissingTlsRptRecordFinding(tlsRptAnalysis.findings, domain));
	} catch {
		tlsRptChecked = true;
		findings.push(
			createFinding(
				'mta_sts',
				'TLS-RPT DNS query failed',
				'low',
				`Could not query TLS-RPT TXT record for ${domain}.`,
			),
		);
	}

	// If no issues found
	if (findings.length === 0) {
		findings.push(
			createFinding(
				'mta_sts',
				'MTA-STS properly configured',
				'info',
				`MTA-STS is properly configured for ${domain} with an accessible policy file.`,
			),
		);
	}

	// If both records are missing, add a clear summary and suppress duplicate findings.
	// Defect K (issue #264 sibling): branch the copy and severity on MX presence —
	// missing MTA-STS on a domain that DOES accept inbound mail is medium (real
	// risk), but on a domain with no inbound mail it's a low-severity informational
	// note. Without the branch, paypal/stripe-class domains (with real MX) get
	// the "do not accept inbound email" copy, which is factually wrong.
	if (shouldSummarizeMissingMailProtections(findings, hasTxtRecord, tlsRptChecked, hasTlsRptRecord)) {
		const hasMx = await detectInboundMail(domain, queryDNS, timeout);
		findings = [];
		findings.push(
			hasMx
				? createFinding(
						'mta_sts',
						'No MTA-STS or TLS-RPT records found',
						'medium',
						`${domain} accepts inbound email (MX records present) but has neither MTA-STS nor TLS-RPT configured. Sending MTAs cannot enforce TLS or report failures for mail to this domain.`,
						{ missingControl: true },
					)
				: createFinding(
						'mta_sts',
						'No MTA-STS or TLS-RPT records found',
						// No inbound MX → this domain does not receive mail, so missing MTA-STS
						// is NOT a deficiency (low, no missingControl → ~95). Penalizing a parked
						// domain here harder than for a missing optional control would be
						// inconsistent. The has-MX branch above keeps missingControl (real gap).
						'low',
						`Neither MTA-STS nor TLS-RPT records are present for ${domain}. This is normal for domains that do not accept inbound email, but consider adding these records if you operate a mail server.`,
					),
		);
	}

	// controlPresent: an MTA-STS policy record (_mta-sts TXT) was observed. TLS-RPT alone does not
	// count as MTA-STS, and a failed lookup leaves hasTxtRecord false (conservative: not credited).
	return buildCheckResult('mta_sts', findings, hasTxtRecord);
}

/**
 * Lightweight MX presence probe used by the missing-mail-protections summary
 * to branch its copy and severity. Returns `true` only when the domain has at
 * least one real (non-null, RFC 7505) MX record. Any DNS failure resolves to
 * `false` (treat as "no inbound mail") so a flaky lookup can't synthesise a
 * medium-severity finding out of nothing.
 */
async function detectInboundMail(domain: string, queryDNS: DNSQueryFunction, timeout: number): Promise<boolean> {
	try {
		const mxAnswers = await queryDNS(domain, 'MX', { timeout });
		const parsed = parseMxRecords(mxAnswers);
		return parsed.some((record) => !isNullMxRecord(record));
	} catch {
		return false;
	}
}
