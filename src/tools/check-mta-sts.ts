/**
 * MTA-STS (Mail Transfer Agent Strict Transport Security) check tool.
 * Queries _mta-sts TXT records and validates the MTA-STS policy.
 */

import { HTTPS_TIMEOUT_MS } from '../lib/config';
import { queryMxRecords, queryTxtRecords } from '../lib/dns';
import { type CheckResult, type Finding, buildCheckResult, createFinding } from '../lib/scoring';
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

/**
 * Check MTA-STS configuration for a domain.
 * Queries _mta-sts.<domain> TXT records and optionally fetches the policy file.
 */
export async function checkMtaSts(domain: string): Promise<CheckResult> {
	let findings: Finding[] = [];

	// Check for _mta-sts TXT record
	let hasTxtRecord = false;
	try {
		const txtRecords = await queryTxtRecords(`_mta-sts.${domain}`);
		const txtAnalysis = getMtaStsTxtFindings(txtRecords);
		hasTxtRecord = txtAnalysis.hasTxtRecord;
		findings.push(...finalizeMissingMtaStsRecordFinding(txtAnalysis.findings, domain));
	} catch (err: unknown) {
		findings = [];
		const message = err instanceof Error ? err.message : 'Unknown error';
		findings.push(createFinding('mta_sts', 'MTA-STS DNS query failed', 'low', `Could not query MTA-STS TXT record for ${domain}. Error: ${message}`));
	}

	// Try to fetch the MTA-STS policy file
	if (hasTxtRecord) {
		try {
			const policyUrl = `https://mta-sts.${domain}/.well-known/mta-sts.txt`;
			const response = await fetch(policyUrl, {
				method: 'GET',
				signal: AbortSignal.timeout(HTTPS_TIMEOUT_MS),
			});

			if (!response.ok) {
				findings.push(
					createFinding(
						'mta_sts',
						'MTA-STS policy file not accessible',
						'high',
						`MTA-STS policy file at ${policyUrl} returned HTTP ${response.status}. The policy file must be accessible over HTTPS.`,
					),
				);
			} else {
				const body = await response.text();
				findings.push(...getMtaStsPolicyFindings(body, policyUrl));

				const policyMxPatterns = extractPolicyMxPatterns(body);
				const modeMatch = body.match(/mode:\s*(enforce|testing|none)/i);
				const policyMode = modeMatch ? modeMatch[1].toLowerCase() : '';
				if (policyMxPatterns.length > 0 && (policyMode === 'enforce' || policyMode === 'testing')) {
					try {
						const mxRecords = await queryMxRecords(domain);
						findings.push(...getUncoveredMxHostFindings(mxRecords.map((mx) => mx.exchange), policyMxPatterns));
					} catch {
						// MX query failed; skip coverage cross-check.
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
		const tlsrptRecords = await queryTxtRecords(`_smtp._tls.${domain}`);
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

	// If both records are missing, add a clear summary and suppress duplicate findings
	// But preserve DNS error findings so they are not masked
	if (shouldSummarizeMissingMailProtections(findings, hasTxtRecord, tlsRptChecked, hasTlsRptRecord)) {
		findings = [];
		findings.push(
			createFinding(
				'mta_sts',
				'No MTA-STS or TLS-RPT records found',
				'medium',
				`Neither MTA-STS nor TLS-RPT records are present for ${domain}. This is normal for domains that do not accept inbound email, but consider adding these records if you operate a mail server.`,
			),
		);
	}

	return buildCheckResult('mta_sts', findings);
}
