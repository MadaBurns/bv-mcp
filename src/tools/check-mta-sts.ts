/**
 * MTA-STS (Mail Transfer Agent Strict Transport Security) check tool.
 * Queries _mta-sts TXT records and validates the MTA-STS policy.
 */

import { queryTxtRecords } from '../lib/dns';
import { type CheckResult, type Finding, buildCheckResult, createFinding } from '../lib/scoring';

/**
 * Check MTA-STS configuration for a domain.
 * Queries _mta-sts.<domain> TXT records and optionally fetches the policy file.
 */
export async function checkMtaSts(domain: string): Promise<CheckResult> {
	const findings: Finding[] = [];

	// Check for _mta-sts TXT record
	let hasTxtRecord = false;
	   try {
		   const txtRecords = await queryTxtRecords(`_mta-sts.${domain}`);
		   const mtaStsRecords = txtRecords.filter((r) => r.toLowerCase().startsWith('v=stsv1'));

			  if (mtaStsRecords.length === 0) {
				  findings.push(
					  createFinding(
						  'mta_sts',
						  'No MTA-STS record found',
						  'medium',
						  `No MTA-STS TXT record found at _mta-sts.${domain}. MTA-STS enforces TLS for incoming email, preventing downgrade attacks.`,
					  ),
				  );
			  } else {
			   hasTxtRecord = true;

			   if (mtaStsRecords.length > 1) {
				   findings.push(
					   createFinding(
						   'mta_sts',
						   'Multiple MTA-STS records',
						   'medium',
						   `Found ${mtaStsRecords.length} MTA-STS records. Only one should exist.`,
					   ),
				   );
			   }

			   // Check for id= tag
			   const record = mtaStsRecords[0];
			   if (!record.includes('id=')) {
				   findings.push(
					   createFinding(
						   'mta_sts',
						   'MTA-STS missing id tag',
						   'medium',
						   `MTA-STS record is missing the "id=" tag. This tag is required for policy versioning.`,
					   ),
				   );
			   }
		   }
	   } catch (err: unknown) {
		   findings.length = 0;
		   const message = err instanceof Error ? err.message : 'Unknown error';
		   findings.push(createFinding('mta_sts', 'MTA-STS DNS query failed', 'low', `Could not query MTA-STS TXT record for ${domain}. Error: ${message}`));
	   }

	// Try to fetch the MTA-STS policy file
	if (hasTxtRecord) {
		try {
			const policyUrl = `https://mta-sts.${domain}/.well-known/mta-sts.txt`;
			const response = await fetch(policyUrl, {
				method: 'GET',
				signal: AbortSignal.timeout(10_000),
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

				// Check policy mode
				const modeMatch = body.match(/mode:\s*(enforce|testing|none)/i);
				if (!modeMatch) {
					findings.push(
						createFinding(
							'mta_sts',
							'MTA-STS policy missing mode',
							'high',
							`MTA-STS policy file does not contain a valid "mode:" directive.`,
						),
					);
				} else if (modeMatch[1].toLowerCase() === 'testing') {
					findings.push(
						createFinding(
							'mta_sts',
							'MTA-STS in testing mode',
							'low',
							`MTA-STS policy is in "testing" mode. Consider switching to "enforce" once verified.`,
						),
					);
				} else if (modeMatch[1].toLowerCase() === 'none') {
					findings.push(
						createFinding(
							'mta_sts',
							'MTA-STS policy disabled',
							'medium',
							`MTA-STS policy mode is "none", effectively disabling MTA-STS protection.`,
						),
					);
				}

				// Check for mx entries
				if (!body.includes('mx:')) {
					findings.push(
						createFinding(
							'mta_sts',
							'MTA-STS policy missing MX entries',
							'high',
							`MTA-STS policy file does not contain any "mx:" entries. At least one MX pattern is required.`,
						),
					);
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
			const validRecords = tlsrptRecords.filter((r) => r.toLowerCase().startsWith('v=tlsrptv1'));
			if (validRecords.length === 0) {
				findings.push(
					createFinding(
						'mta_sts',
						'TLS-RPT record missing',
						'low',
						`No TLS-RPT record found at _smtp._tls.${domain}. Consider adding a TLS-RPT record for reporting SMTP TLS issues.`,
					),
				);
			} else {
				hasTlsRptRecord = true;
			}
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
		if (!hasTxtRecord && tlsRptChecked && !hasTlsRptRecord) {
			findings.length = 0; // Remove any prior findings
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
