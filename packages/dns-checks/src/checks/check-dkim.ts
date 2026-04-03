// SPDX-License-Identifier: BUSL-1.1

/**
 * DKIM (DomainKeys Identified Mail) check.
 * Queries common DKIM selector TXT records and validates configuration.
 *
 * Copyright (c) 2023-2026 BlackVeil Security Ltd.
 * Licensed under BSL 1.1
 */

import type { CheckResult, DNSQueryFunction, Finding } from '../types';
import { buildCheckResult, createFinding } from '../check-utils';
import { analyzeKeyStrength, consolidateSelectorProbeKeyStrengthFindings, getDkimTagValue } from './dkim-analysis';

/** Common DKIM selectors used by major email providers */
const COMMON_SELECTORS = [
	'default',
	'google',
	'20230601', // Google Workspace
	'selector1', // Microsoft 365
	'selector2', // Microsoft 365
	'k1', // Mailchimp
	's1',
	's2',
	'mail',
	'dkim',
	'amazonses', // Amazon SES
	'zoho', // Zoho Mail
];

/**
 * Check DKIM records for a domain.
 * Probes common selectors at <selector>._domainkey.<domain>.
 * Optionally accepts a specific selector to check.
 */
export async function checkDKIM(
	domain: string,
	queryDNS: DNSQueryFunction,
	options?: { timeout?: number; selector?: string },
): Promise<CheckResult> {
	const timeout = options?.timeout ?? 5000;
	const selector = options?.selector;
	const findings: Finding[] = [];
	const selectorsToCheck = selector ? [selector] : COMMON_SELECTORS;
	const foundSelectors: string[] = [];
	let hasValidKey = false;

	// Check each selector in parallel
	const results = await Promise.all(
		selectorsToCheck.map(async (sel) => {
			try {
				const records = await queryDNS(`${sel}._domainkey.${domain}`, 'TXT', { timeout });
				const dkimRecords = records.filter((r) => r.toLowerCase().includes('v=dkim1') || r.includes('p='));
				return { selector: sel, records: dkimRecords };
			} catch {
				return { selector: sel, records: [] };
			}
		}),
	);

	for (const result of results) {
		if (result.records.length > 0) {
			foundSelectors.push(result.selector);

			// Validate each DKIM record
			for (const record of result.records) {
				const isRevoked = /p=\s*;/i.test(record) || /p=\s*$/i.test(record);
				const publicKey = getDkimTagValue(record, 'p');

				// Check for empty public key (revoked)
				if (isRevoked) {
					findings.push(
						createFinding(
							'dkim',
							`Revoked DKIM key: ${result.selector}`,
							'medium',
							`DKIM selector "${result.selector}" has an empty public key (p=), indicating the key has been revoked.`,
						),
					);
				} else {
					hasValidKey = true;
				}

				// Check key type (should be rsa or ed25519)
				const keyTypeMatch = record.match(/k=([^;\s]+)/i);
				const parsedKeyType = keyTypeMatch ? keyTypeMatch[1].toLowerCase() : null;
				if (keyTypeMatch && !['rsa', 'ed25519'].includes(parsedKeyType!)) {
					findings.push(
						createFinding(
							'dkim',
							`Unknown DKIM key type: ${keyTypeMatch[1]}`,
							'medium',
							`DKIM selector "${result.selector}" uses unknown key type "${keyTypeMatch[1]}". Expected "rsa" or "ed25519".`,
						),
					);
				}

				// Check for testing mode
				if (/t=y/i.test(record)) {
					findings.push(
						createFinding(
							'dkim',
							`DKIM in testing mode: ${result.selector}`,
							'low',
							`DKIM selector "${result.selector}" is in testing mode (t=y). Verifiers may treat failures as non-fatal.`,
						),
					);
				}

				// Analyze key strength (only if key is valid/not revoked)
				if (!isRevoked && publicKey) {
					const declaredKeyType = parsedKeyType ?? 'rsa-default';
					const keyAnalysis = analyzeKeyStrength(publicKey, declaredKeyType);

					if (keyAnalysis.keyType === 'ed25519') {
						findings.push(
							createFinding(
								'dkim',
								`Ed25519 key detected: ${result.selector}`,
								'info',
								`DKIM selector "${result.selector}" uses Ed25519, a strong elliptic-curve key type.`,
								{
									keyType: 'ed25519',
									selector: result.selector,
								},
							),
						);
					} else if (keyAnalysis.keyType === 'unknown') {
						findings.push(
							createFinding(
								'dkim',
								`Short key material: ${result.selector}`,
								'medium',
								`DKIM selector "${result.selector}" has very short key material without a k= tag. Consider adding "k=ed25519" or "k=rsa" for clarity.`,
								{
									selector: result.selector,
								},
							),
						);
					} else if (keyAnalysis.keyType === 'rsa') {
						const severityMsg =
							keyAnalysis.strength === 'critical'
								? 'weak'
								: keyAnalysis.strength === 'high'
									? 'legacy'
									: keyAnalysis.strength === 'medium'
										? 'below recommended'
										: 'strong';
						const descriptions: Record<string, string> = {
							critical:
								`DKIM RSA key for "${result.selector}" is ${severityMsg} (~${keyAnalysis.bits} bits). Upgrade to 2048-bit RSA or use Ed25519 for better security.`,
							high: `DKIM RSA key for "${result.selector}" is ${severityMsg} (${keyAnalysis.bits} bits). Consider upgrading to 2048-bit RSA or Ed25519.`,
							medium: `DKIM RSA key for "${result.selector}" is ${severityMsg} (${keyAnalysis.bits} bits). Major providers recommend 4096-bit RSA or Ed25519.`,
							info: `DKIM RSA key for "${result.selector}" is strong (${keyAnalysis.bits} bits).`,
						};

						if (keyAnalysis.strength !== 'info') {
							findings.push(
								createFinding(
									'dkim',
									`${severityMsg.charAt(0).toUpperCase() + severityMsg.slice(1)} RSA key: ${result.selector}`,
									keyAnalysis.strength,
									descriptions[keyAnalysis.strength],
									{
										estimatedBits: keyAnalysis.bits,
										keyType: keyAnalysis.keyType,
										selector: result.selector,
									},
								),
							);
						}
					}
				}

				// Check for missing v= tag (should be v=DKIM1)
				const versionTag = getDkimTagValue(record, 'v');
				if (!versionTag) {
					findings.push(
						createFinding(
							'dkim',
							`Missing DKIM version tag: ${result.selector}`,
							'medium',
							`DKIM selector "${result.selector}" is missing the v= tag. Should be set to v=DKIM1.`,
						),
					);
				}

				// Check for deprecated SHA-1 hash algorithm (RFC 8301)
				// h= tag restricts which hash algorithms are accepted for this key.
				// If only sha1 is listed (no sha256), the key cannot verify modern DKIM signatures.
				const hashTag = getDkimTagValue(record, 'h');
				if (hashTag) {
					const hashAlgs = hashTag.split(':').map((h) => h.trim().toLowerCase()).filter(Boolean);
					if (hashAlgs.length > 0 && !hashAlgs.includes('sha256') && hashAlgs.includes('sha1')) {
						findings.push(
							createFinding(
								'dkim',
								`Deprecated hash algorithm (h=sha1): ${result.selector}`,
								'medium',
								`DKIM selector "${result.selector}" only accepts SHA-1 signatures (h=sha1). SHA-1 is deprecated for DKIM signing per RFC 8301. Add sha256 to the h= tag or remove the restriction.`,
							),
						);
					}
				}
			}
		}
	}

	// If multiple found selectors are ALL revoked and none have valid keys,
	// this is a non-sending domain posture — downgrade to info
	if (foundSelectors.length > 1 && !hasValidKey) {
		const revokedCount = findings.filter((f) => f.title.startsWith('Revoked DKIM key:')).length;
		// Remove individual revoked findings
		for (let i = findings.length - 1; i >= 0; i--) {
			if (findings[i].title.startsWith('Revoked DKIM key:')) {
				findings.splice(i, 1);
			}
		}
		findings.push(
			createFinding(
				'dkim',
				'DKIM keys revoked (non-sending)',
				'info',
				`All ${revokedCount} DKIM selector(s) have revoked keys (empty p= tag). This is expected for domains that do not send email.`,
			),
		);
	}

	// In selector-probing mode, multiple selectors can expose identical key profiles.
	if (!selector && foundSelectors.length > 1) {
		consolidateSelectorProbeKeyStrengthFindings(findings);
	}

	if (foundSelectors.length === 0) {
		findings.push(
			createFinding(
				'dkim',
				'No DKIM records found among tested selectors',
				'high',
				`No DKIM records were found for ${domain} among the tested selector set (${selectorsToCheck.join(', ')}). This result is based on selector probing and may miss custom selector names. DKIM helps verify email authenticity and integrity.`,
				{
					signalType: 'dkim',
					confidence: 'heuristic',
					detectionMethod: 'selector-probing',
					selectorsChecked: selectorsToCheck,
					selectorsFound: [],
				},
			),
		);
	} else if (foundSelectors.length > 0 && hasValidKey && findings.every((f) => f.severity === 'info')) {
		findings.push(
			createFinding('dkim', 'DKIM configured', 'info', `DKIM records found for selectors: ${foundSelectors.join(', ')}`, {
				signalType: 'dkim',
				selectorsChecked: selectorsToCheck,
				selectorsFound: foundSelectors,
			}),
		);
	}

	return buildCheckResult('dkim', findings);
}
