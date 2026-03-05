/**
 * DKIM (DomainKeys Identified Mail) check tool.
 * Queries common DKIM selector TXT records and validates configuration.
 */

import { queryTxtRecords } from '../lib/dns';
import { type CheckResult, type Finding, buildCheckResult, createFinding } from '../lib/scoring';

/** Common DKIM selectors used by major email providers */
const COMMON_SELECTORS = [
	'default',
	'google',
	'20230601', // Google Workspace
	'20210112', // Google Workspace (legacy)
	'selector1', // Microsoft 365
	'selector2', // Microsoft 365
	'selector',
	'k1', // Mailchimp
	's1024',
	's2048',
	's1',
	's2',
	'mail',
	'dkim',
	'smtp',
	'amazonses',
	'mandrill',
	'mailjet',
	'zoho',
];

function getDkimTagValue(record: string, tag: string): string | undefined {
	const match = record.match(new RegExp(`(?:^|;)\\s*${tag}=([^;]*)`, 'i'));
	return match?.[1]?.trim();
}

/**
 * Analyze RSA key strength by estimating bit-length from base64 character count.
 * Conservative heuristic: longer base64 = more bits.
 * Returns estimated bits and severity classification.
 */
function analyzeRsaKeyLength(publicKeyBase64: string | undefined): {
	bits: number | null;
	strength: 'critical' | 'high' | 'medium' | 'info';
	keyType: 'rsa' | 'ed25519' | 'unknown';
} {
	if (!publicKeyBase64) {
		return { bits: null, strength: 'info', keyType: 'unknown' };
	}

	// Check for ED25519 (always strong)
	if (publicKeyBase64.includes('[ED25519]') || publicKeyBase64.toLowerCase().includes('ed25519')) {
		return { bits: null, strength: 'info', keyType: 'ed25519' };
	}

	// Estimate RSA bits from base64 character count
	const cleanKey = publicKeyBase64.replace(/\s/g, '');
	const charCount = cleanKey.length;

	let bits: number;
	let strength: 'critical' | 'high' | 'medium' | 'info';

	if (charCount < 150) {
		bits = 512;
		strength = 'critical';
	} else if (charCount < 230) {
		bits = 1024;
		strength = 'high';
	} else if (charCount < 330) {
		bits = 2048;
		strength = 'medium';
	} else {
		bits = 4096;
		strength = 'info';
	}

	return { bits, strength, keyType: 'rsa' };
}

/**
 * Check DKIM records for a domain.
 * Probes common selectors at <selector>._domainkey.<domain>.
 * Optionally accepts a specific selector to check.
 */
export async function checkDkim(domain: string, selector?: string): Promise<CheckResult> {
	const findings: Finding[] = [];
	const selectorsToCheck = selector ? [selector] : COMMON_SELECTORS;
	const foundSelectors: string[] = [];
	let hasValidKey = false;

	// Check each selector in parallel
	const results = await Promise.all(
		selectorsToCheck.map(async (sel) => {
			try {
				const records = await queryTxtRecords(`${sel}._domainkey.${domain}`);
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
				const keyType = record.match(/k=([^;\s]+)/i);
				if (keyType && !['rsa', 'ed25519'].includes(keyType[1].toLowerCase())) {
					findings.push(
						createFinding(
							'dkim',
							`Unknown DKIM key type: ${keyType[1]}`,
							'medium',
							`DKIM selector "${result.selector}" uses unknown key type "${keyType[1]}". Expected "rsa" or "ed25519".`,
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

				// Analyze RSA key strength (only if key is valid/not revoked)
				if (!isRevoked && publicKey) {
					const keyAnalysis = analyzeRsaKeyLength(publicKey);
					if (keyAnalysis.keyType === 'rsa') {
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
								`DKIM RSA key for "${result.selector}" is ${severityMsg} (~${keyAnalysis.bits} bits). Upgrade to 2048-bit RSA or use ED25519 for better security.`,
							high: `DKIM RSA key for "${result.selector}" is ${severityMsg} (${keyAnalysis.bits} bits). Consider upgrading to 2048-bit RSA or ED25519.`,
							medium: `DKIM RSA key for "${result.selector}" is ${severityMsg} (${keyAnalysis.bits} bits). Major providers recommend 4096-bit RSA or ED25519.`,
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

	if (foundSelectors.length === 0) {
		findings.push(
			createFinding(
				'dkim',
				'No DKIM records found',
				'high',
				`No DKIM records found for ${domain} across common selectors (${COMMON_SELECTORS.join(', ')}). DKIM helps verify email authenticity and integrity.`,
				{
					signalType: 'dkim',
					selectorsChecked: selectorsToCheck,
					selectorsFound: [],
				},
			),
		);
	} else if (findings.length === 0) {
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
