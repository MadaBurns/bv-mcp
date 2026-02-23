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
	'selector1', // Microsoft 365
	'selector2', // Microsoft 365
	'k1', // Mailchimp
	's1',
	's2',
	'mail',
	'dkim',
	'smtp',
];

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
			),
		);
	} else if (findings.length === 0) {
		findings.push(createFinding('dkim', 'DKIM configured', 'info', `DKIM records found for selectors: ${foundSelectors.join(', ')}`));
	}

	return buildCheckResult('dkim', findings);
}
