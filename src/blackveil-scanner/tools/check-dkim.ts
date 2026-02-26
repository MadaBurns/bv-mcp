/**
 * DKIM (DomainKeys Identified Mail) check tool for BLACKVEIL Scanner npm package.
 * Queries common DKIM selector TXT records and validates configuration.
 */

import { queryTxtRecords } from '../lib/dns';
import { buildCheckResult, createFinding, type CheckResult, type Finding } from '../lib/scoring';

const COMMON_SELECTORS = [
	'default',
	'google',
	'selector1',
	'selector2',
	'k1',
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
			for (const record of result.records) {
				const isRevoked = /p=\s*;/i.test(record) || /p=\s*$/i.test(record);
				if (isRevoked) {
					findings.push(
						createFinding(
							'dkim',
							`Revoked DKIM key: ${result.selector}`,
							'critical',
							`DKIM selector ${result.selector} has an empty or revoked public key (p=). Legitimate email may be dropped.`,
						),
					);
				} else {
					hasValidKey = true;
				}
			}
		}
	}

	if (foundSelectors.length === 0) {
		findings.push(
			createFinding(
				'dkim',
				'No DKIM records found',
				'high',
				`No DKIM records found for ${domain} across common selectors. DKIM helps verify email authenticity and integrity.`,
			),
		);
	}

	if (hasValidKey && findings.length === 0) {
		findings.push(
			createFinding(
				'dkim',
				'DKIM key found',
				'info',
				`Valid DKIM key found for ${domain} on selector(s): ${foundSelectors.join(', ')}.`,
			),
		);
	}

	return buildCheckResult('dkim', findings);
}
