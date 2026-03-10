// SPDX-License-Identifier: MIT

import type { CaaRecord } from '../lib/dns';
import type { Finding } from '../lib/scoring';
import { createFinding } from '../lib/scoring';

export function summarizeCaaTags(caaRecords: CaaRecord[]): {
	hasIssue: boolean;
	hasIssuewild: boolean;
	hasIodef: boolean;
} {
	let hasIssue = false;
	let hasIssuewild = false;
	let hasIodef = false;

	for (const record of caaRecords) {
		if (record.tag === 'issue') {
			hasIssue = true;
		}
		if (record.tag === 'issuewild') {
			hasIssuewild = true;
		}
		if (record.tag === 'iodef') {
			hasIodef = true;
		}
	}

	return { hasIssue, hasIssuewild, hasIodef };
}

export function getCaaValidationFindings(tagSummary: { hasIssue: boolean; hasIssuewild: boolean; hasIodef: boolean }): Finding[] {
	const findings: Finding[] = [];

	if (!tagSummary.hasIssue) {
		findings.push(
			createFinding(
				'caa',
				'No CAA issue tag',
				'medium',
				'CAA records exist but no "issue" tag found. The "issue" tag specifies which CAs are authorized to issue certificates.',
			),
		);
	}

	if (!tagSummary.hasIssuewild) {
		findings.push(
			createFinding(
				'caa',
				'No CAA issuewild tag',
				'low',
				'No "issuewild" CAA tag found. Consider adding one to control wildcard certificate issuance separately.',
			),
		);
	}

	if (!tagSummary.hasIodef) {
		findings.push(
			createFinding(
				'caa',
				'No CAA iodef tag',
				'low',
				'No "iodef" CAA tag found. The iodef tag specifies where CAs should report policy violations.',
			),
		);
	}

	return findings;
}

export function getCaaConfiguredFinding(): Finding {
	return createFinding('caa', 'CAA properly configured', 'info', 'CAA records found with issue, issuewild, and iodef tags configured.');
}