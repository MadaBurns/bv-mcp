// SPDX-License-Identifier: BUSL-1.1

/**
 * MTA-STS analysis helpers.
 * Pure functions for analyzing MTA-STS TXT records, policy files, and TLS-RPT records.
 *
 * Copyright (c) 2023-2026 BlackVeil Security Ltd.
 * Licensed under BSL 1.1
 */

import type { Finding } from '../types';
import { createFinding } from '../check-utils';

export function getMtaStsTxtFindings(records: string[]): { findings: Finding[]; hasTxtRecord: boolean } {
	const findings: Finding[] = [];
	const mtaStsRecords = records.filter((record) => /^v=stsv1[;\s]/i.test(record));

	if (mtaStsRecords.length === 0) {
		return {
			findings: [
				createFinding(
					'mta_sts',
					'No MTA-STS record found',
					'medium',
					'',
					{ missingControl: true },
				),
			],
			hasTxtRecord: false,
		};
	}

	if (mtaStsRecords.length > 1) {
		findings.push(
			createFinding('mta_sts', 'Multiple MTA-STS records', 'medium', `Found ${mtaStsRecords.length} MTA-STS records. Only one should exist.`),
		);
	}

	if (!mtaStsRecords[0].includes('id=')) {
		findings.push(
			createFinding(
				'mta_sts',
				'MTA-STS missing id tag',
				'medium',
				'MTA-STS record is missing the "id=" tag. This tag is required for policy versioning.',
			),
		);
	}

	return { findings, hasTxtRecord: true };
}

export function finalizeMissingMtaStsRecordFinding(findings: Finding[], domain: string): Finding[] {
	return findings.map((finding) =>
		finding.title === 'No MTA-STS record found'
			? createFinding(
					'mta_sts',
					'No MTA-STS record found',
					'medium',
					`No MTA-STS TXT record found at _mta-sts.${domain}. MTA-STS enforces TLS for incoming email, preventing downgrade attacks.`,
					{ missingControl: true },
				)
			: finding,
	);
}

export function getMtaStsPolicyFindings(body: string, policyUrl: string): Finding[] {
	const findings: Finding[] = [];
	const versionMatch = body.match(/version:\s*(\S+)/i);
	if (!versionMatch || versionMatch[1] !== 'STSv1') {
		findings.push(
			createFinding(
				'mta_sts',
				'MTA-STS policy missing or invalid version',
				'high',
				'The MTA-STS policy must contain "version: STSv1" as required by RFC 8461.',
			),
		);
	}

	const modeMatch = body.match(/mode:\s*(enforce|testing|none)/i);

	if (!modeMatch) {
		findings.push(
			createFinding('mta_sts', 'MTA-STS policy missing mode', 'high', 'MTA-STS policy file does not contain a valid "mode:" directive.'),
		);
	} else {
		const mode = modeMatch[1].toLowerCase();
		if (mode === 'testing') {
			findings.push(
				createFinding('mta_sts', 'MTA-STS in testing mode', 'low', 'MTA-STS policy is in "testing" mode. Consider switching to "enforce" once verified.'),
			);
		} else if (mode === 'none') {
			findings.push(
				createFinding('mta_sts', 'MTA-STS policy disabled', 'medium', 'MTA-STS policy mode is "none", effectively disabling MTA-STS protection.'),
			);
		}
	}

	if (!body.includes('mx:')) {
		findings.push(
			createFinding(
				'mta_sts',
				'MTA-STS policy missing MX entries',
				'high',
				'MTA-STS policy file does not contain any "mx:" entries. At least one MX pattern is required.',
			),
		);
	}

	const maxAgeMatch = body.match(/max_age:\s*(\d+)/i);
	if (!maxAgeMatch) {
		findings.push(
			createFinding(
				'mta_sts',
				'MTA-STS policy missing max_age',
				'high',
				'The max_age directive is required by RFC 8461. Without it, the policy is technically invalid.',
			),
		);
	} else {
		const maxAge = parseInt(maxAgeMatch[1], 10);
		if (maxAge < 86400) {
			findings.push(
				createFinding(
					'mta_sts',
					'MTA-STS max_age too short',
					'low',
					`MTA-STS max_age is ${maxAge} seconds (less than 1 day). A short max_age reduces the effectiveness of MTA-STS protection.`,
				),
			);
		} else if (maxAge > 31557600) {
			findings.push(
				createFinding(
					'mta_sts',
					'MTA-STS max_age exceeds one year',
					'info',
					`MTA-STS max_age is ${maxAge} seconds (more than 1 year). This is acceptable but noted.`,
				),
			);
		}
	}

	if (findings.length === 0) {
		return [];
	}

	return findings.map((finding) =>
		finding.title === 'MTA-STS policy missing mode' || finding.title === 'MTA-STS policy missing MX entries'
			? createFinding('mta_sts', finding.title, finding.severity, finding.detail.replace('MTA-STS policy file', `MTA-STS policy file at ${policyUrl}`))
			: finding,
	);
}

export function extractPolicyMxPatterns(body: string): string[] {
	return [...body.matchAll(/mx:\s*(\S+)/gi)].map((match) => match[1].toLowerCase());
}

export function matchesMxPattern(hostname: string, pattern: string): boolean {
	if (pattern.startsWith('*.')) {
		const suffix = pattern.slice(1);
		return hostname.endsWith(suffix) || hostname === pattern.slice(2);
	}

	return hostname === pattern;
}

export function getUncoveredMxHostFindings(mxHosts: string[], policyMxPatterns: string[]): Finding[] {
	return mxHosts.flatMap((mxHost) => {
		const hostname = mxHost.toLowerCase();
		const covered = policyMxPatterns.some((pattern) => matchesMxPattern(hostname, pattern));
		if (covered) {
			return [];
		}

		return [
			createFinding(
				'mta_sts',
				`MTA-STS policy does not cover MX host ${mxHost}`,
				'high',
				`The MX host ${mxHost} is not matched by any mx: entry in the MTA-STS policy. Mail delivered to this MX will fail MTA-STS validation.`,
			),
		];
	});
}

export function hasValidTlsRptRecord(records: string[]): boolean {
	return records.some((record) => record.toLowerCase().startsWith('v=tlsrptv1'));
}

export function getTlsRptRecordFindings(records: string[]): { findings: Finding[]; hasTlsRptRecord: boolean } {
	const validRecords = records.filter((record) => record.toLowerCase().startsWith('v=tlsrptv1'));
	if (validRecords.length === 0) {
		return {
			findings: [
				createFinding(
					'mta_sts',
					'TLS-RPT record missing',
					'low',
					'',
				),
			],
			hasTlsRptRecord: false,
		};
	}

	const tlsrptRecord = validRecords[0];
	const ruaMatch = tlsrptRecord.match(/rua\s*=\s*([^;\s]+)/i);
	if (!ruaMatch) {
		return {
			findings: [
				createFinding(
					'mta_sts',
					'TLS-RPT missing rua directive',
					'low',
					'TLS-RPT record does not contain a "rua=" directive. The rua URI is needed to receive TLS failure reports.',
				),
			],
			hasTlsRptRecord: true,
		};
	}

	const ruaValue = ruaMatch[1];
	const isValidMailto = /^mailto:[^@\s]+@[^@\s]+\.[^@\s]+$/.test(ruaValue);
	const isValidHttps = /^https:\/\/.+/.test(ruaValue);
	if (!isValidMailto && !isValidHttps) {
		return {
			findings: [
				createFinding(
					'mta_sts',
					'TLS-RPT invalid rua format',
					'medium',
					`TLS-RPT rua value "${ruaValue}" is not a valid mailto: or https: URI.`,
				),
			],
			hasTlsRptRecord: true,
		};
	}

	return { findings: [], hasTlsRptRecord: true };
}

export function finalizeMissingTlsRptRecordFinding(findings: Finding[], domain: string): Finding[] {
	return findings.map((finding) =>
		finding.title === 'TLS-RPT record missing'
			? createFinding(
					'mta_sts',
					'TLS-RPT record missing',
					'low',
					`No TLS-RPT record found at _smtp._tls.${domain}. Consider adding a TLS-RPT record for reporting SMTP TLS issues.`,
				)
			: finding,
	);
}

export function shouldSummarizeMissingMailProtections(findings: Finding[], hasTxtRecord: boolean, tlsRptChecked: boolean, hasTlsRptRecord: boolean): boolean {
	const hasDnsErrorFindings = findings.some((finding) => finding.title.includes('DNS query failed'));
	return !hasTxtRecord && tlsRptChecked && !hasTlsRptRecord && !hasDnsErrorFindings;
}
