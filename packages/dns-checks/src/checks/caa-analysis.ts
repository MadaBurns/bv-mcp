// SPDX-License-Identifier: BUSL-1.1

/**
 * CAA record analysis helpers.
 * Pure functions for summarizing and validating CAA records.
 *
 * Copyright (c) 2023-2026 BlackVeil Security Ltd.
 * Licensed under BSL 1.1
 */

import type { Finding } from '../types';
import { createFinding } from '../check-utils';

/** Parsed CAA record with flags, tag, and value */
export interface CaaRecord {
	flags: number;
	tag: string;
	value: string;
}

/**
 * Parse a single CAA record data string.
 * Handles both human-readable format (e.g. `0 issue "letsencrypt.org"`)
 * and Cloudflare DoH hex wire format (e.g. `\# 19 00 05 69 73 73 75 65...`).
 */
export function parseCaaRecord(data: string): CaaRecord | null {
	if (data.startsWith('\\#') || data.startsWith('#')) {
		const parts = data.trim().split(/\s+/);
		const hexStart = parts[0] === '\\#' || parts[0] === '#' ? 2 : 1;
		const hexBytes = parts.slice(hexStart);
		if (hexBytes.length < 3) return null;

		const flags = parseInt(hexBytes[0], 16);
		const tagLen = parseInt(hexBytes[1], 16);
		if (isNaN(flags) || isNaN(tagLen) || hexBytes.length < 2 + tagLen) return null;

		const tag = hexBytes
			.slice(2, 2 + tagLen)
			.map((hexByte) => String.fromCharCode(parseInt(hexByte, 16)))
			.join('');
		const value = hexBytes
			.slice(2 + tagLen)
			.map((hexByte) => String.fromCharCode(parseInt(hexByte, 16)))
			.join('');

		return { flags, tag: tag.toLowerCase(), value };
	}

	const match = data.match(/^(\d+)\s+(\S+)\s+"?([^"]*)"?\s*$/);
	if (match) {
		return {
			flags: parseInt(match[1], 10),
			tag: match[2].toLowerCase(),
			value: match[3],
		};
	}

	return null;
}

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
