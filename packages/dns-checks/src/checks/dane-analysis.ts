// SPDX-License-Identifier: BUSL-1.1

/**
 * DANE (DNS-Based Authentication of Named Entities) analysis helpers.
 * Pure functions for analyzing TLSA records and classifying DANE presence.
 *
 * Copyright (c) 2023-2026 BlackVeil Security Ltd.
 * Licensed under BSL 1.1
 */

import type { Finding } from '../types';
import { createFinding } from '../check-utils';

/** Parsed TLSA record with usage, selector, matching type, and certificate data */
export interface TlsaRecord {
	usage: number;
	selector: number;
	matchingType: number;
	certData: string;
}

/**
 * Parse a TLSA record data string into structured fields.
 * Handles both human-readable format (`usage selector matchingType certData`)
 * and hex wire format (data starting with `\#`).
 */
export function parseTlsaRecord(data: string): TlsaRecord | null {
	if (data.startsWith('\\#') || data.startsWith('#')) {
		const parts = data.trim().split(/\s+/);
		const hexStart = parts[0] === '\\#' || parts[0] === '#' ? 2 : 1;
		const hexBytes = parts.slice(hexStart);
		if (hexBytes.length < 4) return null;

		const usage = parseInt(hexBytes[0], 16);
		const selector = parseInt(hexBytes[1], 16);
		const matchingType = parseInt(hexBytes[2], 16);
		if (isNaN(usage) || isNaN(selector) || isNaN(matchingType)) return null;

		const certData = hexBytes.slice(3).join('');
		return { usage, selector, matchingType, certData };
	}

	const parts = data.trim().split(/\s+/);
	if (parts.length < 4) return null;

	const usage = parseInt(parts[0], 10);
	const selector = parseInt(parts[1], 10);
	const matchingType = parseInt(parts[2], 10);
	if (isNaN(usage) || isNaN(selector) || isNaN(matchingType)) return null;

	const certData = parts.slice(3).join('');
	return { usage, selector, matchingType, certData };
}

/** TLSA usage field labels for human-readable output. */
const USAGE_LABELS: Record<number, string> = {
	0: 'PKIX-TA (CA constraint)',
	1: 'PKIX-EE (service certificate constraint)',
	2: 'DANE-TA (trust anchor assertion)',
	3: 'DANE-EE (domain-issued certificate)',
};

/**
 * Analyze a set of TLSA records for a given DNS name.
 * Validates field ranges, checks DNSSEC dependency, and flags weak matching types.
 */
export function analyzeTlsaRecords(records: string[], name: string, hasDnssec: boolean): Finding[] {
	const findings: Finding[] = [];

	for (const record of records) {
		const parsed = parseTlsaRecord(record);
		if (!parsed) {
			findings.push(
				createFinding(
					'dane',
					'Malformed TLSA record',
					'medium',
					`Could not parse TLSA record for ${name}: ${record}`,
				),
			);
			continue;
		}

		// Validate usage field (0-3)
		if (parsed.usage < 0 || parsed.usage > 3) {
			findings.push(
				createFinding(
					'dane',
					'Invalid TLSA usage',
					'medium',
					`TLSA record for ${name} has invalid usage value ${parsed.usage}. Valid range is 0-3.`,
					{ usage: parsed.usage },
				),
			);
			continue;
		}

		// Validate selector field (0-1)
		if (parsed.selector < 0 || parsed.selector > 1) {
			findings.push(
				createFinding(
					'dane',
					'Invalid TLSA selector',
					'medium',
					`TLSA record for ${name} has invalid selector value ${parsed.selector}. Valid range is 0-1.`,
					{ selector: parsed.selector },
				),
			);
			continue;
		}

		// Validate matching type field (0-2)
		if (parsed.matchingType < 0 || parsed.matchingType > 2) {
			findings.push(
				createFinding(
					'dane',
					'Invalid TLSA matching type',
					'medium',
					`TLSA record for ${name} has invalid matching type ${parsed.matchingType}. Valid range is 0-2.`,
					{ matchingType: parsed.matchingType },
				),
			);
			continue;
		}

		// DANE-EE (3) and DANE-TA (2) require DNSSEC for security
		if ((parsed.usage === 2 || parsed.usage === 3) && !hasDnssec) {
			const usageLabel = USAGE_LABELS[parsed.usage] ?? `usage ${parsed.usage}`;
			findings.push(
				createFinding(
					'dane',
					'DANE without DNSSEC',
					'high',
					`TLSA record for ${name} uses ${usageLabel} but DNSSEC is not validated. Without DNSSEC, DANE records can be spoofed, negating their security benefit.`,
					{ usage: parsed.usage, name },
				),
			);
		}

		// Matching type 0 = full certificate data (less secure than hash)
		if (parsed.matchingType === 0) {
			findings.push(
				createFinding(
					'dane',
					'TLSA uses full certificate matching',
					'low',
					`TLSA record for ${name} uses matching type 0 (full certificate). SHA-256 (type 1) or SHA-512 (type 2) matching is recommended for better security and smaller records.`,
					{ matchingType: parsed.matchingType, name },
				),
			);
		}

		// Valid DANE record found
		const usageLabel = USAGE_LABELS[parsed.usage] ?? `usage ${parsed.usage}`;
		findings.push(
			createFinding(
				'dane',
				`DANE TLSA configured for ${name}`,
				'info',
				`Valid TLSA record: ${usageLabel}, selector ${parsed.selector}, matching type ${parsed.matchingType}.`,
				{ usage: parsed.usage, selector: parsed.selector, matchingType: parsed.matchingType, name },
			),
		);
	}

	return findings;
}

/**
 * Generate findings when no TLSA records are found for MX and/or HTTPS endpoints.
 */
export function classifyDanePresence(hasMxTlsa: boolean, hasHttpsTlsa: boolean): Finding[] {
	const findings: Finding[] = [];

	if (!hasMxTlsa) {
		findings.push(
			createFinding(
				'dane',
				'No DANE TLSA for MX servers',
				'medium',
				'No TLSA records found for MX server SMTP ports (_25._tcp). DANE pins TLS certificates to DNS, preventing CA misissuance attacks on email delivery.',
			),
		);
	}

	if (!hasHttpsTlsa) {
		findings.push(
			createFinding(
				'dane',
				'No DANE TLSA for HTTPS',
				'low',
				'No TLSA record found for HTTPS endpoint (_443._tcp). DANE can pin web server certificates to DNS, providing an additional layer of trust beyond the CA system.',
			),
		);
	}

	return findings;
}
