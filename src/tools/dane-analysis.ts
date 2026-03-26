// SPDX-License-Identifier: BUSL-1.1

/**
 * DANE (DNS-Based Authentication of Named Entities) analysis helpers.
 * Pure functions for analyzing TLSA records and classifying DANE presence.
 * Workers-compatible: no Node.js APIs.
 */

import type { Finding } from '../lib/scoring';
import { createFinding } from '../lib/scoring';
import { parseTlsaRecord } from '../lib/dns';

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
 *
 * @param records - Raw TLSA record data strings from DNS
 * @param name - The DNS name the TLSA records belong to (e.g., _25._tcp.mx.example.com)
 * @param hasDnssec - Whether the domain has validated DNSSEC
 * @returns Array of findings from the analysis
 */
export function analyzeTlsaRecords(records: string[], name: string, hasDnssec: boolean): Finding[] {
	const findings: Finding[] = [];
	const seenDaneWithoutDnssec = new Set<string>();
	let validRecordCount = 0;

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

		// DANE-EE (3) and DANE-TA (2) require DNSSEC for security — deduplicate per host
		if ((parsed.usage === 2 || parsed.usage === 3) && !hasDnssec && !seenDaneWithoutDnssec.has(name)) {
			seenDaneWithoutDnssec.add(name);
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

		// Count valid DANE records for consolidated info finding
		validRecordCount++;
	}

	// Emit a single consolidated info finding for all valid TLSA records
	if (validRecordCount > 0) {
		const detail =
			validRecordCount === 1
				? `Valid TLSA record configured for ${name}.`
				: `${validRecordCount} DANE TLSA records configured for ${name}.`;
		findings.push(
			createFinding('dane', `DANE TLSA configured for ${name}`, 'info', detail, { name, validRecordCount }),
		);
	}

	return findings;
}

/**
 * Generate findings when no TLSA records are found for MX and/or HTTPS endpoints.
 *
 * @param hasMxTlsa - Whether any TLSA records were found for MX server ports
 * @param hasHttpsTlsa - Whether any TLSA records were found for HTTPS (port 443)
 * @returns Array of findings for missing DANE records
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
				{ missingControl: true },
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
				{ missingControl: true },
			),
		);
	}

	return findings;
}
