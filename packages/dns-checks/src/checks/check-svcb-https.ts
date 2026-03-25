// SPDX-License-Identifier: BUSL-1.1

/**
 * SVCB/HTTPS DNS record check (RFC 9460).
 * Queries HTTPS resource records at the apex domain and validates the
 * presence and content of modern transport capability advertisements.
 *
 * Copyright (c) 2023-2026 BlackVeil Security Ltd.
 * Licensed under BSL 1.1
 */

import type { CheckResult, DNSQueryFunction, Finding } from '../types';
import { buildCheckResult, createFinding } from '../check-utils';

/**
 * Parse ALPN protocols from an HTTPS record data string.
 */
function parseAlpn(data: string): string[] {
	const match = data.match(/\balpn=(?:"([^"]+)"|(\S+))/i);
	if (!match) return [];
	const raw = match[1] ?? match[2] ?? '';
	return raw.split(',').map((p) => p.trim()).filter(Boolean);
}

/**
 * Check for ECH (Encrypted Client Hello) in the HTTPS record data.
 */
function hasEch(data: string): boolean {
	return /\bech=/i.test(data);
}

/**
 * Parse the priority from HTTPS record data.
 */
function parsePriority(data: string): number | null {
	const match = data.match(/^(\d+)\s/);
	if (!match) return null;
	return parseInt(match[1], 10);
}

/**
 * Check HTTPS/SVCB records (RFC 9460) for a domain.
 * Validates the presence of HTTPS records and analyzes their contents
 * for modern transport capability advertisements.
 */
export async function checkSVCBHTTPS(
	domain: string,
	queryDNS: DNSQueryFunction,
	options?: { timeout?: number },
): Promise<CheckResult> {
	const timeout = options?.timeout ?? 5000;
	const findings: Finding[] = [];

	let httpsRecords: string[] = [];
	try {
		httpsRecords = await queryDNS(domain, 'HTTPS', { timeout });
	} catch {
		findings.push(
			createFinding(
				'svcb_https',
				'HTTPS record query failed',
				'low',
				`DNS query for HTTPS records at ${domain} failed. Unable to determine SVCB/HTTPS status.`,
			),
		);
		return buildCheckResult('svcb_https', findings);
	}

	if (httpsRecords.length === 0) {
		findings.push(
			createFinding(
				'svcb_https',
				'No HTTPS record found',
				'low',
				`No HTTPS (type 65) record found at ${domain}. HTTPS records (RFC 9460) advertise modern transport capabilities (ALPN, ECH) and enable clients to connect securely without an initial redirect round-trip. Consider publishing an HTTPS record with h2 and h3 ALPN support.`,
			),
		);
		return buildCheckResult('svcb_https', findings);
	}

	// Analyze each HTTPS record
	let hasH2 = false;
	let hasH3 = false;
	let hasEchParam = false;
	let hasAliasMode = false;
	let validServiceModeRecords = 0;

	for (const record of httpsRecords) {
		const priority = parsePriority(record);

		if (priority === 0) {
			// Alias mode — delegates to another name for parameters
			hasAliasMode = true;
			findings.push(
				createFinding(
					'svcb_https',
					'HTTPS record in alias mode',
					'info',
					`HTTPS record at ${domain} uses alias mode (priority 0): ${record}. This delegates SVCB parameters to a canonical name. Ensure the target also has valid HTTPS records.`,
					{ record, mode: 'alias' },
				),
			);
			continue;
		}

		// Service mode (priority >= 1)
		validServiceModeRecords++;
		const alpnProtocols = parseAlpn(record);
		const recordHasEch = hasEch(record);

		if (alpnProtocols.includes('h2')) hasH2 = true;
		if (alpnProtocols.includes('h3')) hasH3 = true;
		if (recordHasEch) hasEchParam = true;

		findings.push(
			createFinding(
				'svcb_https',
				'HTTPS record configured',
				'info',
				`HTTPS record found at ${domain} (priority ${priority}): ALPN=[${alpnProtocols.join(', ') || 'none'}]${recordHasEch ? ', ECH=present' : ''}.`,
				{ record, priority, alpn: alpnProtocols, ech: recordHasEch },
			),
		);

		// Flag missing ALPN
		if (alpnProtocols.length === 0 && !hasAliasMode) {
			findings.push(
				createFinding(
					'svcb_https',
					'HTTPS record missing ALPN parameter',
					'low',
					`HTTPS record at ${domain} does not specify an ALPN parameter. Without ALPN, clients cannot use the record to negotiate HTTP/2 or HTTP/3 without an additional round-trip. Add alpn="h2" or alpn="h2,h3" to enable protocol negotiation.`,
					{ record },
				),
			);
		}
	}

	// Summary findings for capabilities
	if (validServiceModeRecords > 0 || hasAliasMode) {
		if (!hasH2 && !hasAliasMode) {
			findings.push(
				createFinding(
					'svcb_https',
					'HTTPS record does not advertise HTTP/2',
					'low',
					`HTTPS records at ${domain} do not include h2 in the ALPN list. HTTP/2 support via SVCB allows faster TLS negotiation. Add alpn="h2,h3" to enable HTTP/2 and HTTP/3 advertisement.`,
				),
			);
		}

		if (hasH3) {
			findings.push(
				createFinding(
					'svcb_https',
					'HTTP/3 (QUIC) advertised via HTTPS record',
					'info',
					`HTTPS record at ${domain} advertises HTTP/3 (h3) ALPN, enabling QUIC-based transport. This provides improved performance and resilience, especially on lossy networks.`,
				),
			);
		}

		if (hasEchParam) {
			findings.push(
				createFinding(
					'svcb_https',
					'Encrypted Client Hello (ECH) advertised',
					'info',
					`HTTPS record at ${domain} includes ECH parameters. ECH encrypts the TLS SNI field, preventing passive observers from identifying the target hostname during connection establishment.`,
				),
			);
		}
	}

	return buildCheckResult('svcb_https', findings);
}
