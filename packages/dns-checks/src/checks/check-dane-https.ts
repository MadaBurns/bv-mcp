// SPDX-License-Identifier: BUSL-1.1

/**
 * DANE-HTTPS check.
 * Validates TLSA records specifically for the HTTPS endpoint (_443._tcp.{domain}).
 *
 * Copyright (c) 2023-2026 BlackVeil Security Ltd.
 * Licensed under BSL 1.1
 */

import type { CheckResult, DNSQueryFunction, Finding, RawDNSQueryFunction } from '../types';
import { buildCheckResult, createFinding } from '../check-utils';
import { analyzeTlsaRecords } from './dane-analysis';

/**
 * Check DANE TLSA records for a domain's HTTPS endpoint (_443._tcp.{domain}).
 */
export async function checkDANEHTTPS(
	domain: string,
	queryDNS: DNSQueryFunction,
	options?: { timeout?: number; rawQueryDNS?: RawDNSQueryFunction },
): Promise<CheckResult> {
	const timeout = options?.timeout ?? 5000;
	const rawQueryDNS = options?.rawQueryDNS;
	const findings: Finding[] = [];
	let hasDnssec = false;

	// Step 1: Check DNSSEC status for the domain
	if (rawQueryDNS) {
		try {
			const resp = await rawQueryDNS(domain, 'A', true, { timeout });
			hasDnssec = resp.AD === true;
		} catch {
			// DNSSEC check failed — continue without it
		}
	}

	// Step 2: Query TLSA records at _443._tcp.{domain}
	const tlsaName = `_443._tcp.${domain}`;
	let hasHttpsTlsa = false;

	try {
		const tlsaRecords = await queryDNS(tlsaName, 'TLSA', { timeout });
		if (tlsaRecords.length > 0) {
			hasHttpsTlsa = true;
			findings.push(...analyzeTlsaRecords(tlsaRecords, tlsaName, hasDnssec));
		}
	} catch {
		// TLSA query failed — report and continue
		findings.push(
			createFinding(
				'dane_https',
				'DANE HTTPS query failed',
				'low',
				`DNS query for TLSA records at ${tlsaName} failed. Unable to determine DANE HTTPS status for ${domain}.`,
			),
		);
	}

	// Step 3: If no TLSA records found, classify absence
	if (!hasHttpsTlsa && findings.every((f) => f.title !== 'DANE HTTPS query failed')) {
		findings.push(
			createFinding(
				'dane_https',
				'No DANE TLSA for HTTPS',
				'low',
				`No TLSA record found at ${tlsaName}. DANE can pin web server certificates to DNS, providing an additional layer of trust beyond the CA system. Implement DANE-EE (usage 3) with DNSSEC enabled for maximum security.`,
			),
		);
	}

	// Step 4: Handle case where all DNS queries failed and findings is empty
	if (findings.length === 0) {
		findings.push(
			createFinding(
				'dane_https',
				'DANE HTTPS check inconclusive',
				'medium',
				`DNS queries for DANE HTTPS TLSA records failed for ${domain}. Unable to determine DANE HTTPS status.`,
			),
		);
	}

	// Remap any finding categories to 'dane_https' (analyzeTlsaRecords produces 'dane' category)
	const remapped = findings.map((f) => ({ ...f, category: 'dane_https' as const }));

	return buildCheckResult('dane_https', remapped);
}
