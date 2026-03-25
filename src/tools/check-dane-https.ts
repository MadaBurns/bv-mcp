// SPDX-License-Identifier: BUSL-1.1

/**
 * DANE-HTTPS check tool.
 * Validates TLSA records specifically for the HTTPS endpoint (_443._tcp.{domain}).
 *
 * Unlike the combined `check-dane` tool (which checks both MX/SMTP and HTTPS),
 * this focused check isolates HTTPS certificate pinning via DANE. It is used
 * in the scoring model as a separate `dane_https` category.
 *
 * Requires DNSSEC to be effective — TLSA records without DNSSEC can be spoofed.
 *
 * Workers-compatible: uses fetch API only (DNS-over-HTTPS).
 */

import { type CheckResult, type Finding, buildCheckResult, createFinding } from '../lib/scoring';
import { queryDnsRecords, checkDnssec } from '../lib/dns';
import type { QueryDnsOptions } from '../lib/dns-types';
import { analyzeTlsaRecords } from './dane-analysis';

/**
 * Check DANE TLSA records for a domain's HTTPS endpoint (_443._tcp.{domain}).
 *
 * @param domain - The domain to check (must already be validated and sanitized)
 * @param dnsOptions - Optional DNS query options (e.g., scan-context optimizations)
 * @returns CheckResult with DANE HTTPS findings
 */
export async function checkDaneHttps(domain: string, dnsOptions?: QueryDnsOptions): Promise<CheckResult> {
	const findings: Finding[] = [];
	let hasDnssec = false;

	// Step 1: Check DNSSEC status for the domain
	try {
		hasDnssec = await checkDnssec(domain, dnsOptions);
	} catch {
		// DNSSEC check failed — continue without it (findings will note the lack)
	}

	// Step 2: Query TLSA records at _443._tcp.{domain}
	const tlsaName = `_443._tcp.${domain}`;
	let hasHttpsTlsa = false;

	try {
		const tlsaRecords = await queryDnsRecords(tlsaName, 'TLSA', dnsOptions);
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
