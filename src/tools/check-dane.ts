// SPDX-License-Identifier: BUSL-1.1

/**
 * DANE (DNS-Based Authentication of Named Entities) check tool.
 * Validates TLSA records for MX servers (_25._tcp.{mx-host}) and
 * HTTPS endpoints (_443._tcp.{domain}).
 *
 * DANE pins TLS certificates to DNS, preventing CA misissuance attacks.
 * Requires DNSSEC to be effective — TLSA records without DNSSEC can be spoofed.
 *
 * Workers-compatible: uses fetch API only (DNS-over-HTTPS).
 */

import { type CheckResult, type Finding, buildCheckResult, createFinding } from '../lib/scoring';
import { queryDnsRecords, queryMxRecords, checkDnssec } from '../lib/dns';
import type { QueryDnsOptions } from '../lib/dns-types';
import { analyzeTlsaRecords, classifyDanePresence } from './dane-analysis';

/**
 * Check DANE TLSA records for a domain's MX servers and HTTPS endpoint.
 *
 * @param domain - The domain to check (must already be validated and sanitized)
 * @param dnsOptions - Optional DNS query options (e.g., scan-context optimizations)
 * @returns CheckResult with DANE findings
 */
export async function checkDane(domain: string, dnsOptions?: QueryDnsOptions): Promise<CheckResult> {
	const findings: Finding[] = [];
	let hasDnssec = false;
	let hasMxTlsa = false;
	let hasHttpsTlsa = false;

	// Step 1: Check DNSSEC status for the domain
	try {
		hasDnssec = await checkDnssec(domain, dnsOptions);
	} catch {
		// DNSSEC check failed — continue without it (findings will note the lack)
	}

	// Step 2: Query MX records and check TLSA for each MX host
	try {
		const mxRecords = await queryMxRecords(domain, dnsOptions);

		for (const mx of mxRecords) {
			const mxHost = mx.exchange;
			if (!mxHost || mxHost === '.') continue;

			const tlsaName = `_25._tcp.${mxHost}`;
			try {
				const tlsaRecords = await queryDnsRecords(tlsaName, 'TLSA', dnsOptions);
				if (tlsaRecords.length > 0) {
					hasMxTlsa = true;
					findings.push(...analyzeTlsaRecords(tlsaRecords, tlsaName, hasDnssec));
				}
			} catch {
				// Individual MX TLSA query failed — skip this host
			}
		}
	} catch {
		// MX query failed — still check HTTPS TLSA below
		findings.push(
			createFinding(
				'dane',
				'MX lookup failed for DANE check',
				'low',
				`Could not query MX records for ${domain} to check SMTP DANE. HTTPS DANE was still checked.`,
			),
		);
	}

	// Step 3: Check HTTPS TLSA at _443._tcp.{domain}
	const httpsTlsaName = `_443._tcp.${domain}`;
	try {
		const httpsTlsaRecords = await queryDnsRecords(httpsTlsaName, 'TLSA', dnsOptions);
		if (httpsTlsaRecords.length > 0) {
			hasHttpsTlsa = true;
			findings.push(...analyzeTlsaRecords(httpsTlsaRecords, httpsTlsaName, hasDnssec));
		}
	} catch {
		// HTTPS TLSA query failed — continue with whatever we have
	}

	// Step 4: If no TLSA records found anywhere, classify absence
	if (!hasMxTlsa && !hasHttpsTlsa && findings.every((f) => f.severity !== 'medium' || !f.title.includes('Malformed'))) {
		findings.push(...classifyDanePresence(hasMxTlsa, hasHttpsTlsa));
	}

	// Step 5: Handle case where all DNS queries failed
	if (findings.length === 0) {
		findings.push(
			createFinding(
				'dane',
				'DANE check inconclusive',
				'medium',
				`DNS queries for DANE TLSA records failed for ${domain}. Unable to determine DANE status.`,
			),
		);
	}

	return buildCheckResult('dane', findings);
}
