// SPDX-License-Identifier: BUSL-1.1

/**
 * DANE (DNS-Based Authentication of Named Entities) check.
 * Validates TLSA records for MX servers (_25._tcp.{mx-host}) and
 * HTTPS endpoints (_443._tcp.{domain}).
 *
 * Copyright (c) 2023-2026 BlackVeil Security Ltd.
 * Licensed under BSL 1.1
 */

import type { CheckResult, DNSQueryFunction, Finding, RawDNSQueryFunction } from '../types';
import { buildCheckResult, createFinding } from '../check-utils';
import { analyzeTlsaRecords, classifyDanePresence } from './dane-analysis';

/**
 * Parse MX records from raw DNS response strings.
 */
function parseMxFromRaw(answers: string[]): Array<{ exchange: string }> {
	return answers.map((answer) => {
		const parts = answer.split(' ');
		const exchange = (parts.slice(1).join(' ') || '').replace(/\.$/, '').toLowerCase();
		return { exchange };
	});
}

/**
 * Check DANE TLSA records for a domain's MX servers and HTTPS endpoint.
 */
export async function checkDANE(
	domain: string,
	queryDNS: DNSQueryFunction,
	options?: { timeout?: number; rawQueryDNS?: RawDNSQueryFunction },
): Promise<CheckResult> {
	const timeout = options?.timeout ?? 5000;
	const rawQueryDNS = options?.rawQueryDNS;
	const findings: Finding[] = [];
	let hasDnssec = false;
	let hasMxTlsa = false;
	let hasHttpsTlsa = false;

	// Step 1: Check DNSSEC status for the domain
	if (rawQueryDNS) {
		try {
			const resp = await rawQueryDNS(domain, 'A', true, { timeout });
			hasDnssec = resp.AD === true;
		} catch {
			// DNSSEC check failed — continue without it
		}
	}

	// Step 2: Query MX records and check TLSA for each MX host
	try {
		const mxAnswers = await queryDNS(domain, 'MX', { timeout });
		const mxRecords = parseMxFromRaw(mxAnswers);

		for (const mx of mxRecords) {
			const mxHost = mx.exchange;
			if (!mxHost || mxHost === '.') continue;

			const tlsaName = `_25._tcp.${mxHost}`;
			try {
				const tlsaRecords = await queryDNS(tlsaName, 'TLSA', { timeout });
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
		const httpsTlsaRecords = await queryDNS(httpsTlsaName, 'TLSA', { timeout });
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
