// SPDX-License-Identifier: BUSL-1.1

/**
 * DNSSEC (DNS Security Extensions) check.
 * Validates DNSSEC by checking the AD flag, querying for DNSKEY/DS records,
 * and auditing algorithm and digest type security.
 *
 * Copyright (c) 2023-2026 BlackVeil Security Ltd.
 * Licensed under BSL 1.1
 */

import type { CheckResult, DNSQueryFunction, Finding, RawDNSQueryFunction } from '../types';
import { buildCheckResult, createFinding } from '../check-utils';
import { auditDnskeyAlgorithms, auditDsDigestTypes } from './dnssec-analysis';

export { parseDnskeyAlgorithm, parseDsRecord } from './dnssec-analysis';

/**
 * Check DNSSEC configuration for a domain.
 * Verifies the AD (Authenticated Data) flag, checks for DNSKEY/DS records,
 * and audits algorithm and digest type security.
 *
 * Requires a rawQueryDNS function that returns the full DoH response (including AD flag).
 * Falls back to queryDNS for DNSKEY/DS record queries.
 */
export async function checkDNSSEC(
	domain: string,
	queryDNS: DNSQueryFunction,
	options?: { timeout?: number; rawQueryDNS?: RawDNSQueryFunction },
): Promise<CheckResult> {
	const timeout = options?.timeout ?? 5000;
	const rawQueryDNS = options?.rawQueryDNS;
	const findings: Finding[] = [];

	// Check AD flag via raw DoH query
	let adFlag = false;
	try {
		if (rawQueryDNS) {
			const resp = await rawQueryDNS(domain, 'A', true, { timeout });
			adFlag = resp.AD === true;
		}
		// If no rawQueryDNS provided, we can't check AD flag — continue without it
	} catch {
		findings.push(
			createFinding('dnssec', 'DNSSEC check failed', 'medium', `Could not verify DNSSEC status for ${domain}. The DNS query failed.`),
		);
		return buildCheckResult('dnssec', findings);
	}

	// Query DNSKEY and DS records independently; default to empty on failure
	let dnskeyRecords: string[] = [];
	let dsRecords: string[] = [];

	try {
		dnskeyRecords = await queryDNS(domain, 'DNSKEY', { timeout });
	} catch {
		// Non-critical: DNSKEY query failure — treat as absent
	}

	try {
		dsRecords = await queryDNS(domain, 'DS', { timeout });
	} catch {
		// Non-critical: DS query failure — treat as absent
	}

	// Consolidated finding logic
	if (!adFlag && dnskeyRecords.length === 0 && dsRecords.length === 0) {
		// Fully absent — single MEDIUM
		findings.push(
			createFinding(
				'dnssec',
				'DNSSEC not enabled',
				'high',
				`DNSSEC is not configured for ${domain}. Without DNSSEC, DNS responses are not cryptographically verified, leaving SPF, DMARC, and DKIM records vulnerable to DNS-level manipulation.`,
				{ missingControl: true },
			),
		);
	} else if (dnskeyRecords.length > 0 && dsRecords.length === 0) {
		// DNSKEY published but no DS in parent zone — broken chain
		findings.push(
			createFinding(
				'dnssec',
				'DNSSEC chain of trust incomplete',
				'high',
				`DNSKEY records are published for ${domain} but no DS records exist in the parent zone. The chain of trust is broken — DNSSEC validation will fail.`,
			),
		);
	} else if (dnskeyRecords.length > 0 && dsRecords.length > 0 && !adFlag) {
		// Deployed but validation failing — worse than not having DNSSEC
		findings.push(
			createFinding(
				'dnssec',
				'DNSSEC validation failing',
				'high',
				`DNSKEY and DS records are present for ${domain} but the AD flag is not set. DNSSEC is deployed but validation is failing — this is worse than not having DNSSEC.`,
			),
		);
	}

	// Algorithm/digest audits (only when records exist)
	if (dnskeyRecords.length > 0) {
		findings.push(...auditDnskeyAlgorithms(domain, dnskeyRecords));
	}
	if (dsRecords.length > 0) {
		findings.push(...auditDsDigestTypes(domain, dsRecords));
	}

	// If DNSSEC is valid and no issues found (only info findings at most)
	if (findings.length === 0) {
		findings.push(
			createFinding(
				'dnssec',
				'DNSSEC enabled and validated',
				'info',
				`DNSSEC is properly configured for ${domain}. DNS responses are cryptographically verified.`,
			),
		);
	}

	return buildCheckResult('dnssec', findings);
}
