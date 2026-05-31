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
import { auditDnskeyAlgorithms, auditDsDigestTypes, auditNsec3Params } from './dnssec-analysis';
import { isRegistryManagedDnssec } from './registry-managed-dnssec';

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

	// Query DNSKEY, DS, and NSEC3PARAM records independently; default to empty on failure
	let dnskeyRecords: string[] = [];
	let dsRecords: string[] = [];
	let nsec3ParamRecords: string[] = [];

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

	try {
		nsec3ParamRecords = await queryDNS(domain, 'NSEC3PARAM', { timeout });
	} catch {
		// Non-critical: NSEC3PARAM query failure — domain may use NSEC instead of NSEC3
	}

	// Consolidated finding logic
	if (!adFlag && dnskeyRecords.length === 0 && dsRecords.length === 0) {
		// Fully absent — CRITICAL, but NOT a missing-control zero. NIST SP 800-81r3
		// (Mar 2026) makes DNSSEC a baseline deployment goal and RFC 9364 (BCP 237)
		// states origin-authentication via DNSSEC is "the best current practice", so an
		// unsigned PUBLIC zone is a near-failing deficiency (critical, −40 → ~60) — far
		// heavier than the previous lenient 75. We do NOT set `missingControl: true`
		// (which would zero the category): DNSSEC is one of several integrity controls,
		// not a sole baseline, so a heavy proportionate deduction is the faithful read.
		// The detail text deliberately avoids "no … record / missing / not found" so
		// `scoreIndicatesMissingControl` cannot auto-zero a critical finding.
		findings.push(
			createFinding(
				'dnssec',
				'DNSSEC not enabled',
				'critical',
				`DNSSEC is not configured for ${domain}. Without DNSSEC, DNS responses are not cryptographically verified, leaving SPF, DMARC, and DKIM records vulnerable to DNS-level manipulation.`,
			),
		);
	} else if (dnskeyRecords.length > 0 && dsRecords.length === 0) {
		// DNSKEY published but no DS in parent zone — broken chain. BOGUS to any
		// validating resolver (worse than unsigned): explicit missingControl → score 0.
		findings.push(
			createFinding(
				'dnssec',
				'DNSSEC chain of trust incomplete',
				'high',
				`DNSKEY records are published for ${domain} but no DS records exist in the parent zone. The chain of trust is broken — DNSSEC validation will fail.`,
				{ missingControl: true },
			),
		);
	} else if (dnskeyRecords.length > 0 && dsRecords.length > 0 && !adFlag) {
		// Deployed but validation failing (BOGUS) — worse than not having DNSSEC.
		// DNSSEC-1 decision: explicit missingControl → score 0 (same BOGUS principle as
		// the broken chain — a validating resolver rejects the zone's data outright).
		findings.push(
			createFinding(
				'dnssec',
				'DNSSEC validation failing',
				'high',
				`DNSKEY and DS records are present for ${domain} but the AD flag is not set. DNSSEC is deployed but validation is failing — this is worse than not having DNSSEC.`,
				{ missingControl: true },
			),
		);
	}

	// Registry-managed DNSSEC: when the chain validates (AD set + DS + DNSKEY), some
	// ccTLD registries auto-signed the zone rather than the owner. The zone is still
	// protected, so this is a MODERATE deduction (medium → ~85), not the punitive 50
	// bv-web historically used — 50 would rank a validated zone BELOW an unsigned one
	// (60), which is incoherent. Detection is fail-safe (false when indeterminate).
	if (adFlag && dnskeyRecords.length > 0 && dsRecords.length > 0) {
		if (await isRegistryManagedDnssec(domain, queryDNS, timeout)) {
			findings.push(
				createFinding(
					'dnssec',
					'DNSSEC is registry-managed',
					'medium',
					`The DNSSEC chain for ${domain} validates, but the zone is signed by its ccTLD registry rather than independently configured by the domain owner. The zone is cryptographically protected, but the owner has less direct control over key management.`,
				),
			);
		}
	}

	// Algorithm/digest audits (only when records exist)
	if (dnskeyRecords.length > 0) {
		findings.push(...auditDnskeyAlgorithms(domain, dnskeyRecords));
	}
	if (dsRecords.length > 0) {
		findings.push(...auditDsDigestTypes(domain, dsRecords));
	}
	if (nsec3ParamRecords.length > 0) {
		findings.push(...auditNsec3Params(domain, nsec3ParamRecords));
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
