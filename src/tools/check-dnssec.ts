// SPDX-License-Identifier: BUSL-1.1

/**
 * DNSSEC (DNS Security Extensions) check tool.
 * Validates DNSSEC by checking the AD flag, querying for DNSKEY/DS records,
 * and auditing algorithm and digest type security.
 *
 * Finding consolidation logic:
 * - Fully absent (no AD, no DNSKEY, no DS) → single MEDIUM "DNSSEC not enabled"
 * - DNSKEY present but no DS → HIGH "DNSSEC chain of trust incomplete"
 * - DNSKEY + DS present but AD not set → HIGH "DNSSEC validation failing"
 * - All present and valid → INFO "DNSSEC enabled and validated"
 */

import { checkDnssec as dnsCheckDnssec, queryDnsRecords } from '../lib/dns';
import type { QueryDnsOptions } from '../lib/dns-types';
import { type CheckResult, type Finding, buildCheckResult, createFinding } from '../lib/scoring';
import { auditDnskeyAlgorithms, auditDsDigestTypes, parseDnskeyAlgorithm, parseDsRecord } from './dnssec-analysis';

export { parseDnskeyAlgorithm, parseDsRecord };

/**
 * Check DNSSEC configuration for a domain.
 * Verifies the AD (Authenticated Data) flag, checks for DNSKEY/DS records,
 * and audits algorithm and digest type security.
 */
export async function checkDnssec(domain: string, dnsOptions?: QueryDnsOptions): Promise<CheckResult> {
	const findings: Finding[] = [];

	// Check AD flag via DoH
	let adFlag = false;
	try {
		adFlag = await dnsCheckDnssec(domain, dnsOptions);
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
		dnskeyRecords = await queryDnsRecords(domain, 'DNSKEY', dnsOptions);
	} catch {
		// Non-critical: DNSKEY query failure — treat as absent
	}

	try {
		dsRecords = await queryDnsRecords(domain, 'DS', dnsOptions);
	} catch {
		// Non-critical: DS query failure — treat as absent
	}

	// Consolidated finding logic
	if (!adFlag && dnskeyRecords.length === 0 && dsRecords.length === 0) {
		// Fully absent → single MEDIUM
		findings.push(
			createFinding(
				'dnssec',
				'DNSSEC not enabled',
				'medium',
				`DNSSEC is not configured for ${domain}. Without DNSSEC, DNS responses are not cryptographically verified, leaving SPF, DMARC, and DKIM records vulnerable to DNS-level manipulation.`,
			),
		);
	} else if (dnskeyRecords.length > 0 && dsRecords.length === 0) {
		// DNSKEY published but no DS in parent zone → broken chain
		findings.push(
			createFinding(
				'dnssec',
				'DNSSEC chain of trust incomplete',
				'high',
				`DNSKEY records are published for ${domain} but no DS records exist in the parent zone. The chain of trust is broken — DNSSEC validation will fail.`,
			),
		);
	} else if (dnskeyRecords.length > 0 && dsRecords.length > 0 && !adFlag) {
		// Deployed but validation failing → worse than not having DNSSEC
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
