/**
 * DNSSEC (DNS Security Extensions) check tool.
 * Validates DNSSEC by checking the AD flag, querying for DNSKEY/DS records,
 * and auditing algorithm and digest type security.
 */

import { checkDnssec as dnsCheckDnssec, queryDnsRecords } from '../lib/dns';
import { type CheckResult, type Finding, buildCheckResult, createFinding } from '../lib/scoring';
import { auditDnskeyAlgorithms, auditDsDigestTypes, parseDnskeyAlgorithm, parseDsRecord } from './dnssec-analysis';

export { parseDnskeyAlgorithm, parseDsRecord };

/**
 * Check DNSSEC configuration for a domain.
 * Verifies the AD (Authenticated Data) flag, checks for DNSKEY/DS records,
 * and audits algorithm and digest type security.
 */
export async function checkDnssec(domain: string): Promise<CheckResult> {
	const findings: Finding[] = [];

	// Check AD flag via DoH
	let adFlag = false;
	try {
		adFlag = await dnsCheckDnssec(domain);
	} catch {
		findings.push(
			createFinding('dnssec', 'DNSSEC check failed', 'medium', `Could not verify DNSSEC status for ${domain}. The DNS query failed.`),
		);
		return buildCheckResult('dnssec', findings);
	}

	if (!adFlag) {
		findings.push(
			createFinding(
				'dnssec',
				'DNSSEC not validated',
				'high',
				`DNSSEC validation failed for ${domain}. The AD (Authenticated Data) flag is not set, meaning DNS responses are not cryptographically verified.`,
			),
		);
	}

	// Check for DNSKEY records and audit algorithms
	try {
		const dnskeyRecords = await queryDnsRecords(domain, 'DNSKEY');
		if (dnskeyRecords.length === 0 && !adFlag) {
			findings.push(
				createFinding(
					'dnssec',
					'No DNSKEY records',
					'high',
					`No DNSKEY records found for ${domain}. DNSSEC requires DNSKEY records to be published in the zone.`,
				),
			);
		} else if (dnskeyRecords.length > 0) {
			findings.push(...auditDnskeyAlgorithms(domain, dnskeyRecords));
		}
	} catch {
		// Non-critical: DNSKEY query failure
	}

	// Check for DS records and audit digest types
	try {
		const dsRecords = await queryDnsRecords(domain, 'DS');
		if (dsRecords.length === 0 && !adFlag) {
			findings.push(
				createFinding(
					'dnssec',
					'No DS records',
					'medium',
					`No DS (Delegation Signer) records found for ${domain}. DS records in the parent zone are needed to establish the DNSSEC chain of trust.`,
				),
			);
		} else if (dsRecords.length > 0) {
			findings.push(...auditDsDigestTypes(domain, dsRecords));
		}
	} catch {
		// Non-critical: DS query failure
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
