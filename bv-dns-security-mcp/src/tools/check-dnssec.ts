/**
 * DNSSEC (DNS Security Extensions) check tool.
 * Validates DNSSEC by checking the AD flag and querying for DNSKEY/DS records.
 */

import { checkDnssec as dnsCheckDnssec, queryDnsRecords } from '../lib/dns';
import { type CheckResult, type Finding, buildCheckResult, createFinding } from '../lib/scoring';

/**
 * Check DNSSEC configuration for a domain.
 * Verifies the AD (Authenticated Data) flag and checks for DNSKEY/DS records.
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

	// Check for DNSKEY records
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
		}
	} catch {
		// Non-critical: DNSKEY query failure
	}

	// Check for DS records (delegation signer)
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
		}
	} catch {
		// Non-critical: DS query failure
	}

	// If DNSSEC is valid and no issues
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
