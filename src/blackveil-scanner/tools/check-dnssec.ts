/**
 * DNSSEC (DNS Security Extensions) check tool for BLACKVEIL Scanner npm package.
 * Validates DNSSEC by checking the AD flag and querying for DNSKEY/DS records.
 */

import { queryDns, queryDnsRecords } from '../lib/dns';
import { buildCheckResult, createFinding, type CheckResult, type Finding } from '../lib/scoring';

/**
 * Check DNSSEC configuration for a domain.
 * Verifies the AD (Authenticated Data) flag and checks for DNSKEY/DS records.
 */
export async function checkDnssec(domain: string): Promise<CheckResult> {
	const findings: Finding[] = [];

	let adFlag = false;
	try {
		const resp = await queryDns(domain, 'A', true);
		adFlag = resp.AD;
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
	} catch {}

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
	} catch {}

	return buildCheckResult('dnssec', findings);
}
