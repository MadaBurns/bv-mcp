// SPDX-License-Identifier: BUSL-1.1

/**
 * NS (Name Server) check.
 * Validates nameserver configuration for a domain.
 *
 * Copyright (c) 2023-2026 BLACKVEIL Security
 * Licensed under BUSL-1.1
 */

import type { CheckResult, DNSQueryFunction, Finding, RawDNSQueryFunction, ZoneContext } from '../types';
import { buildCheckResult, createFinding } from '../check-utils';
import {
	MAX_LAME_DELEGATION_PROBES,
	assessLameDelegation,
	getInheritedNsFinding,
	getNameserverDiversityFinding,
	getNsConfiguredFinding,
	getNsVisibilityFinding,
	getPartialLameDelegationFinding,
	getSingleNsFinding,
	getSoaValidationFindings,
	getTotalLameDelegationFinding,
	getUndelegatedInconclusiveFinding,
	normalizeNsRecords,
	parseSoaValues,
} from './ns-analysis';
import type { NameserverProbeOutcome, NameserverProbeResult } from './ns-analysis';

/** DoH numeric record types used by the nameserver-reachability probe. */
const DOH_TYPE_A = 1;
const DOH_TYPE_AAAA = 28;

/**
 * Probe one delegated nameserver for reachability.
 *
 * Workers cannot open a UDP socket to an individual nameserver, so authority is
 * established the only way a recursive-resolver vantage point allows: a delegated
 * nameserver with NO address cannot be queried by anyone, and therefore cannot be
 * answering authoritatively for the zone. That is exactly the delegation an attacker
 * claims in a Sitting Ducks hijack.
 *
 * AAAA is consulted ONLY when A came back empty, so an IPv6-only nameserver is not a
 * false positive while a healthy zone still costs one subrequest per nameserver.
 * A thrown probe yields `unknown` (never `no_address`) — a failure to measure must not
 * be reported as a failure.
 */
async function probeNameserverReachable(
	nameserver: string,
	rawQueryDNS: RawDNSQueryFunction,
	timeout: number,
): Promise<NameserverProbeOutcome> {
	try {
		const a = await rawQueryDNS(nameserver, 'A', false, { timeout });
		if ((a.Answer ?? []).some((ans) => ans.type === DOH_TYPE_A || ans.type === DOH_TYPE_AAAA)) {
			return 'resolves';
		}
	} catch {
		return 'unknown';
	}

	try {
		const aaaa = await rawQueryDNS(nameserver, 'AAAA', false, { timeout });
		if ((aaaa.Answer ?? []).some((ans) => ans.type === DOH_TYPE_AAAA)) {
			return 'resolves';
		}
	} catch {
		return 'unknown';
	}

	return 'no_address';
}

/**
 * Probe up to `MAX_LAME_DELEGATION_PROBES` delegated nameservers in parallel.
 * Never throws — every rejection degrades to an `unknown` outcome.
 */
async function probeDelegatedNameservers(
	nsRecords: string[],
	rawQueryDNS: RawDNSQueryFunction,
	timeout: number,
): Promise<NameserverProbeResult[]> {
	const targets = nsRecords.slice(0, MAX_LAME_DELEGATION_PROBES);
	const settled = await Promise.allSettled(targets.map((ns) => probeNameserverReachable(ns, rawQueryDNS, timeout)));
	return targets.map((nameserver, i) => {
		const outcome = settled[i];
		return { nameserver, outcome: outcome.status === 'fulfilled' ? outcome.value : 'unknown' };
	});
}

/**
 * Check nameserver configuration for a domain.
 * Validates NS records exist, checks for diversity, and verifies SOA configuration.
 *
 * Requires rawQueryDNS for SOA record parsing (needs answer type filtering)
 * and for domain resolution check (A record check for delegation-only zones).
 */
export async function checkNS(
	domain: string,
	queryDNS: DNSQueryFunction,
	options?: { timeout?: number; rawQueryDNS?: RawDNSQueryFunction; zone?: ZoneContext },
): Promise<CheckResult> {
	const timeout = options?.timeout ?? 5000;
	const rawQueryDNS = options?.rawQueryDNS;
	const findings: Finding[] = [];
	const zone = options?.zone;

	// Non-apex label: attribute posture to the zone apex instead of firing a false
	// "no NS records" finding. Apex targets (zone.isApex, or no zone) fall through
	// to the unchanged logic below → byte-identical output.
	if (zone && !zone.isApex) {
		if (zone.delegationStatus === 'unknown') {
			// Resolver could not classify — inconclusive, exclude from scoring, self-heal.
			const result = buildCheckResult('ns', [getUndelegatedInconclusiveFinding(domain)]);
			return { ...result, score: 0, passed: false, checkStatus: 'error', partial: true };
		}
		if (zone.delegationStatus === 'inherited') {
			findings.push(getInheritedNsFinding(zone));
			const single = getSingleNsFinding(zone.apexNsRecords);
			if (single) findings.push(single);
			const diversity = getNameserverDiversityFinding(zone.apexNsRecords);
			if (diversity) findings.push(diversity);
			return buildCheckResult('ns', findings);
		}
		// delegationStatus === 'undelegated_broken' falls through: the registrable apex
		// itself has no NS → the existing no-NS logic (below) correctly reports it.
	}

	let nsRecords: string[] = [];
	try {
		nsRecords = normalizeNsRecords(await queryDNS(domain, 'NS', { timeout }));
	} catch {
		// Transient resolver failure (timeout / SERVFAIL / network flake) — we could not
		// MEASURE the nameserver posture. Mark the category INCONCLUSIVE (checkStatus) so the
		// scoring engine renormalizes over the remaining categories instead of penalizing a
		// possibly-healthy domain with a scored "NS query failed" deficiency.
		return {
			...buildCheckResult('ns', [
				createFinding(
					'ns',
					'Nameserver configuration not assessed',
					'info',
					`Could not query nameserver (NS) records for ${domain} due to a transient DNS failure; this control was not assessed.`,
				),
			]),
			checkStatus: 'error',
		};
	}

	if (nsRecords.length === 0) {
		// Check if domain still resolves (e.g. delegation-only zones like govt.nz)
		let domainResolves = false;
		if (rawQueryDNS) {
			try {
				const aResp = await rawQueryDNS(domain, 'A', false, { timeout });
				domainResolves = (aResp.Answer ?? []).length > 0;
			} catch {
				/* ignore */
			}
		} else {
			// Fallback: try resolving A records via queryDNS
			try {
				const aRecords = await queryDNS(domain, 'A', { timeout });
				domainResolves = aRecords.length > 0;
			} catch {
				/* ignore */
			}
		}

		findings.push(getNsVisibilityFinding(domain, domainResolves));
		return buildCheckResult('ns', findings);
	}

	// Check for single nameserver (no redundancy) — RFC 1035 §2.2 mandates at least two
	const singleNsFinding = getSingleNsFinding(nsRecords);
	if (singleNsFinding) {
		findings.push(singleNsFinding);
	}

	const diversityFinding = getNameserverDiversityFinding(nsRecords);
	if (diversityFinding) {
		findings.push(diversityFinding);
	}

	// Lame delegation ("Sitting Ducks") — does every delegated nameserver actually
	// answer for this zone? Runs before the SOA/wildcard probes so the TOTAL case
	// short-circuits without spending further subrequests.
	if (rawQueryDNS) {
		const assessment = assessLameDelegation(await probeDelegatedNameservers(nsRecords, rawQueryDNS, timeout));
		if (assessment.verdict === 'total') {
			// Nothing in the delegation answered — a resolution failure, not a posture
			// reading. Mark the category INCONCLUSIVE so scoring EXCLUDES it (same shape as
			// the undelegated branch above) rather than zeroing a category we never measured.
			// The partial findings gathered so far are dropped deliberately: a category that
			// could not be measured must not also ship scored deficiencies.
			const result = buildCheckResult('ns', [getTotalLameDelegationFinding(domain, assessment)]);
			return { ...result, score: 0, passed: false, checkStatus: 'error', partial: true };
		}
		if (assessment.verdict === 'partial') {
			findings.push(getPartialLameDelegationFinding(domain, assessment));
		}
	}

	// Check SOA record exists and validate parameters
	if (rawQueryDNS) {
		try {
			const soaResp = await rawQueryDNS(domain, 'SOA', false, { timeout });
			const soaRecords = (soaResp.Answer ?? []).filter((a) => a.type === 6);
			if (soaRecords.length === 0) {
				findings.push(
					createFinding(
						'ns',
						'No SOA record',
						'medium',
						`No SOA (Start of Authority) record found for ${domain}. SOA records are required for proper DNS zone configuration.`,
					),
				);
			} else {
				const soaValues = parseSoaValues(soaRecords[0].data);
				if (soaValues) {
					findings.push(...getSoaValidationFindings(soaValues));
				}
			}
		} catch {
			// Non-critical
		}
	}

	// Wildcard DNS detection — probe a random subdomain
	try {
		const probeId = Math.random().toString(36).substring(2, 10);
		const probeFqdn = `_bv-probe-${probeId}.${domain}`;
		const probeRecords = await queryDNS(probeFqdn, 'A', { timeout });
		if (probeRecords.length > 0) {
			findings.push(
				createFinding(
					'ns',
					'Wildcard DNS detected',
					'medium',
					`Domain responds to arbitrary subdomains, indicating a wildcard DNS record (*.${domain}). Wildcard records can mask dangling CNAMEs, complicate subdomain enumeration defences, and make subdomain takeover detection unreliable.`,
					{ wildcardDetected: true, probeSubdomain: probeFqdn },
				),
			);
		}
	} catch {
		// Non-critical — wildcard detection failure should not affect NS check
	}

	// If no issues found
	if (findings.length === 0) {
		findings.push(getNsConfiguredFinding(nsRecords));
	}

	return buildCheckResult('ns', findings);
}
