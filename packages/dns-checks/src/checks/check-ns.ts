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
	claimabilityProbeTargets,
	getInheritedNsFinding,
	getNameserverDiversityFinding,
	getNsConfiguredFinding,
	getNsVisibilityFinding,
	getPartialLameDelegationFinding,
	getSingleNsFinding,
	getSoaValidationFindings,
	getTotalLameDelegationFinding,
	getUndelegatedInconclusiveFinding,
	nameserverBaseDomain,
	normalizeNsRecords,
	parseSoaValues,
} from './ns-analysis';
import type { NameserverProbeOutcome, NameserverProbeResult } from './ns-analysis';

/** DoH numeric record types used by the nameserver-reachability probe. */
const DOH_TYPE_A = 1;
const DOH_TYPE_AAAA = 28;

/**
 * RFC 1035 §4.1.1 RCODE 3 — the name provably does not exist.
 *
 * NXDOMAIN is a MEASUREMENT; SERVFAIL (2) and REFUSED (5) are measurement FAILURES and
 * must never reach the claimability path. Same distinction `check-dane.ts` draws.
 */
const RCODE_NXDOMAIN = 3;

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
): Promise<{ outcome: NameserverProbeOutcome; hostNxdomain: boolean }> {
	let hostNxdomain = false;

	try {
		const a = await rawQueryDNS(nameserver, 'A', false, { timeout });
		if ((a.Answer ?? []).some((ans) => ans.type === DOH_TYPE_A || ans.type === DOH_TYPE_AAAA)) {
			return { outcome: 'resolves', hostNxdomain: false };
		}
		hostNxdomain = a.Status === RCODE_NXDOMAIN;
	} catch {
		return { outcome: 'unknown', hostNxdomain: false };
	}

	try {
		const aaaa = await rawQueryDNS(nameserver, 'AAAA', false, { timeout });
		if ((aaaa.Answer ?? []).some((ans) => ans.type === DOH_TYPE_AAAA)) {
			return { outcome: 'resolves', hostNxdomain: false };
		}
		// BOTH families must agree the name does not exist. An adapter that omits `Status`
		// leaves this false, which is the conservative direction: no rcode, no claim.
		hostNxdomain = hostNxdomain && aaaa.Status === RCODE_NXDOMAIN;
	} catch {
		return { outcome: 'unknown', hostNxdomain: false };
	}

	return { outcome: 'no_address', hostNxdomain };
}

/**
 * Establish whether a dead nameserver is CLAIMABLE — the difference between a lame
 * delegation and a demonstrated Sitting Ducks hijack precondition.
 *
 * The test is direct: is the nameserver's registrable base domain itself unregistered?
 * An NXDOMAIN answer on its NS RRset means nobody owns the name, so an attacker can
 * register it, point it at their own infrastructure, and become authoritative for the
 * victim zone. That is the one claimability shape a recursive-resolver vantage point can
 * PROVE, and proving it is the precondition for stamping the finding `verified`.
 *
 * NOT IMPLEMENTED, DELIBERATELY: the second claimability shape — a nameserver hostname
 * that resolves normally at a self-service DNS provider which will let any account add
 * the unconfigured zone. That variant is invisible to this probe (the host HAS an
 * address, so it never reaches `no_address` at all), and a provider-name fingerprint
 * would be asserting hijackability from a vendor string rather than from evidence. The
 * metadata carries `claimabilityBasis` so a future, actually-measured basis can be added
 * without reshaping the finding.
 *
 * Query budget: bounded by `MAX_LAME_DELEGATION_PROBES` distinct base domains, spent
 * ONLY on the `partial` verdict and ONLY for nameserver hosts that answered NXDOMAIN. A
 * healthy zone, a total-lame zone, and an indeterminate zone all cost zero extra. A
 * thrown probe yields "not claimable" — a failure to measure never manufactures a claim.
 */
async function resolveClaimableNameservers(
	targets: string[],
	rawQueryDNS: RawDNSQueryFunction,
	timeout: number,
): Promise<string[]> {
	const byBase = new Map<string, string[]>();
	for (const nameserver of targets) {
		const base = nameserverBaseDomain(nameserver);
		if (base === null) continue;
		const group = byBase.get(base);
		if (group) group.push(nameserver);
		else if (byBase.size < MAX_LAME_DELEGATION_PROBES) byBase.set(base, [nameserver]);
	}

	const bases = [...byBase.keys()];
	const settled = await Promise.allSettled(bases.map((base) => rawQueryDNS(base, 'NS', false, { timeout })));

	const claimable: string[] = [];
	bases.forEach((base, i) => {
		const outcome = settled[i];
		if (outcome.status !== 'fulfilled') return;
		if (outcome.value.Status !== RCODE_NXDOMAIN) return;
		claimable.push(...(byBase.get(base) ?? []));
	});

	// Preserve the delegation's own ordering so the finding prose is stable across runs.
	return targets.filter((ns) => claimable.includes(ns));
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
		const probe = settled[i];
		if (probe.status !== 'fulfilled') return { nameserver, outcome: 'unknown', hostNxdomain: false };
		return { nameserver, outcome: probe.value.outcome, hostNxdomain: probe.value.hostNxdomain };
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
		const probes = await probeDelegatedNameservers(nsRecords, rawQueryDNS, timeout);
		const assessment = assessLameDelegation(probes);
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
			// Claimability is established ONLY here — inside the one verdict whose finding
			// makes a hijack claim, and only for hosts that answered NXDOMAIN. See
			// `resolveClaimableNameservers` for the budget and for what "verified" attests.
			const claimable = await resolveClaimableNameservers(claimabilityProbeTargets(probes), rawQueryDNS, timeout);
			findings.push(getPartialLameDelegationFinding(domain, assessment, claimable));
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
