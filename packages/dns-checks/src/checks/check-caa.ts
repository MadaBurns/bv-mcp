// SPDX-License-Identifier: BUSL-1.1

/**
 * CAA (Certificate Authority Authorization) check.
 * Validates CAA DNS records that restrict which CAs can issue certificates.
 *
 * Copyright (c) 2023-2026 BLACKVEIL Security
 * Licensed under BUSL-1.1
 */

import type { CheckResult, DNSQueryFunction, Finding, RawDNSQueryFunction, ZoneContext } from '../types';
import { buildCheckResult, createFinding } from '../check-utils';
import {
	type CaaRecord,
	parseCaaRecord,
	getCaaConfiguredFinding,
	getCaaDnssecPairingFinding,
	getCaaParameterBindingFindings,
	getCaaTtlStalenessFinding,
	getCaaValidationFindings,
	summarizeCaaTags,
} from './caa-analysis';

/** Hard cap on ancestor hops during the RFC 8659 CAA climb — mirrors the zone-apex walk bound. */
const MAX_CAA_CLIMB_DEPTH = 8;

/** DNS RR type code for CAA (RFC 8659 §4.1). */
const CAA_RECORD_TYPE = 257;

/**
 * One CAA lookup at one owner name, plus the two enforceability signals the plain
 * `DNSQueryFunction` (`string[]`) projection discards.
 *
 * `minTtl` and `dnssecAuthenticated` are BOTH `undefined` unless a
 * `rawQueryDNS` was injected — they are not inferable from record data, so a
 * consumer that supplies only `queryDNS` gets byte-identical behaviour to before
 * and simply does not receive the enforceability findings.
 */
interface CaaLookup {
	records: CaaRecord[];
	/** Minimum TTL across the CAA RRset (a CA may reuse the whole RRset). */
	minTtl?: number;
	/** DoH `AD` flag on the response that carried the CAA RRset. */
	dnssecAuthenticated?: boolean;
}

function parseAll(data: string[]): CaaRecord[] {
	return data.map(parseCaaRecord).filter((record): record is CaaRecord => record !== null);
}

/**
 * Look up the CAA RRset at one owner name.
 *
 * When `rawQueryDNS` is available the lookup goes through it with the
 * DNSSEC-validation flag set (`cd=0`), because the SAME single response carries
 * the record data, its TTL and the `AD` flag together. This REPLACES the plain
 * `queryDNS` call rather than adding to it, so the enforceability signals cost
 * **zero additional subrequests** — which matters given the Workers per-invocation
 * subrequest ceiling that a fan-out `scan_domain` already operates near.
 */
async function lookupCaa(
	name: string,
	queryDNS: DNSQueryFunction,
	rawQueryDNS: RawDNSQueryFunction | undefined,
	timeout: number,
): Promise<CaaLookup> {
	if (!rawQueryDNS) {
		return { records: parseAll(await queryDNS(name, 'CAA', { timeout })) };
	}
	const resp = await rawQueryDNS(name, 'CAA', true, { timeout });
	// Filter by RR type exactly as the Worker's `queryDnsRecords` projection does,
	// so a CNAME/other record in the answer section can't be parsed as a CAA record.
	const answers = (resp.Answer ?? []).filter((answer) => answer.type === CAA_RECORD_TYPE);
	const ttls = answers.map((answer) => answer.TTL).filter((ttl): ttl is number => typeof ttl === 'number' && Number.isFinite(ttl));
	return {
		records: parseAll(answers.map((answer) => answer.data)),
		minTtl: ttls.length > 0 ? Math.min(...ttls) : undefined,
		// `AD !== true` is the honest reading: an answer the resolver did not
		// authenticate is exactly the "Insecure" determination (RFC 4035 §4.3) that
		// the BR §4.2.2 subsection 1.3 escape hatch turns on. Absent AD is treated as unsigned.
		dnssecAuthenticated: resp.AD === true,
	};
}

/**
 * Build the enforceability findings for a CAA RRset found at `ownerName`.
 * Empty when no `rawQueryDNS` was injected (nothing was measured — say nothing).
 */
function getCaaEnforceabilityFindings(lookup: CaaLookup, ownerName: string): Finding[] {
	const findings: Finding[] = [];
	const ttlFinding = getCaaTtlStalenessFinding(lookup.minTtl, ownerName);
	if (ttlFinding) findings.push(ttlFinding);
	if (lookup.dnssecAuthenticated !== undefined) {
		findings.push(getCaaDnssecPairingFinding(lookup.dnssecAuthenticated, ownerName));
	}
	return findings;
}

/** Enumerate label → floor ancestors (inclusive of both ends), bounded by MAX_CAA_CLIMB_DEPTH. */
function ancestorChainToFloor(label: string, floor: string): string[] {
	const chain: string[] = [];
	let current = label;
	for (let i = 0; i <= MAX_CAA_CLIMB_DEPTH; i += 1) {
		if (current.length < floor.length) break;
		chain.push(current);
		if (current === floor) break;
		const dot = current.indexOf('.');
		if (dot === -1) break;
		current = current.slice(dot + 1);
	}
	return chain;
}

/**
 * RFC 8659 CAA tree-climb: starting at the nearest ancestor above `start`, query CAA
 * up to (and including) `floor` — the PSL registrable domain, never crossed. Returns
 * the first non-empty parsed CAA RRset found. Fail-soft: a query error at a given
 * ancestor is treated as "no CAA here" and the climb continues to the next ancestor.
 */
async function climbForCaa(
	start: string,
	floor: string,
	queryDNS: DNSQueryFunction,
	rawQueryDNS: RawDNSQueryFunction | undefined,
	timeout: number,
): Promise<CaaLookup & { foundAt: string | null }> {
	const ancestors = ancestorChainToFloor(start, floor).slice(1);
	for (const ancestor of ancestors) {
		try {
			const lookup = await lookupCaa(ancestor, queryDNS, rawQueryDNS, timeout);
			if (lookup.records.length > 0) {
				return { ...lookup, foundAt: ancestor };
			}
		} catch {
			// Fail-soft: a resolver error at this ancestor doesn't fail the whole check —
			// treat as "no CAA at this level" and keep climbing toward the floor.
		}
	}
	return { records: [], foundAt: null };
}

/**
 * Check CAA records for a domain.
 * Validates that CAA records exist and are properly configured.
 *
 * Queries CAA record type and parses the raw DNS data into structured records.
 *
 * Pass `rawQueryDNS` to additionally assess whether the published policy is
 * *enforceable* — the CAA RRset TTL (which sets the CA reuse window) and whether
 * the answer was DNSSEC-authenticated. It is optional: without it the check
 * behaves exactly as before and emits no enforceability findings.
 */
export async function checkCAA(
	domain: string,
	queryDNS: DNSQueryFunction,
	options?: { timeout?: number; zone?: ZoneContext; rawQueryDNS?: RawDNSQueryFunction },
): Promise<CheckResult> {
	const rawQueryDNS = options?.rawQueryDNS;
	const timeout = options?.timeout ?? 5000;
	const findings: Finding[] = [];
	const zone = options?.zone;

	// No CAA lookup happens on this branch at all, so `recordPresent` is left undefined
	// ("not determined") — never false.
	if (zone && !zone.isApex && zone.delegationStatus === 'unknown') {
		return {
			...buildCheckResult('caa', [
				createFinding(
					'caa',
					'CAA records not assessed',
					'info',
					`Could not determine the authoritative zone for ${zone.scannedLabel} due to a transient DNS failure; CAA inheritance was not assessed.`,
				),
			]),
			checkStatus: 'error',
		};
	}

	let lookup: CaaLookup;
	try {
		lookup = await lookupCaa(domain, queryDNS, rawQueryDNS, timeout);
	} catch {
		// Transient resolver failure — we could not MEASURE the CAA posture. Mark the category
		// INCONCLUSIVE (checkStatus) so the scoring engine renormalizes over the remaining
		// categories instead of penalizing a possibly-healthy domain with a scored deficiency.
		// (The per-ancestor climb catch above is a legitimate fail-soft and stays unchanged.)
		// `recordPresent` likewise stays undefined: the query failed, so absence was never observed.
		return {
			...buildCheckResult('caa', [
				createFinding(
					'caa',
					'CAA records not assessed',
					'info',
					`Could not query CAA records for ${domain} due to a transient DNS failure; this control was not assessed.`,
				),
			]),
			checkStatus: 'error',
		};
	}

	const caaRecords: CaaRecord[] = lookup.records;

	if (caaRecords.length === 0) {
		// RFC 8659: CAA is located by climbing from the FQDN toward the apex. A non-apex
		// label with no CAA of its own inherits the nearest ancestor's CAA RRset. Bounded
		// by the PSL registrable floor (zone.registrableDomain). Apex targets (zone.isApex,
		// or no zone) skip this — byte-identical output. Gated strictly on isApex, NOT
		// delegationStatus: CAA inheritance follows the DNS tree, independent of NS delegation.
		if (zone && !zone.isApex) {
			const climbed = await climbForCaa(zone.scannedLabel, zone.registrableDomain, queryDNS, rawQueryDNS, timeout);
			if (climbed.records.length > 0 && climbed.foundAt) {
				findings.push(
					createFinding(
						'caa',
						'CAA inherited from parent zone',
						'info',
						`${domain} has no CAA records of its own; CAA policy is inherited from ${climbed.foundAt} per RFC 8659.`,
					),
				);
				findings.push(...getCaaValidationFindings(summarizeCaaTags(climbed.records)));
				// RFC 8657 binding is a property of the RRset that governs issuance — here the
				// ANCESTOR's, for the same reason enforceability is reported against it below.
				findings.push(...getCaaParameterBindingFindings(climbed.records));
				// Enforceability is a property of the RRset that actually governs issuance —
				// here the ANCESTOR's, so report it against `climbed.foundAt`, not `domain`.
				findings.push(...getCaaEnforceabilityFindings(climbed, climbed.foundAt));
				// A CAA RRset governing this name IS published — at the ancestor, per the RFC 8659
				// climb. Publication is what `recordPresent` reports, so inheritance counts as true.
				return buildCheckResult('caa', findings, true, true);
			}
			// Climb reached the registrable floor with nothing found — genuinely no CAA
			// anywhere up the tree. Fall through to the existing "No CAA records" finding.
		}

		// RFC 8659: absence of CAA means ANY CA may issue — a real defense-in-depth gap,
		// but NOT a zeroed control (CA/B-Forum hardening, not a NIST-DNS baseline). MEDIUM
		// (→85), no missingControl. Severity MUST stay medium: at high/critical the
		// "no … record" text would trip scoreIndicatesMissingControl and re-zero it.
		// (D3: a managed-CDN domain still owes a CAA record listing its CDN's CA.)
		findings.push(
			createFinding(
				'caa',
				'No CAA records',
				'medium',
				`No CAA records found for ${domain}. CAA records restrict which Certificate Authorities can issue certificates for your domain, preventing unauthorized issuance.`,
			),
		);
		// No CAA records observed → control absent (a query failure above leaves controlPresent undefined).
		return buildCheckResult('caa', findings, false, false);
	}

	findings.push(...getCaaValidationFindings(summarizeCaaTags(caaRecords)));

	// If no issues found. Evaluated on the TAG-validation findings only, and
	// therefore BEFORE the enforceability findings are appended: the "properly
	// configured" note is about tag completeness, and the enforceability signals
	// (one of which is always emitted when measured) would otherwise suppress it
	// permanently.
	if (findings.length === 0) {
		findings.push(getCaaConfiguredFinding());
	}

	// Appended alongside the enforceability findings, and for the same reason: this is
	// a BONUS signal about how tightly the grant is bound, not a tag-completeness
	// signal, so it must not suppress the "properly configured" note evaluated above.
	// Its prose is deliberately kept clear of the MISSING_CONTROL_REGEX vocabulary for
	// the same reason the "No CAA records" severity is pinned to medium below — see the
	// PROSE HAZARD note in caa-analysis.ts.
	findings.push(...getCaaParameterBindingFindings(caaRecords));

	findings.push(...getCaaEnforceabilityFindings(lookup, domain));

	// CAA records present → control present. Enforceability does NOT change this:
	// `controlPresent` feeds profile detection (`caaPass`), and an unsigned zone
	// still has a published CAA policy — the record exists, it is just strippable.
	return buildCheckResult('caa', findings, true, true);
}
