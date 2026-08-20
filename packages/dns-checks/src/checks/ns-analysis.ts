// SPDX-License-Identifier: BUSL-1.1

/**
 * NS record analysis helpers.
 * Pure functions for analyzing nameserver configuration.
 *
 * Copyright (c) 2023-2026 BLACKVEIL Security
 * Licensed under BUSL-1.1
 */

import type { Finding, ZoneContext } from '../types';
import { createFinding } from '../check-utils';

const RESILIENT_NS_PROVIDERS: Record<string, string> = {
	'cloudflare.com':
		"Cloudflare's anycast network provides built-in geographic redundancy, so this is lower risk than single-provider setups on traditional DNS hosts.",
	'awsdns.com': "AWS Route 53's anycast network provides built-in geographic redundancy, so this is lower risk than single-provider setups on traditional DNS hosts.",
	'google.com':
		'Google Cloud DNS uses globally distributed authoritative infrastructure, so this is lower risk than single-provider setups on traditional DNS hosts.',
};

export type ParsedSoaValues = {
	refresh: number | null;
	retry: number | null;
	expire: number | null;
	minimum: number | null;
};

export function normalizeNsRecords(nsRecords: string[]): string[] {
	return nsRecords.map((record) => record.replace(/\.$/, '').toLowerCase());
}

export function getNsVisibilityFinding(domain: string, domainResolves: boolean): Finding {
	if (domainResolves) {
		return createFinding(
			'ns',
			'NS records not directly visible',
			'low',
			`No NS records returned for ${domain} directly, but the domain resolves. NS records may be managed at a parent zone.`,
		);
	}

	// `domainResolves: false` is the STRUCTURED marker the scoring engine's non-resolving
	// gate keys on (see scoring/resolution.ts). This branch is the only place in the package
	// that has actually determined non-resolution — NS returned nothing AND the A-record
	// fallback above returned nothing — so it is the only honest place to assert it.
	// Structured, not prose: the title is customer-facing copy and will be reworded.
	return createFinding(
		'ns',
		'No NS records found',
		'critical',
		`No nameserver records found for ${domain}. Without NS records, the domain cannot resolve.`,
		{ missingControl: true, domainResolves: false },
	);
}

export function getSingleNsFinding(nsRecords: string[]): Finding | null {
	if (nsRecords.length !== 1) {
		return null;
	}

	return createFinding(
		'ns',
		'Single nameserver (violates RFC 1035 §2.2)',
		'high',
		`Only one nameserver found (${nsRecords[0]}). RFC 1035 §2.2 mandates at least two nameservers for every zone to ensure redundancy and availability.`,
	);
}

export function getNameserverDiversityFinding(nsRecords: string[]): Finding | null {
	const providerDomains = new Set(
		nsRecords.map((record) => {
			const parts = record.split('.');
			return parts.slice(-2).join('.');
		}),
	);

	if (providerDomains.size !== 1 || nsRecords.length <= 1) {
		return null;
	}

	const providerDomain = [...providerDomains][0];
	const providerContext =
		RESILIENT_NS_PROVIDERS[providerDomain] ?? 'Consider using nameservers from different providers for better resilience.';

	return createFinding(
		'ns',
		'Low nameserver diversity',
		'low',
		`All nameservers are under ${providerDomain}. ${providerContext} For maximum independence, a secondary DNS provider can be added.`,
	);
}

export function parseSoaValues(soaData: string): ParsedSoaValues | null {
	const soaParts = soaData.trim().split(/\s+/);
	if (soaParts.length < 7) {
		return null;
	}

	const refresh = parseInt(soaParts[3], 10);
	const retry = parseInt(soaParts[4], 10);
	const expire = parseInt(soaParts[5], 10);
	const minimum = parseInt(soaParts[6], 10);

	return {
		refresh: Number.isNaN(refresh) ? null : refresh,
		retry: Number.isNaN(retry) ? null : retry,
		expire: Number.isNaN(expire) ? null : expire,
		minimum: Number.isNaN(minimum) ? null : minimum,
	};
}

export function getSoaValidationFindings(soaValues: ParsedSoaValues): Finding[] {
	const findings: Finding[] = [];

	if (soaValues.refresh !== null) {
		if (soaValues.refresh < 300) {
			findings.push(
				createFinding(
					'ns',
					'SOA refresh interval too short',
					'low',
					`SOA refresh interval is ${soaValues.refresh}s (< 300s / 5 min). Very short refresh intervals increase DNS traffic and load on nameservers.`,
				),
			);
		} else if (soaValues.refresh > 86400) {
			findings.push(
				createFinding(
					'ns',
					'SOA refresh interval too long',
					'low',
					`SOA refresh interval is ${soaValues.refresh}s (> 86400s / 1 day). Long refresh intervals delay propagation of zone changes to secondary nameservers.`,
				),
			);
		}
	}

	if (soaValues.retry !== null && soaValues.refresh !== null && soaValues.retry > soaValues.refresh) {
		findings.push(
			createFinding(
				'ns',
				'SOA retry exceeds refresh interval',
				'low',
				`SOA retry interval (${soaValues.retry}s) exceeds refresh interval (${soaValues.refresh}s). Retry should be shorter than refresh to allow timely recovery after failed zone transfers.`,
			),
		);
	}

	if (soaValues.expire !== null && soaValues.expire < 604800) {
		findings.push(
			createFinding(
				'ns',
				'SOA expire too short',
				'medium',
				`SOA expire value is ${soaValues.expire}s (< 604800s / 1 week). If secondary nameservers cannot reach the primary for this duration, they will stop serving the zone.`,
			),
		);
	}

	if (soaValues.minimum !== null && soaValues.minimum > 86400) {
		findings.push(
			createFinding(
				'ns',
				'SOA negative cache TTL too long',
				'low',
				`SOA minimum (negative cache TTL) is ${soaValues.minimum}s (> 86400s / 1 day). This means NXDOMAIN responses will be cached for extended periods, delaying visibility of new records.`,
			),
		);
	}

	return findings;
}

export function getNsConfiguredFinding(nsRecords: string[]): Finding {
	return createFinding('ns', 'Nameservers properly configured', 'info', `${nsRecords.length} nameservers found: ${nsRecords.join(', ')}`);
}

/**
 * INFO finding for a non-apex label that inherits its NS posture from the zone
 * apex. Not a missing control — the label legitimately has no NS RRset of its own.
 */
export function getInheritedNsFinding(zone: ZoneContext): Finding {
	return createFinding(
		'ns',
		`${zone.scannedLabel} is not a delegated zone`,
		'info',
		`${zone.scannedLabel} has no nameserver records of its own — this is normal for a subdomain that is not separately delegated. ` +
			`Nameserver posture is inherited from the zone apex ${zone.zoneApex} (${zone.apexNsRecords.join(', ')}).`,
		{ inheritedFromApex: zone.zoneApex },
	);
}

// ---------------------------------------------------------------------------
// Lame delegation ("Sitting Ducks")
// ---------------------------------------------------------------------------

/**
 * Hard cap on how many delegated nameservers are probed for lame delegation.
 *
 * A cold `scan_domain` already fans out ~20 subrequests; each probed nameserver
 * costs one A query, plus one AAAA query ONLY when the A query came back empty
 * (so a healthy zone costs exactly one query per nameserver). With this cap the
 * NS check adds at most 4 subrequests in the healthy case and at most 8 in the
 * all-broken case — bounded regardless of how many NS records a zone publishes.
 *
 * Four is enough evidence: the finding needs one working nameserver and one
 * broken one to establish the partial-lame shape, and RFC 1035 §2.2 zones
 * publish 2–4 in practice.
 */
export const MAX_LAME_DELEGATION_PROBES = 4;

/**
 * Per-nameserver probe outcome.
 *
 * - `resolves` — the nameserver hostname has an address, so queries can reach it.
 * - `no_address` — DETERMINED to have no A/AAAA address. The parent delegates to a
 *   host that cannot serve the zone; this is the Sitting Ducks precondition.
 * - `unknown` — the probe itself failed (resolver timeout/network error). NOT
 *   evidence of anything: a failure to MEASURE is never scored as a failure.
 */
export type NameserverProbeOutcome = 'resolves' | 'no_address' | 'unknown';

/** One nameserver's probe result. */
export interface NameserverProbeResult {
	nameserver: string;
	outcome: NameserverProbeOutcome;
	/**
	 * The nameserver HOSTNAME answered NXDOMAIN (RCODE 3) — the name provably does not
	 * exist, as opposed to existing with no address (NODATA) or the resolver having
	 * failed (SERVFAIL/REFUSED, which are not measurements at all).
	 *
	 * This is the ONLY gate on spending a claimability probe. It is not itself evidence
	 * of claimability: `ns1.provider.example` can be NXDOMAIN while `provider.example`
	 * is firmly registered by its owner.
	 */
	hostNxdomain?: boolean;
}

/**
 * The exact phrases `inferFindingConfidence` (scoring/model.ts) demotes a finding to
 * `heuristic` on, mirrored here so the NS check's prose can be TESTED against them.
 *
 * WHY THIS EXISTS. The escalation only registers because the finding carries an
 * explicit `metadata.confidence` — and an explicit stamp outranks the prose sniff, so
 * the claimable branch cannot be disarmed by a copy edit. The NOT-shown-claimable
 * branch is the one that matters: it is deliberately `deterministic`, and a future copy
 * edit that reached for a softening word ("this could indicate…", "a potential
 * hijack…") would silently reclassify it as `heuristic`. Same score either way, but a
 * reviewer reading `heuristic` would draw the wrong conclusion about what was measured.
 *
 * Mirrored, not imported, on purpose: this is a MIRROR under test, and `scoring/model.ts`
 * owns the runtime list. If the two drift, the audit that consumes this constant is the
 * thing that must be re-read — not silently re-pointed at the source it is checking.
 */
export const CONFIDENCE_DEMOTING_PHRASES = [
	'common selectors',
	'among tested selectors',
	'inferred',
	'manual review',
	'possible',
	'potential',
	'could indicate',
] as const;

/**
 * Verdict over the probed set.
 *
 * - `healthy` — every determinate probe resolved.
 * - `partial` — at least one resolved AND at least one determinately did not.
 *   The exploitable shape: the zone still answers (so nothing looks broken to the
 *   owner) while a delegated nameserver sits unclaimed.
 * - `total` — at least one determinate `no_address` and NOTHING resolved. That is a
 *   whole-zone resolution failure, not a posture deficiency, so it must route to
 *   the inconclusive path rather than score 0.
 * - `indeterminate` — no determinate outcome at all (every probe errored). Emits
 *   nothing and leaves the rest of the NS result untouched.
 */
export type LameDelegationVerdict = 'healthy' | 'partial' | 'total' | 'indeterminate';

export interface LameDelegationAssessment {
	verdict: LameDelegationVerdict;
	resolving: string[];
	nonResolving: string[];
	unknown: string[];
}

/**
 * Classify a set of per-nameserver probe outcomes into a lame-delegation verdict.
 *
 * Pure — the I/O lives in `checkNS`. `unknown` outcomes are deliberately excluded
 * from the verdict arithmetic so a flaky resolver can never manufacture a `total`
 * (or suppress a real `partial`).
 */
export function assessLameDelegation(results: NameserverProbeResult[]): LameDelegationAssessment {
	const resolving = results.filter((r) => r.outcome === 'resolves').map((r) => r.nameserver);
	const nonResolving = results.filter((r) => r.outcome === 'no_address').map((r) => r.nameserver);
	const unknown = results.filter((r) => r.outcome === 'unknown').map((r) => r.nameserver);

	let verdict: LameDelegationVerdict;
	if (nonResolving.length === 0) {
		verdict = resolving.length > 0 ? 'healthy' : 'indeterminate';
	} else if (resolving.length > 0) {
		verdict = 'partial';
	} else {
		verdict = 'total';
	}

	return { verdict, resolving, nonResolving, unknown };
}

/**
 * CRITICAL finding for partial lame delegation — some delegated nameservers do not
 * answer for the zone while others still do.
 *
 * This is the "Sitting Ducks" hijack precondition: the zone keeps resolving via the
 * healthy nameservers, so nothing looks broken, while an attacker who can claim the
 * non-responsive nameserver at its DNS provider gains authoritative control of the
 * zone without ever touching the registrar.
 *
 * TWO BRANCHES, AND THE SPLIT IS THE POINT.
 * The severity is `critical` either way — a delegation that does not answer is a
 * first-class defect. What differs is the ATTESTATION, and therefore the score.
 *
 * - `claimable` non-empty — the dead nameserver's registrable base domain was probed
 *   and answered NXDOMAIN. It is unregistered; anyone can register it and serve the
 *   zone. That is the hijack precondition PROVEN, so the finding is stamped
 *   `confidence: 'verified'`, which is what makes the engine's verified-critical
 *   count (and its −15 overall penalty) fire.
 *
 * - `claimable` empty — the delegation is lame, but nothing showed the dead nameserver
 *   can be taken over: SERVFAIL is a resolver failure rather than a measurement, and a
 *   registered base domain belongs to somebody already. The finding stays
 *   `deterministic`, moves no overall score, and — critically — its prose does NOT
 *   assert hijackability. Publishing the Sitting Ducks sentence here would be an
 *   over-claim on a customer-visible surface backed by evidence we do not have.
 *
 * Deliberately does NOT set `missingControl`. The domain HAS nameservers; some are
 * dead. `missingControl` is also the ONLY route into the 64 critical-gap ceiling, which
 * is a separate product decision and explicitly out of scope for this escalation.
 */
export function getPartialLameDelegationFinding(
	domain: string,
	assessment: LameDelegationAssessment,
	claimable: string[] = [],
): Finding {
	const plural = assessment.nonResolving.length === 1 ? 'that nameserver is' : 'those nameservers are';
	const answers = assessment.resolving.length === 1 ? 's' : '';
	const shared =
		`The parent zone delegates ${domain} to ${assessment.nonResolving.join(', ')}, but ${plural} not reachable for this zone ` +
		`(no address resolves). ${assessment.resolving.join(', ')} still answer${answers}, so the domain keeps resolving and the ` +
		`fault is invisible in normal use.`;

	const shown = claimable.length > 0;
	const detail = shown
		? `${shared} This is the "Sitting Ducks" precondition, and it is confirmed here: ${claimable.join(', ')} ` +
			`${claimable.length === 1 ? 'sits' : 'sit'} under a base domain that is not registered, so an attacker who registers it ` +
			`becomes authoritative for ${domain} without touching the registrar. Remove the stale delegation at the registrar, or ` +
			`re-provision the zone on that nameserver.`
		: // Prose constraint, not style: `scoreIndicatesMissingControl` runs MISSING_CONTROL_REGEX
			// (/no .{1,64} record|missing|required|not found/i) over BOTH title and detail, and a
			// `critical`+`deterministic` match ZEROES the whole ns category — a far bigger score
			// move than the escalation itself, from a single adjective. An earlier draft of this
			// sentence said "rather than a missing name" and silently dropped ns from 60 to 0.
			`${shared} This run did not establish that the stale delegation can be taken over — the base domain behind it is ` +
			`registered, or the reachability failure was a resolver error rather than an absent name — so no hijack claim is ` +
			`made here. Remove the stale delegation at the registrar, or re-provision the zone on that nameserver.`;

	return createFinding('ns', 'Lame delegation — nameserver does not answer for the zone', 'critical', detail, {
		lameDelegation: 'partial',
		// DECLARED, never inferred. `verifiedCriticalCount` reads this and nothing else;
		// an unstamped critical finding is worth exactly zero points.
		confidence: shown ? 'verified' : 'deterministic',
		nonResolvingNameservers: assessment.nonResolving,
		resolvingNameservers: assessment.resolving,
		...(shown ? { claimableNameservers: claimable, claimabilityBasis: 'base_domain_unregistered' } : {}),
		...(assessment.unknown.length > 0 ? { unprobedNameservers: assessment.unknown } : {}),
	});
}

/**
 * Best-effort registrable base domain for a NAMESERVER hostname — the last two labels.
 *
 * Deliberately the same naive heuristic `getNameserverDiversityFinding` already uses,
 * and deliberately NOT PSL-accurate: `zone.registrableDomain` is supplied by the caller
 * for the SCANNED domain only, and nameserver hosts live under arbitrary suffixes this
 * package has no PSL for.
 *
 * The inaccuracy is one-directional and therefore safe HERE. Under a multi-label
 * suffix, `ns1.example.co.uk` yields `co.uk`, which is registered and answers NOERROR —
 * so the claimability probe reports NOT claimable and the finding stays unattested. The
 * heuristic can suppress a real claim; it cannot manufacture one against a registered
 * suffix. Returns `null` for anything with fewer than two labels, which cannot be a
 * registrable name.
 */
export function nameserverBaseDomain(nameserver: string): string | null {
	const labels = nameserver.replace(/\.$/, '').toLowerCase().split('.').filter(Boolean);
	if (labels.length < 2) return null;
	return labels.slice(-2).join('.');
}

/**
 * The nameservers worth spending a claimability probe on: determinately address-less
 * AND provably non-existent as a NAME (NXDOMAIN).
 *
 * Everything else is excluded on purpose. A NODATA host exists, so its base domain is
 * registered by definition. A SERVFAIL/`unknown` host was not measured at all. Neither
 * can support a hijack claim, and neither should cost a subrequest.
 */
export function claimabilityProbeTargets(results: NameserverProbeResult[]): string[] {
	return results.filter((r) => r.outcome === 'no_address' && r.hostNxdomain === true).map((r) => r.nameserver);
}

/**
 * Inconclusive finding for TOTAL lame delegation — no delegated nameserver resolves.
 *
 * Deliberately NOT a scored deficiency. When nothing in the delegation answers, the
 * NS posture was not measured, it was merely unobservable; scoring it 0 would penalize
 * a category we never got a reading for (the same rule `getUndelegatedInconclusiveFinding`
 * exists for). Carries the transient shape so scoring EXCLUDES the category.
 *
 * Deliberately does NOT set `domainResolves: false` — that key is the package's
 * non-resolving guard and belongs only to `getNsVisibilityFinding`, which has actually
 * probed NS *and* A. This probe only establishes that the nameserver HOSTS have no
 * address, which cannot distinguish a dead zone from a resolver-side outage.
 */
export function getTotalLameDelegationFinding(domain: string, assessment: LameDelegationAssessment): Finding {
	return createFinding(
		'ns',
		'Nameserver reachability not assessed',
		'low',
		`None of the nameservers delegated for ${domain} (${assessment.nonResolving.join(', ')}) resolved to an address during this run. That is a resolution failure rather than a measurable nameserver posture, so this control was not assessed.`,
		{ errorKind: 'dns_error', inconclusive: true, lameDelegation: 'total', nonResolvingNameservers: assessment.nonResolving },
	);
}

/**
 * Inconclusive finding when the zone-apex walk could not be resolved (resolver
 * timeout/error). Carries the transient shape so scoring EXCLUDES the category
 * rather than emitting a false CRITICAL.
 */
export function getUndelegatedInconclusiveFinding(domain: string): Finding {
	return createFinding(
		'ns',
		'NS zone resolution inconclusive',
		'low',
		`Could not determine the governing zone for ${domain} (the nameserver lookup did not complete). Nameserver posture is unknown for this run.`,
		{ errorKind: 'dns_error', inconclusive: true },
	);
}
