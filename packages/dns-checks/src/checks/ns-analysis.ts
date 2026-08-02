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
}

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
 * HIGH finding for partial lame delegation — some delegated nameservers do not
 * answer for the zone while others still do.
 *
 * This is the "Sitting Ducks" hijack precondition: the zone keeps resolving via the
 * healthy nameservers, so nothing looks broken, while an attacker who can claim the
 * non-responsive nameserver at its DNS provider gains authoritative control of the
 * zone without ever touching the registrar.
 */
export function getPartialLameDelegationFinding(domain: string, assessment: LameDelegationAssessment): Finding {
	return createFinding(
		'ns',
		'Lame delegation — nameserver does not answer for the zone',
		'high',
		`The parent zone delegates ${domain} to ${assessment.nonResolving.join(', ')}, but ${
			assessment.nonResolving.length === 1 ? 'that nameserver is' : 'those nameservers are'
		} not reachable for this zone (no address resolves). ${assessment.resolving.join(', ')} still answer${
			assessment.resolving.length === 1 ? 's' : ''
		}, so the domain keeps resolving and the fault is invisible in normal use. This is the "Sitting Ducks" precondition: an attacker who registers the unclaimed nameserver at its DNS provider becomes authoritative for ${domain} without touching the registrar. Remove the stale delegation at the registrar, or re-provision the zone on that nameserver.`,
		{
			lameDelegation: 'partial',
			nonResolvingNameservers: assessment.nonResolving,
			resolvingNameservers: assessment.resolving,
			...(assessment.unknown.length > 0 ? { unprobedNameservers: assessment.unknown } : {}),
		},
	);
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
