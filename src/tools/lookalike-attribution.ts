// SPDX-License-Identifier: BUSL-1.1

/**
 * Attribution predicates for the lookalike check — the "whose domain is this"
 * corroboration layer (issue #263 same-entity correlation, and the brand-held
 * defensive-registration signal).
 *
 * Extracted VERBATIM from `check-lookalikes.ts` (pure split, no behaviour
 * change). These are AXIS 1 (attribution) inputs only: nothing here may move a
 * threat severity, and — Ruling A — nothing here may produce an `owned_by_seed`
 * ownership verdict of its own. The ONE exception is
 * {@link refineOwnershipBySeedAuthorisation} (#864), which produces no
 * verdict itself either: it gathers the MX pre-filter and the SEED-published
 * DMARC report-authorisation result and hands them to `classifyOwnership()`,
 * whose step 5b is the single place that conjunction is decided (see the
 * amendment in `src/lib/ownership-attribution.ts`'s file header).
 */

import { evaluateDefensiveRegistration, type DefensiveReason } from '../lib/brand-defensive-registration';
import { mapConcurrent } from '../lib/map-concurrent';
import { classifyOwnership, mxRoutedIntoSeed, type DmarcReportAuthorisation, type OwnershipAssessment } from '../lib/ownership-attribution';
import { isRedactedRegistrantOrg } from './check-rdap-lookup';
import { SEED_AUTHORISATION_CONCURRENCY, type LookalikeResult } from './lookalike-dns';
import type { LookalikeCorroborators } from './lookalike-enrichment';
import { calibrateLookalikeSeverity, type LookalikeSeverity } from './lookalike-severity';

/**
 * Cap on the number of medium/high-severity lookalikes for which we attempt
 * the same-entity (shared-registrant) RDAP correlation. RDAP registrant data
 * is already harvested from the single enrichment fetch per candidate
 * (`probeRdap`), so the cost is bounded by the enrichment set; this cap
 * is a defensive ceiling so a pathological permutation explosion can't widen
 * the RDAP fan-out beyond the lookalike check's wall-clock budget. Ordered by
 * severity (high before medium) so the most damaging false-positives are
 * corrected first when the cap binds.
 */
const SAME_ENTITY_RDAP_CAP = 10;

/**
 * IANA registrar IDs of BRAND-PROTECTION registrars — corporate registrars
 * that do not sell to the general public. Getting a domain registered through
 * one requires a corporate account and a contract; you cannot buy a name at
 * CSC or MarkMonitor the way you can at a retail registrar.
 *
 * WHY THIS IS DIFFERENT FROM THE REGISTRANT-ORG FIELD (and therefore why it is
 * allowed to corroborate ownership at all). Ruling A / F2 bars the registrant
 * org from influencing attribution because it is free text the REGISTRANT
 * types — forgeable with one form field, and collision-prone because half the
 * internet sits behind the same privacy services. The IANA registrar ID is
 * neither: it is assigned by ICANN and published by the REGISTRY as part of
 * the delegation record. A registrant cannot set it, and cannot move a domain
 * into a corporate registrar's accreditation without that registrar's consent.
 *
 * It is still NOT proof of common ownership — many brands share CSC — which is
 * why {@link isBrandHeldRegistration} requires the candidate's INFRASTRUCTURE
 * to be defensively shaped as well, and why nothing here can ever produce an
 * `owned_by_seed` verdict (that remains seed-side NS evidence only).
 *
 * RETAIL REGISTRARS MUST NEVER BE ADDED. GoDaddy (146), Namecheap (1068) and
 * friends are shared by millions of unrelated registrants, so a shared-retail-
 * registrar match carries no identity information whatsoever. A control test
 * pins that GoDaddy is not treated as evidence.
 */
const BRAND_PROTECTION_REGISTRAR_IANA_IDS: ReadonlySet<string> = new Set([
	'299', // CSC Corporate Domains, Inc.
	'292', // MarkMonitor Inc.
	'470', // Com Laude (Nom-IQ Ltd)
	'447', // SafeNames Ltd
	'1600', // Brandsight, Inc.
	'106', // Ascio Technologies (corporate channel)
	'1316', // Nameshield SAS
	'1495', // EBRAND Services
	'151', // Gandi SAS — corporate/enterprise channel
	'1479', // In2net / brand-protection channel
]);

/**
 * THE single predicate deciding whether two RDAP registrant-org strings may be
 * treated as the same entity (issue #263). Added in Task 7b fix round 1 for
 * review finding F1.
 *
 * The org field is free text the registrant TYPES and RDAP does not verify it.
 * Raw string equality was therefore both forgeable (one registrar form field)
 * and — far more damaging — trivially collision-prone: seed and candidate
 * sitting behind the SAME privacy service normalise equal for reasons that
 * carry zero identity information. Both sides are gated through
 * `isRedactedRegistrantOrg()`, so a redacted / proxy / generic value can never
 * produce a match.
 *
 * A surviving match is still only a WEAK, unverified signal: it earns a
 * sentence in the report, never a severity discount. The threat-observation
 * finding is emitted at its full calibrated severity regardless.
 *
 * EQUALITY-MATCHING INVARIANT — READ BEFORE CHANGING THE COMPARISON (fix round
 * 2, re-review residual). The final test is STRICT EQUALITY, and
 * `isRedactedRegistrantOrg()` is a pure function of its string. Therefore
 * whenever the two orgs are equal the predicate returns the SAME verdict for
 * both, and checking one side is currently EXACTLY equivalent to checking both.
 * That was verified by execution: mutating this function to gate the candidate
 * side only left the entire suite green, and no end-to-end fixture can
 * discriminate — for a one-sided gate to wrongly match, the two strings would
 * have to differ in redaction status while still being equal, which equality
 * matching makes impossible.
 *
 * The both-sides form is kept as DEFENCE IN DEPTH for the day that comparison
 * stops being equality. ANY change to fuzzy/containment/token-overlap/edit-
 * distance matching MUST (a) keep the gate on BOTH sides — under fuzzy matching
 * a redacted string can match a non-redacted one, so a one-sided gate becomes a
 * real hole — and (b) ship a fixture that discriminates one-sided from
 * two-sided, which only becomes constructible once equality is gone. Until
 * then the semantics are pinned directly by the unit tests on this function in
 * `test/check-lookalikes.spec.ts` (re-exported from `check-lookalikes.ts` for
 * exactly that purpose), not by an end-to-end fixture that cannot tell the two
 * implementations apart.
 */
export function isSameEntityOrgMatch(primaryOrg: string | null, candidateOrg: string | null): boolean {
	if (primaryOrg === null || candidateOrg === null) return false;
	if (isRedactedRegistrantOrg(primaryOrg) || isRedactedRegistrantOrg(candidateOrg)) return false;
	return primaryOrg === candidateOrg;
}

/**
 * Determine which lookalike candidates are eligible for the issue #263
 * same-entity (shared-registrant) downgrade. Eligibility mirrors the
 * classification loop's decision so we never fetch the primary's registrant
 * org speculatively: a candidate qualifies only when `ownershipByDomain`
 * does NOT already attribute it to the seed (`owned_by_seed` — CALL SITE 3
 * of the D4 2026-07-26 correctness-defects design's ownership gate) and has
 * mail/web infra. The result is sorted by calibrated severity, highest first,
 * and capped at {@link SAME_ENTITY_RDAP_CAP} so a permutation explosion can't
 * widen the RDAP fan-out unbounded.
 *
 * LOW-SEVERITY CANDIDATES ARE ELIGIBLE (changed — they used to be excluded as
 * "not worth the RDAP cost"). That exclusion was the mechanical cause of the
 * brand's-own-defensive-registration defect: a defensive registration is
 * PARKED, so it is web-only, aged and mail-less, and therefore calibrates
 * exactly `low`. The tool skipped the one fetch that would have told it who
 * held the domain, then asserted the domain "is registered to a different
 * organisation" and offered to report it for takedown — a positive
 * non-ownership CLAIM derived from evidence it declined to gather.
 *
 * Severity is a THREAT tier, so gating an ATTRIBUTION lookup on it was a
 * category error: the cheapest candidates to dismiss as low-threat are
 * precisely the ones most likely to be the customer's own.
 *
 * COST OF THE WIDENING IS ONE FETCH, MEASURED NOT ASSUMED. Candidate RDAP was
 * never gated on severity — `enrichLookalikes()` already fetches it for every
 * non-owned candidate with mail/web infra. The medium/high gate only decided
 * whether the SEED's single RDAP fetch happened. So widening to `low` adds at
 * most ONE request per scan, on scans that have a registered non-owned
 * candidate at all. `SAME_ENTITY_RDAP_CAP` still bounds the set; severity now
 * only decides ORDER within it, and `owned_by_seed` candidates are still
 * excluded outright, so the shared-NS short-circuit still pays no RDAP cost.
 */
export function computeSameEntityCandidates(
	results: LookalikeResult[],
	ownershipByDomain: Map<string, OwnershipAssessment>,
	enrichment: Map<string, LookalikeCorroborators>,
): string[] {
	const SEVERITY_ORDER: Record<LookalikeSeverity, number> = { high: 0, medium: 1, low: 2 };
	const eligible: Array<{ domain: string; severity: LookalikeSeverity }> = [];
	for (const result of results) {
		const sameOwner = ownershipByDomain.get(result.domain)?.verdict === 'owned_by_seed';
		if (sameOwner) continue;
		if (!result.hasMX && !result.hasA) continue;
		const corroborators = enrichment.get(result.domain);
		const severity = calibrateLookalikeSeverity({
			hasA: result.hasA,
			hasMX: result.hasMX,
			registrationDays: corroborators?.registrationDays ?? null,
			mxOnDisposable: corroborators?.mxOnDisposable ?? false,
			hasWebContent: corroborators?.hasWebContent ?? true,
		});
		eligible.push({ domain: result.domain, severity });
	}
	eligible.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
	return eligible.slice(0, SAME_ENTITY_RDAP_CAP).map((e) => e.domain);
}

/**
 * THE predicate deciding whether a candidate is the scanned organisation's own
 * DEFENSIVE REGISTRATION rather than a third party's domain.
 *
 * Requires BOTH, and neither alone is sufficient:
 *
 *  1. REGISTRATION-RECORD corroboration — the candidate and the seed share an
 *     IANA registrar ID belonging to a brand-protection registrar
 *     ({@link BRAND_PROTECTION_REGISTRAR_IANA_IDS}). A shared RETAIL registrar
 *     is explicitly not evidence: millions of unrelated registrants share one.
 *
 *  2. DEFENSIVE INFRASTRUCTURE SHAPE — `evaluateDefensiveRegistration()`
 *     (`src/lib/brand-defensive-registration.ts`) agrees the candidate is a
 *     typo-close label parked with minimal infrastructure. An attacker who
 *     somehow reached the same corporate registrar but stood up live mail
 *     still fails this leg and gets the full threat treatment.
 *
 * WHAT THIS DELIBERATELY DOES NOT DO: it does not, and must not, produce an
 * `owned_by_seed` ownership verdict. `classifyOwnership()` stays driven by
 * seed-side nameserver evidence alone (Ruling A), and every finding about this
 * candidate keeps carrying its structural `third_party` verdict. What changes
 * is what the report CLAIMS and RECOMMENDS: it stops asserting the domain
 * "is registered to a different organisation" on evidence that never
 * addressed the question, and stops telling the customer to report their own
 * domain for takedown.
 *
 * NULL-GUARD NOTE — VERIFIED BY MUTATION, NOT ASSUMED (the same disclosure
 * `isSameEntityOrgMatch` above makes about its own both-sides gate). The
 * `=== null` guard on the first line is currently REDUNDANT: deleting it left
 * the entire suite green, because two `null` IDs pass the equality check and
 * are then rejected by `BRAND_PROTECTION_REGISTRAR_IANA_IDS.has(null)` anyway.
 * No fixture can discriminate the two implementations while membership is an
 * exact-set test, so none is shipped pretending to.
 *
 * It is kept as DEFENCE IN DEPTH and becomes load-bearing the moment that
 * membership test is relaxed — a name-based or fuzzy registrar comparison, or
 * an "any shared registrar" mode — at which point "both sides published
 * nothing" would read as a match and silently mark every RDAP-less candidate
 * as brand-held. Anyone relaxing it MUST keep this guard and ship a fixture
 * that discriminates it, which only becomes constructible then.
 */
export function isBrandHeldRegistration(input: {
	seedDomain: string;
	candidateDomain: string;
	seedRegistrarIanaId: string | null;
	candidateRegistrarIanaId: string | null;
	candidateMxExchanges: readonly string[];
	candidateNsHosts: readonly string[];
}): { brandHeld: false } | { brandHeld: true; registrarIanaId: string; reason: DefensiveReason } {
	const { seedRegistrarIanaId, candidateRegistrarIanaId } = input;
	if (seedRegistrarIanaId === null || candidateRegistrarIanaId === null) return { brandHeld: false };
	if (seedRegistrarIanaId !== candidateRegistrarIanaId) return { brandHeld: false };
	if (!BRAND_PROTECTION_REGISTRAR_IANA_IDS.has(candidateRegistrarIanaId)) return { brandHeld: false };

	const shape = evaluateDefensiveRegistration({
		candidateDomain: input.candidateDomain,
		targetDomain: input.seedDomain,
		// A concrete array (never `undefined`) — we DID look, via the Phase 2
		// probe, so an empty set means "no mail", not "unknown". The heuristic
		// abstains on `undefined`, which would silently disable this leg.
		mxRecords: input.candidateMxExchanges,
		nsHosts: input.candidateNsHosts,
	});
	if (!shape.defensive || shape.reason === undefined) return { brandHeld: false };
	return { brandHeld: true, registrarIanaId: candidateRegistrarIanaId, reason: shape.reason };
}

/**
 * Defensive ceiling on how many candidates the #864 seed-authorisation pass
 * will probe in one run. The MX pre-filter (every exchange inside the seed
 * apex) already makes the eligible set tiny on any real scan — a seed's
 * genuine regional domains, not its squatters — so this cap exists only so a
 * pathological candidate set can never widen the extra DNS fan-out unbounded.
 */
export const SEED_AUTHORISATION_CAP = 10;

export interface SeedAuthorisationRefinementInput {
	seedDomain: string;
	/** The seed's own resolved NS hostnames (empty when unresolved). */
	seedNs: readonly string[];
	/** #832 — true when the seed's NS lookup rejected. */
	seedNsUnresolved: boolean;
	/** Phase-2 probe results (carry the resolved real MX exchanges). */
	results: readonly LookalikeResult[];
	/** Phase-1 NS answer sets, keyed by candidate. */
	nsByDomain: ReadonlyMap<string, ReadonlySet<string>>;
	/** The run's ownership map — updated IN PLACE for every probed candidate. */
	ownershipByDomain: Map<string, OwnershipAssessment>;
	isSharedNsHost: (nsHost: string) => boolean;
	/** Injected seed-side probe (`probeDmarcReportAuthorisation` in production; a stub in tests). */
	probeAuthorisation: (candidate: string, seedDomain: string) => Promise<DmarcReportAuthorisation>;
}

export interface SeedAuthorisationRefinementOutcome {
	/** Candidates whose MX routed into the seed apex and were therefore probed on the seed side. */
	probed: string[];
	/** Subset that came back `owned_by_seed` via step 5b. */
	owned: string[];
	/**
	 * Subset whose seed-side probe REJECTED, leaving the question asked but
	 * unanswered → `unmeasured` (#832's law). The orchestrator marks the run
	 * `partial` when this is non-empty so the withheld verdict is not cached
	 * for the full TTL after DNS recovers.
	 */
	unmeasured: string[];
}

/**
 * #864 — second attribution pass, run AFTER the Phase-2 A/MX probe and BEFORE
 * enrichment. The first pass (`classifyOwnership()` on NS evidence alone) is
 * blind to a same-entity domain on a different DNS platform; this pass asks
 * the SEED whether it has authorised DMARC reporting for the candidate (RFC
 * 7489 §7.1 — a record only the seed can publish), for the few candidates
 * that pass the cheap pre-filter (MX routed into the seed apex —
 * {@link mxRoutedIntoSeed}, read from records Phase 2 already fetched). Only
 * THOSE candidates pay the extra lookups, through a bounded pool, so a scan
 * with no such candidate issues zero extra queries.
 *
 * Candidates already `owned_by_seed` from seed-side NS evidence are skipped —
 * a strong verdict is never re-derived as a medium one — and every other
 * verdict is recomputed by `classifyOwnership()` itself, so the precedence
 * table stays the single decision surface (this function decides nothing).
 */
export async function refineOwnershipBySeedAuthorisation(
	input: SeedAuthorisationRefinementInput,
): Promise<SeedAuthorisationRefinementOutcome> {
	const outcome: SeedAuthorisationRefinementOutcome = { probed: [], owned: [], unmeasured: [] };
	const eligible = input.results
		.filter((result) => {
			if (input.ownershipByDomain.get(result.domain)?.verdict === 'owned_by_seed') return false;
			if (!result.hasMX) return false;
			return mxRoutedIntoSeed(result.mxExchanges, input.seedDomain);
		})
		.slice(0, SEED_AUTHORISATION_CAP);
	if (eligible.length === 0) return outcome;

	const authorisations = await mapConcurrent(eligible, SEED_AUTHORISATION_CONCURRENCY, (result) =>
		input.probeAuthorisation(result.domain, input.seedDomain),
	);

	eligible.forEach((result, index) => {
		const candidateNs = Array.from(input.nsByDomain.get(result.domain) ?? []);
		const assessment = classifyOwnership({
			seedDomain: input.seedDomain,
			seedNs: [...input.seedNs],
			candidateDomain: result.domain,
			registration: { state: 'registered', ns: candidateNs, evidence: candidateNs.length > 0 ? ['ns'] : ['a'] },
			isSharedNsHost: input.isSharedNsHost,
			seedNsUnresolved: input.seedNsUnresolved,
			candidateMx: result.mxExchanges,
			dmarcReportAuthorisation: authorisations[index],
		});
		input.ownershipByDomain.set(result.domain, assessment);
		outcome.probed.push(result.domain);
		if (assessment.verdict === 'owned_by_seed') {
			outcome.owned.push(result.domain);
		} else if (assessment.verdict === 'unmeasured' && assessment.signals.includes('mx_in_bailiwick')) {
			// Signal-tagged so a seed-NS-caused `unmeasured` (already accounted for
			// by the #832 run-level notice) is not double-counted here.
			outcome.unmeasured.push(result.domain);
		}
	});
	return outcome;
}
