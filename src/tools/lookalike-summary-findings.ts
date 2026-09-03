// SPDX-License-Identifier: BUSL-1.1

/**
 * RUN-LEVEL finding construction for the lookalike check — the aggregate
 * summaries (AXIS 2, `threat_observation`) and the `scan_status` notices about
 * the run itself. Extracted VERBATIM from `check-lookalikes.ts` (pure split, no
 * behaviour change); per-candidate builders live in `lookalike-findings.ts`,
 * whose module JSDoc carries the three-axis contract and its four invariants.
 *
 * INVARIANT 4 APPLIES HERE TOO, and this is where it has actually been broken:
 * every `threat_observation` must NAME its subject. The mail-capable summary
 * below sets `lookalikeDomains` for exactly that reason — the first draft set
 * only `mailCapableDomains` and was anonymous, which
 * `test/check-lookalikes.spec.ts`'s `assertAxisInvariants` caught. Do not
 * "simplify" that key away.
 */

import type { Finding } from '../lib/scoring';
import { createFinding } from '../lib/scoring';
import type { OwnershipAssessment, OwnershipVerdict } from '../lib/ownership-attribution';
import type { LookalikeFindingAxis } from './lookalike-findings';
import type { LookalikeSeverity } from './lookalike-severity';

/**
 * Enumeration coverage for one run.
 *
 * `complete: false` means the candidate set is a SAMPLE, not a census — so a
 * consumer diffing consecutive runs must not read a shrinking set as a
 * deregistration, and a report must not present the list as exhaustive.
 */
export interface LookalikeEnumeration {
	permutationsGenerated: number;
	permutationsProbed: number;
	candidatesResolved: number;
	unresolvedCount: number;
	complete: boolean;
}

/**
 * Share of the PROBED permutation space that went unresolved at or above which
 * the threat rollup ABSTAINS instead of publishing a count (#865).
 *
 * Why one half: the rollup is a claim about a SET. Once more of the probed
 * namespace is unobserved than observed, the emitted count is bounded below by
 * what resolved and above by nothing — its plausible range exceeds its value,
 * so it is dominated by coverage, not by the world. Below the line the count
 * is still reported, but as a FLOOR with the coverage stats beside it.
 *
 * Calibrated against the issue's measured table (2026-08-31, eight providers,
 * same tool, same day): amazon.com 1.2% and cohere.com 43% emit; microsoft.com
 * 51%, meta.com 62%, google.com 67% and openai.com 86% abstain. The openai run
 * — 12 of 90 resolved, published as "8 can send mail in total" at `high` —
 * is the shape this constant exists to stop. #847's degraded-comparison law
 * (`seedNsUnresolved` → every verdict `unmeasured`) is BINARY and about the
 * ownership instrument; this ratio is about enumeration coverage, a separate
 * instrument, and is the first threshold on it.
 */
export const ROLLUP_ABSTAIN_UNRESOLVED_RATIO = 0.5;

/** True when the run's enumeration coverage is too degraded to publish a rollup count (see {@link ROLLUP_ABSTAIN_UNRESOLVED_RATIO}). */
export function isRollupCoverageDegraded(enumeration: LookalikeEnumeration): boolean {
	if (enumeration.permutationsProbed <= 0) return false;
	return enumeration.unresolvedCount / enumeration.permutationsProbed >= ROLLUP_ABSTAIN_UNRESOLVED_RATIO;
}

/**
 * One NON-OWNED, MEASURED candidate the aggregate rollup may count. Assembled
 * by the orchestrator's classification loop for every candidate that received
 * a per-domain `threat_observation` — `owned_by_seed` and `unmeasured`
 * candidates never reach it (#832).
 */
export interface ThreatRollupMember {
	domain: string;
	/** A working mail host (an RFC 7505 null MX is already `false` here). */
	hasMX: boolean;
	/** The #264-calibrated per-domain severity. */
	severity: LookalikeSeverity;
	ownershipVerdict: OwnershipVerdict;
	/** `null` when the RDAP age probe failed or returned nothing — "unknown", never "not recent" for reporting purposes. */
	registrationDays: number | null;
}

/**
 * The enumeration stats FLATTENED onto a rollup finding's own metadata (#865).
 * `enumeration` is still carried as the structured block; these duplicates
 * exist because a consumer reading only the rollup — which is what a rollup
 * is for — must not have to descend into a nested object to learn that the
 * count it is about to quote came from a sample.
 */
function flatEnumerationStats(enumeration: LookalikeEnumeration): Record<string, number | boolean> {
	return {
		permutationsProbed: enumeration.permutationsProbed,
		candidatesResolved: enumeration.candidatesResolved,
		unresolvedCount: enumeration.unresolvedCount,
		complete: enumeration.complete,
	};
}

/** Prose fragment stating that an incomplete run's count is a floor, with the coverage numbers that make it one. */
function floorClause(enumeration: LookalikeEnumeration): string {
	return ` This is a floor, not a total: ${enumeration.unresolvedCount} of ${enumeration.permutationsProbed} probed lookup${enumeration.permutationsProbed === 1 ? '' : 's'} did not resolve, so those permutations could be neither confirmed nor ruled out and the true number can only be higher.`;
}

/**
 * Prose fragment naming how many counted members carry no registration age, so
 * "no recent-registration signal" is not read as "not recent". Unpunctuated —
 * the caller supplies the leading connective and trailing stop.
 */
function ageUnknownSentence(ageUnknownCount: number, total: number): string {
	return `${ageUnknownCount} of ${total} could not be age-checked (the registration-date lookup returned nothing), so "recently registered" is neither confirmed nor ruled out for ${ageUnknownCount === 1 ? 'that one' : 'those'}`;
}

/**
 * `scan_status` — the run timed out. Emitted by the `checkLookalikes` wrapper's
 * race, alongside `partial: true` on the CheckResult so callers skip caching.
 */
export function buildTimeoutFinding(): Finding {
	return createFinding(
		'lookalikes',
		'Lookalike check incomplete',
		'info',
		'Lookalike check did not complete within the time limit. Results may be incomplete — try again shortly.',
		{ findingAxis: 'scan_status' satisfies LookalikeFindingAxis },
	);
}

/** `scan_status` — no permutation could be generated at all for this seed. */
export function buildNoPermutationsFinding(seedDomain: string): Finding {
	return createFinding(
		'lookalikes',
		'No active lookalike domains detected',
		'info',
		`No lookalike domain permutations could be generated for ${seedDomain}.`,
		{ findingAxis: 'scan_status' satisfies LookalikeFindingAxis },
	);
}

/** `scan_status` — permutations were probed, but Phase 1 found no registered candidate. */
export function buildNoRegisteredCandidatesFinding(seedDomain: string, permutationCount: number): Finding {
	return createFinding(
		'lookalikes',
		'No active lookalike domains detected',
		'info',
		`Checked ${permutationCount} domain permutations of ${seedDomain}. No active registrations detected.`,
		{ findingAxis: 'scan_status' satisfies LookalikeFindingAxis },
	);
}

/**
 * `scan_status` — registered candidates existed but none carried DNS or mail
 * infrastructure, so nothing was classified. Carries the enumeration block so a
 * partial run's "none" is explicitly hedged rather than read as conclusive.
 */
export function buildNoActiveInfrastructureFinding(
	seedDomain: string,
	permutationCount: number,
	enumeration: LookalikeEnumeration,
): Finding {
	return createFinding(
		'lookalikes',
		'No active lookalike domains detected',
		'info',
		`Checked ${permutationCount} domain permutations of ${seedDomain}. No active registrations with DNS or mail infrastructure detected.${
			enumeration.complete
				? ''
				: ` ⚠️ ${enumeration.unresolvedCount} lookup${enumeration.unresolvedCount > 1 ? 's' : ''} did not resolve, so this is not a conclusive "none".`
		}`,
		{ findingAxis: 'scan_status' satisfies LookalikeFindingAxis, enumeration },
	);
}

/**
 * `scan_status` — the OWNERSHIP COMPARISON was degraded this run (#832): the
 * seed's own NS lookup did not resolve, so every registered candidate carries
 * an `unmeasured` ownership verdict and no impersonation-shaped finding was
 * emitted. Surfaced as its own finding (not only per-candidate metadata) for
 * the same reason as {@link buildIncompleteEnumerationFinding}: a consumer
 * reading findings must be able to tell "attribution declined because the
 * instrument was throttled" from "attribution concluded third-party" —
 * otherwise a diff of consecutive runs sees the world flip
 * (owned → third-party → owned) when only the run's completeness changed.
 */
export function buildOwnershipUnmeasuredFinding(seedDomain: string, candidateCount: number): Finding {
	return createFinding(
		'lookalikes',
		'Ownership attribution unmeasured this run — treat verdicts as pending',
		'info',
		candidateCount === 0
			? `The nameserver lookup for ${seedDomain} itself did not resolve in this run (DNS timeout or rate limiting), so registered candidates could not be compared against the organisation's own nameservers. No candidate needed that comparison here — each was attributed from its own evidence (nameservers within ${seedDomain} itself) — but a candidate relying on the comparison would have been reported 'unmeasured' rather than attributed. Re-run for a complete picture.`
			: `The nameserver lookup for ${seedDomain} itself did not resolve in this run (DNS timeout or rate limiting), so registered candidates could not be compared against the organisation's own nameservers. ${candidateCount} candidate${candidateCount === 1 ? '' : 's'} ${candidateCount === 1 ? 'is' : 'are'} reported with an 'unmeasured' ownership verdict instead of a definitive attribution — a definitive third-party claim requires the same complete comparison an owned verdict does. Impersonation-shaped observations are withheld for unmeasured candidates; re-run to attribute.`,
		{
			findingAxis: 'scan_status' satisfies LookalikeFindingAxis,
			seedNsUnresolved: true,
			unmeasuredCandidateCount: candidateCount,
			confidence: 'heuristic',
		},
	);
}

/**
 * THE threat-rollup decision point (#865). Exactly one of three outcomes:
 *
 *  - no mail-capable member → `finding: null` (nothing to roll up — the
 *    per-domain findings stand alone, as before);
 *  - enumeration coverage degraded past {@link ROLLUP_ABSTAIN_UNRESOLVED_RATIO}
 *    → the not-assessed `scan_status` notice from
 *    {@link buildRollupNotAssessedFinding}, `abstained: true`, so the caller
 *    marks the run `partial` and the abstention is not cached for the TTL;
 *  - otherwise → the staging rollup when any member reached HIGH with mail,
 *    else the mail-capable rollup — each worded as a FLOOR when the run is
 *    incomplete, and each carrying the enumeration stats flat in its metadata.
 *
 * The order matters: abstention is decided BEFORE either rollup is built, so
 * a throttled run can never reach the count-carrying builders at all.
 */
export function buildThreatRollupFinding(input: { seedDomain: string; members: ThreatRollupMember[]; enumeration: LookalikeEnumeration }): {
	finding: Finding | null;
	abstained: boolean;
} {
	const { seedDomain, members, enumeration } = input;
	const mailCapable = members.filter((m) => m.hasMX);
	if (mailCapable.length === 0) return { finding: null, abstained: false };
	if (isRollupCoverageDegraded(enumeration)) {
		return { finding: buildRollupNotAssessedFinding(seedDomain, enumeration), abstained: true };
	}
	const staging = mailCapable.filter((m) => m.severity === 'high');
	if (staging.length > 0) {
		return { finding: buildStagingSummaryFinding({ seedDomain, staging, mailCapable, enumeration }), abstained: false };
	}
	return { finding: buildMailCapableSummaryFinding({ seedDomain, mailCapable, enumeration }), abstained: false };
}

/**
 * `scan_status` — the threat rollup was NOT ASSESSED this run because
 * enumeration coverage was too degraded to count (#865). Carries NO count and
 * NO domain list on purpose: the whole defect was an integer stated as fact
 * beside a coverage block that contradicted it. Uses the repo's codified
 * "probe never reached the origin" markers (`inconclusive` + `errorKind`,
 * see `lib/control-presence.ts`) so a consumer keyed on those reads this as
 * unmeasured, never as "no lookalike exposure".
 */
export function buildRollupNotAssessedFinding(seedDomain: string, enumeration: LookalikeEnumeration): Finding {
	const pct = Math.round((enumeration.unresolvedCount / Math.max(1, enumeration.permutationsProbed)) * 100);
	return createFinding(
		'lookalikes',
		'Lookalike threat rollup not assessed this run — enumeration too incomplete to count',
		'info',
		`${enumeration.unresolvedCount} of ${enumeration.permutationsProbed} candidate lookups for ${seedDomain} did not resolve (${pct}% — DNS timeout or rate limiting), so most of the permutation space was never observed. No count of mail-capable or staging-flagged lookalikes is published for this run: any such number would measure the throttling, not the estate, and would not be comparable with a run — or another organisation — that resolved more. The ${enumeration.candidatesResolved} candidate${enumeration.candidatesResolved === 1 ? '' : 's'} that did resolve are reported individually below as observed examples. Re-run to obtain a rollup.`,
		{
			findingAxis: 'scan_status' satisfies LookalikeFindingAxis,
			notAssessedReason: 'enumeration_throttled',
			inconclusive: true,
			errorKind: 'dns_error',
			enumeration,
			...flatEnumerationStats(enumeration),
			unresolvedRatio: enumeration.permutationsProbed > 0 ? enumeration.unresolvedCount / enumeration.permutationsProbed : 0,
			abstainThreshold: ROLLUP_ABSTAIN_UNRESOLVED_RATIO,
			confidence: 'heuristic',
		},
	);
}

/**
 * AXIS 2 — summary finding for high-severity lookalikes. Only fires when at
 * least one NON-OWNED candidate reached HIGH under the issue #264 matrix
 * (mail-infra + corroborator). Owned candidates never reach here. Reached only
 * through {@link buildThreatRollupFinding}, which has already ruled out a
 * degraded-coverage run (#865).
 */
export function buildStagingSummaryFinding(input: {
	seedDomain: string;
	/** Members that reached HIGH with a working mail host — the counted set. */
	staging: ThreatRollupMember[];
	/** Every member with a working mail host — the wider set, a superset of `staging`. */
	mailCapable: ThreatRollupMember[];
	enumeration: LookalikeEnumeration;
}): Finding {
	const { seedDomain: domain, staging, mailCapable, enumeration } = input;
	const highCount = staging.length;
	const highDomains = staging.map((m) => m.domain);
	const highVerdicts = new Set(staging.map((m) => m.ownershipVerdict));
	const mailCapableDomains = mailCapable.map((m) => m.domain);
	const ageUnknownCount = mailCapable.filter((m) => m.registrationDays === null).length;
	// #865 — an incomplete run's count is a FLOOR. The title says so, because
	// the title is what gets quoted.
	const floor = !enumeration.complete;
	const lead = floor ? `At least ${highCount}` : `${highCount}`;
	return createFinding(
		'lookalikes',
		// TITLE NAMES THE PREDICATE IT COUNTS (#779). It used to say "with
		// mail capability", which is a strictly wider set than the
		// mail-infra-PLUS-corroborator matrix this count applies — so the
		// headline under-reported threefold against its own per-domain
		// evidence. The staging subset is the right thing to lead with; it
		// just has to be named as the subset it is, with the wider
		// mail-capable figure alongside rather than implied.
		`${lead} lookalike domain${highCount > 1 ? 's' : ''} showing pre-phishing staging signals`,
		'high',
		`${lead} lookalike domain${highCount > 1 ? 's' : ''} of ${domain} ${highCount > 1 ? 'have' : 'has'} active mail infrastructure with corroborating signals consistent with pre-phishing staging.${
			mailCapableDomains.length > highCount
				? ` A further ${mailCapableDomains.length - highCount} confusable domain${mailCapableDomains.length - highCount > 1 ? 's' : ''} also ${mailCapableDomains.length - highCount > 1 ? 'have' : 'has'} a working mail host without those additional signals — ${floor ? 'at least ' : ''}${mailCapableDomains.length} can send mail in total.`
				: ''
		}${floor ? floorClause(enumeration) : ''}${ageUnknownCount > 0 ? ` ${ageUnknownSentence(ageUnknownCount, mailCapableDomains.length)}.` : ''} ${highCount > 1 ? 'None of them appear' : 'It does not appear'} to belong to the scanned organisation, and no action on ${highCount > 1 ? 'them' : 'it'} is requested here. Defensive options: monitor ${highCount > 1 ? 'them' : 'it'}, and enforce DMARC p=reject on ${domain} itself so receivers reject mail spoofing that name.`,
		{
			lookalikeDomainCount: highCount,
			lookalikeDomains: highDomains,
			// BOTH numbers, so a consumer never has to re-derive either from
			// the per-domain findings — which is what the old shape forced,
			// and what nobody did.
			mailCapableCount: mailCapableDomains.length,
			mailCapableDomains,
			// #865 — the counts above are lower bounds when the run is a sample.
			countIsFloor: floor,
			// How many of the mail-capable set carry no registration age. They
			// are COUNTED (the mail host is a real observation); this says that
			// "no recent-registration corroborator" was unmeasured for them.
			ageUnknownCount,
			enumeration,
			...flatEnumerationStats(enumeration),
			// Set-level claim, so its confidence tracks ENUMERATION coverage,
			// not per-domain measurement quality (#781). Each row remains
			// deterministic about its own domain; what is uncertain when a
			// lookup was dropped is whether the SET is complete — and this
			// finding is the one making a claim about the set.
			confidence: enumeration.complete ? 'deterministic' : 'heuristic',
			// Present whenever the counted set shares one verdict (the realistic
			// case — a non-owned registered candidate is always `third_party`).
			// Omitted rather than fabricated for a mixed set; either way it can
			// never be `owned_by_seed`, since owned candidates never reach here.
			...(highVerdicts.size === 1 ? { ownershipVerdict: [...highVerdicts][0] } : {}),
			findingAxis: 'threat_observation' satisfies LookalikeFindingAxis,
		},
	);
}

/**
 * AXIS 2 — the other half of #779. When mail-capable candidates exist but none
 * carries a #264 corroborator, the old code emitted NO summary at all — so an
 * estate with several confusable domains that can send mail produced an
 * aggregate view saying nothing, and a consumer reading only summaries
 * concluded there was no mail-capable lookalike exposure.
 *
 * MEDIUM, not high: mail capability alone is a real observation but not
 * evidence of staging, and the severity has to stay honest about which
 * of the two it is. Reached only through {@link buildThreatRollupFinding}
 * (#865: never for a degraded-coverage run).
 */
export function buildMailCapableSummaryFinding(input: {
	seedDomain: string;
	mailCapable: ThreatRollupMember[];
	enumeration: LookalikeEnumeration;
}): Finding {
	const { seedDomain: domain, mailCapable, enumeration } = input;
	const mailCapableDomains = mailCapable.map((m) => m.domain);
	const ageUnknownCount = mailCapable.filter((m) => m.registrationDays === null).length;
	const n = mailCapableDomains.length;
	const floor = !enumeration.complete;
	const lead = floor ? `At least ${n}` : `${n}`;
	return createFinding(
		'lookalikes',
		`${lead} lookalike domain${n > 1 ? 's' : ''} with a working mail host`,
		'medium',
		`${lead} confusable domain${n > 1 ? 's' : ''} of ${domain} ${n > 1 ? 'have' : 'has'} a working mail host, so ${n > 1 ? 'they are' : 'it is'} capable of sending mail that resembles ${domain}.${floor ? floorClause(enumeration) : ''} No additional corroborating signal of pre-phishing staging was observed${ageUnknownCount > 0 ? ` — though ${ageUnknownSentence(ageUnknownCount, n)}` : ''}, and ${n > 1 ? 'none appears' : 'it does not appear'} to belong to the scanned organisation — this is an infrastructure observation, not an allegation. Enforcing DMARC p=reject on ${domain} is what makes receivers reject mail forging that name.`,
		{
			mailCapableCount: n,
			mailCapableDomains,
			countIsFloor: floor,
			ageUnknownCount,
			enumeration,
			...flatEnumerationStats(enumeration),
			confidence: enumeration.complete ? 'deterministic' : 'heuristic',
			// Names what it observed — invariant 4, asserted by
			// `assertAxisInvariants`: every threat_observation must identify
			// its subject. Omitting this made the first draft of this finding
			// anonymous, and the existing suite caught it.
			lookalikeDomains: mailCapableDomains,
			// Deliberately no `lookalikeDomainCount`: nothing reached the
			// staging threshold, and reusing that key would let a consumer
			// read this as the staging count.
			findingAxis: 'threat_observation' satisfies LookalikeFindingAxis,
		},
	);
}

/**
 * `scan_status` — PARTIAL COVERAGE (#781). Emitted as its own finding, not only
 * as metadata, because a consumer reading findings — which is most of them —
 * otherwise has no way to learn the candidate set is a SAMPLE. Without it,
 * repeat runs returning different sets look like real-world change: monitoring
 * built on diffing consecutive runs raises false "new lookalike registered"
 * alerts for names merely missed last time, and misses real ones enumerated
 * before.
 */
export function buildIncompleteEnumerationFinding(seedDomain: string, enumeration: LookalikeEnumeration): Finding {
	return createFinding(
		'lookalikes',
		'Lookalike enumeration was incomplete — treat this list as a sample',
		'info',
		`${enumeration.unresolvedCount} of ${enumeration.permutationsProbed} candidate lookup${enumeration.permutationsProbed > 1 ? 's' : ''} for ${seedDomain} did not resolve (DNS timeout or rate limiting), so those permutations could be neither confirmed nor ruled out. The ${enumeration.candidatesResolved} domain${enumeration.candidatesResolved === 1 ? '' : 's'} reported here are observed examples, not a complete inventory — do not read a smaller set on a later run as a domain having been deregistered, and re-run before relying on the count.`,
		{
			findingAxis: 'scan_status' satisfies LookalikeFindingAxis,
			enumeration,
			confidence: 'heuristic',
		},
	);
}

/**
 * AXIS 2 — bv-recon named a SPECIFIC confusable candidate, so the CT
 * corroboration is a per-candidate threat observation carrying that name
 * (invariant 4) and the candidate's own ownership verdict (invariant 3).
 */
export function buildReconCandidateFinding(matchedDomain: string, detail: string, reconOwnership: OwnershipAssessment): Finding {
	return createFinding('lookalikes', 'CT-observed lookalike corroboration', 'medium', detail, {
		lookalikeDomain: matchedDomain,
		reconEnriched: true,
		findingAxis: 'threat_observation' satisfies LookalikeFindingAxis,
		ownershipVerdict: reconOwnership.verdict,
	});
}

/**
 * `scan_status` — bv-recon corroborated the seed's CT neighbourhood but named
 * no specific candidate. Never fabricate one: this is a scan-level notice about
 * the run's own CT signal, not a per-candidate threat claim, so it stays
 * `info`/`scan_status` (DEMOTE, NEVER DELETE — the real signal is still
 * surfaced).
 */
export function buildReconScanStatusFinding(seedDomain: string, detail: string): Finding {
	return createFinding(
		'lookalikes',
		'CT-observed lookalike corroboration (no specific candidate identified)',
		'info',
		`${detail} No specific confusable domain was identified by this signal, so no candidate-level claim is made.`,
		{ domain: seedDomain, reconEnriched: true, findingAxis: 'scan_status' satisfies LookalikeFindingAxis },
	);
}
