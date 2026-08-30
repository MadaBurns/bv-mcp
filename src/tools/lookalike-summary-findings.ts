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
 * AXIS 2 — summary finding for high-severity lookalikes. Only fires when at
 * least one NON-OWNED candidate reached HIGH under the issue #264 matrix
 * (mail-infra + corroborator). Owned candidates never reach here.
 */
export function buildStagingSummaryFinding(input: {
	seedDomain: string;
	highCount: number;
	highDomains: string[];
	highVerdicts: Set<OwnershipVerdict>;
	mailCapableDomains: string[];
	enumeration: LookalikeEnumeration;
}): Finding {
	const { seedDomain: domain, highCount, highDomains, highVerdicts, mailCapableDomains, enumeration } = input;
	return createFinding(
		'lookalikes',
		// TITLE NAMES THE PREDICATE IT COUNTS (#779). It used to say "with
		// mail capability", which is a strictly wider set than the
		// mail-infra-PLUS-corroborator matrix this count applies — so the
		// headline under-reported threefold against its own per-domain
		// evidence. The staging subset is the right thing to lead with; it
		// just has to be named as the subset it is, with the wider
		// mail-capable figure alongside rather than implied.
		`${highCount} lookalike domain${highCount > 1 ? 's' : ''} showing pre-phishing staging signals`,
		'high',
		`${highCount} lookalike domain${highCount > 1 ? 's' : ''} of ${domain} ${highCount > 1 ? 'have' : 'has'} active mail infrastructure with corroborating signals consistent with pre-phishing staging.${
			mailCapableDomains.length > highCount
				? ` A further ${mailCapableDomains.length - highCount} confusable domain${mailCapableDomains.length - highCount > 1 ? 's' : ''} also ${mailCapableDomains.length - highCount > 1 ? 'have' : 'has'} a working mail host without those additional signals — ${mailCapableDomains.length} can send mail in total.`
				: ''
		} ${highCount > 1 ? 'None of them appear' : 'It does not appear'} to belong to the scanned organisation, and no action on ${highCount > 1 ? 'them' : 'it'} is requested here. Defensive options: monitor ${highCount > 1 ? 'them' : 'it'}, and enforce DMARC p=reject on ${domain} itself so receivers reject mail spoofing that name.`,
		{
			lookalikeDomainCount: highCount,
			lookalikeDomains: highDomains,
			// BOTH numbers, so a consumer never has to re-derive either from
			// the per-domain findings — which is what the old shape forced,
			// and what nobody did.
			mailCapableCount: mailCapableDomains.length,
			mailCapableDomains,
			enumeration,
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
 * of the two it is.
 */
export function buildMailCapableSummaryFinding(input: {
	seedDomain: string;
	mailCapableDomains: string[];
	enumeration: LookalikeEnumeration;
}): Finding {
	const { seedDomain: domain, mailCapableDomains, enumeration } = input;
	const n = mailCapableDomains.length;
	return createFinding(
		'lookalikes',
		`${n} lookalike domain${n > 1 ? 's' : ''} with a working mail host`,
		'medium',
		`${n} confusable domain${n > 1 ? 's' : ''} of ${domain} ${n > 1 ? 'have' : 'has'} a working mail host, so ${n > 1 ? 'they are' : 'it is'} capable of sending mail that resembles ${domain}. No additional corroborating signal of pre-phishing staging was observed, and ${n > 1 ? 'none appears' : 'it does not appear'} to belong to the scanned organisation — this is an infrastructure observation, not an allegation. Enforcing DMARC p=reject on ${domain} is what makes receivers reject mail forging that name.`,
		{
			mailCapableCount: n,
			mailCapableDomains,
			enumeration,
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
