// SPDX-License-Identifier: BUSL-1.1

/**
 * Lookalike domain detection tool.
 * Generates typosquat/lookalike domain permutations and checks for
 * active DNS registrations and mail infrastructure.
 * Standalone check — not included in scan_domain due to query volume.
 *
 * THIS FILE IS THE ORCHESTRATOR AND THE PUBLIC SURFACE. It sequences the
 * pipeline and owns nothing else; each stage lives in a sibling module, split
 * out of this file as a PURE EXTRACTION (no behaviour change):
 *
 *  - `lookalike-analysis.ts` / `markov-generator.ts` — candidate generation.
 *  - `lookalike-dns.ts` — NS-existence filtering, wildcard-parent detection,
 *    the adaptive-batching A/MX probe, and the two seed-side queries.
 *  - `lookalike-enrichment.ts` — the RDAP + HEAD corroborator probes.
 *  - `lookalike-attribution.ts` — the same-entity and brand-held predicates.
 *  - `lookalike-severity.ts` — the #264 severity matrix.
 *  - `lookalike-findings.ts` — the three-axis contract and the per-candidate
 *    Finding builders. READ ITS MODULE JSDOC before touching any emission
 *    site: it carries the four axis invariants `test/check-lookalikes.spec.ts`
 *    pins, including invariant 4 (every `threat_observation` names its subject
 *    via `lookalikeDomain`/`lookalikeDomains`).
 *  - `lookalike-summary-findings.ts` — the aggregate and `scan_status`
 *    Finding builders.
 *
 * Everything the tool exported before the split is still exported from HERE,
 * unchanged, so `src/package.ts`, `src/handlers/tools.ts`,
 * `discover-brand-domains.ts` and the test suite keep one import site.
 */

import { callReconScan, isReconHit } from '../lib/recon-binding';
import type { ReconBinding, BindingDegradationSink, ReconScanResult } from '../lib/recon-binding';
import type { CheckResult, Finding } from '../lib/scoring';
import { buildCheckResult } from '../lib/scoring';
import { generateCognitiveLookalikes, generateCombosquats, generateLookalikes } from './lookalike-analysis';
import { calibrateLookalikeSeverity, type LookalikeSignals } from './lookalike-severity';
import { classifyOwnership, type OwnershipAssessment, type OwnershipVerdict } from '../lib/ownership-attribution';
import { isSharedNsHost } from '../tenants/discovery/shared-ns-hosts';
import { extractBrandName } from '../lib/public-suffix';
import {
	detectWildcardParents,
	filterByNsExistence,
	getParentDomain,
	labelCount,
	probeWithAdaptiveBatching,
	queryPrimaryMx,
	queryPrimaryNs,
	type LookalikeResult,
} from './lookalike-dns';
import { EMPTY_RDAP_PROBE, enrichLookalikes, probePrimaryRegistration } from './lookalike-enrichment';
import { computeSameEntityCandidates, isBrandHeldRegistration, isSameEntityOrgMatch } from './lookalike-attribution';
import type { DefensiveReason } from '../lib/brand-defensive-registration';
import {
	applyOwnershipGate,
	buildBrandHeldFinding,
	buildOwnedBySeedFinding,
	buildRawAttributionFinding,
	buildRegisteredDarkFinding,
	buildSharedRegistrantOrgFinding,
	buildThreatObservationFinding,
	describeCorroborators,
} from './lookalike-findings';
import {
	buildIncompleteEnumerationFinding,
	buildMailCapableSummaryFinding,
	buildNoActiveInfrastructureFinding,
	buildNoPermutationsFinding,
	buildNoRegisteredCandidatesFinding,
	buildOwnershipUnmeasuredFinding,
	buildReconCandidateFinding,
	buildReconScanStatusFinding,
	buildStagingSummaryFinding,
	buildTimeoutFinding,
} from './lookalike-summary-findings';

// ---------------------------------------------------------------------------
// PUBLIC SURFACE — re-exported from the modules the split moved them to, so no
// consumer (or test) has to know where a symbol now lives. This list is the
// tool's external contract; it is byte-identical to the pre-split one.
// ---------------------------------------------------------------------------
export { INITIAL_BATCH_SIZE, MIN_BATCH_SIZE, BACKOFF_DELAY_MS, FAILURE_THRESHOLD, WILDCARD_CANARY_LABEL, PHASE1_DNS_OPTS } from './lookalike-dns';
export { probeHasWebContent } from './lookalike-enrichment';
export { isBrandHeldRegistration, isSameEntityOrgMatch } from './lookalike-attribution';
export { DEFENSIVE_REASON_PHRASES, type LookalikeFindingAxis } from './lookalike-findings';

/** Maximum wall-clock time for the entire lookalike check (ms). */
const LOOKALIKE_TIMEOUT_MS = 20_000;

/**
 * Extract a specific candidate domain bv-recon's CT_LOOKALIKE hit names, if
 * any (fix round 1, F1). The check response schema's only extension point
 * for this is the passthrough `metadata` bag (`ReconScanResponseSchema` in
 * `../lib/recon-binding`); a `matchedDomain` string there is treated as the
 * named candidate. Defensively normalised (trim/lowercase/strip trailing
 * dot); rejected outright — returns `null` rather than the seed — when it is
 * empty or equal to the SEED domain itself, so a recon response that merely
 * echoes the query target can never satisfy the threat-observation naming
 * invariant without actually naming a distinct candidate.
 */
export function extractReconMatchedDomain(reconResult: ReconScanResult, seedDomain: string): string | null {
	const raw = reconResult.metadata?.matchedDomain;
	if (typeof raw !== 'string') return null;
	const normalized = raw.trim().toLowerCase().replace(/\.$/, '');
	const seedNormalized = seedDomain.trim().toLowerCase().replace(/\.$/, '');
	if (normalized === '' || normalized === seedNormalized) return null;
	return normalized;
}

/**
 * Detect registered lookalike/typosquat domains with DNS or mail infrastructure.
 * Generates domain permutations and checks for active registrations using adaptive batching.
 * Filters out false positives from wildcard DNS on parent domains and null MX records.
 */
export async function checkLookalikes(
	domain: string,
	reconOptions: { reconBinding?: ReconBinding; reconAuthToken?: string; onBindingDegradation?: BindingDegradationSink } = {},
): Promise<CheckResult> {
	return Promise.race([
		checkLookalikesCore(domain, reconOptions),
		new Promise<never>((_, reject) => setTimeout(() => reject(new Error('Lookalike check timed out')), LOOKALIKE_TIMEOUT_MS)),
	]).catch(() => {
		const result = buildCheckResult('lookalikes', [buildTimeoutFinding()]);
		// Mark as partial so callers can skip caching
		result.partial = true;
		return result;
	});
}

async function checkLookalikesCore(
	domain: string,
	reconOptions: { reconBinding?: ReconBinding; reconAuthToken?: string; onBindingDegradation?: BindingDegradationSink } = {},
): Promise<CheckResult> {
	const findings: Finding[] = [];
	// THREE disjoint candidate lanes, deduped into one set that flows through the
	// same NS-existence → probe → enrich → severity pipeline:
	//
	//  - `generateLookalikes` — MOTOR errors (keyboard adjacency, omission,
	//    duplication, dot insertion, TLD swap, homoglyph): a slip of the finger
	//    by someone who knows the correct spelling.
	//  - `generateCognitiveLookalikes` — COGNITIVE errors: the spelling a large
	//    population believes IS correct (`sketchers`, `berenstein`), typed
	//    deliberately and repeatedly. The motor set cannot reach these except by
	//    coincidence, so before this lane existed they were simply never probed.
	//  - `generateCombosquats` — brand + lure affix, which defeats edit distance
	//    entirely.
	//
	// Each lane carries its OWN cap, so adding one can never evict another's
	// candidates through a shared truncation.
	const permutations = [
		...new Set([...generateLookalikes(domain), ...generateCognitiveLookalikes(domain), ...generateCombosquats(domain)]),
	];

	if (permutations.length === 0) {
		findings.push(buildNoPermutationsFinding(domain));
		return buildCheckResult('lookalikes', findings);
	}

	// Identify dot-insertion permutations (they have more labels than the original domain)
	const originalLabelCount = labelCount(domain);
	const dotInsertionParents = new Map<string, string[]>(); // parent → [permutations]
	const nonDotInsertionPerms: string[] = [];

	for (const perm of permutations) {
		if (labelCount(perm) > originalLabelCount) {
			const parent = getParentDomain(perm);
			const existing = dotInsertionParents.get(parent);
			if (existing) {
				existing.push(perm);
			} else {
				dotInsertionParents.set(parent, [perm]);
			}
		} else {
			nonDotInsertionPerms.push(perm);
		}
	}

	// Detect wildcard DNS on parent domains of dot-insertion permutations
	const wildcardParents = dotInsertionParents.size > 0 ? await detectWildcardParents([...dotInsertionParents.keys()]) : new Set<string>();

	// Filter out permutations whose parent has wildcard DNS
	const filteredDotInsertionPerms: string[] = [];
	for (const [parent, perms] of dotInsertionParents) {
		if (!wildcardParents.has(parent)) {
			filteredDotInsertionPerms.push(...perms);
		}
	}

	const permsToProbe = [...nonDotInsertionPerms, ...filteredDotInsertionPerms];

	// Phase 0 (#853): resolve the SEED's own NS + MX BEFORE the permutation
	// fan-out, not alongside it. These two queries used to share a Promise.all
	// with `filterByNsExistence`, which dispatches ~66 probes in adaptive
	// batches — so the one lookup that gates every ownership verdict competed
	// with its own burst for resolver budget, and (on PHASE1_DNS_OPTS) had no
	// retry to survive losing. Measured 2026-08-31: meta.com reported
	// `seedNsUnresolved: true` on 2/2 idle runs while a standalone DoH NS query
	// for it returned 4 answers. Sequencing costs one round trip on a check
	// that already takes seconds; a voided attribution costs the whole result.
	const [primaryNsProbe, primaryMx] = await Promise.all([queryPrimaryNs(domain), queryPrimaryMx(domain)]);

	// Phase 1: Fast NS existence check — filter out unregistered domains.
	const nsResult = await filterByNsExistence(permsToProbe);
	const { registered: registeredPerms, nsMap: lookalikeNsMap, unresolved: nsUnresolved } = nsResult;
	const primaryNs = primaryNsProbe.ns;
	// #832 — the seed's own NS lookup failed, so the ownership comparison has
	// nothing to compare against this run. Every set-comparison verdict below
	// becomes `unmeasured` (never the CONTRARY `third_party`), and
	// impersonation-shaped findings are withheld for unmeasured candidates.
	const seedNsUnmeasured = !primaryNsProbe.resolved;

	if (registeredPerms.length === 0) {
		findings.push(buildNoRegisteredCandidatesFinding(domain, permutations.length));
		return buildCheckResult('lookalikes', findings);
	}

	// D4 (2026-07-26 correctness-defects design) — classify every registered
	// candidate's ownership ONCE, up front, reused across all three same-owner
	// decision points below (the enrichment filter, the main classification
	// loop, and the same-entity RDAP-eligibility filter). Replaces
	// sharesNameservers() (SHARED_NS_THRESHOLD = 1 — a single shared NS host,
	// e.g. a pooled Akamai hostname, was already enough to mark two unrelated
	// organisations as the same owner — an even weaker version of the
	// shadow-domains bug this design also fixes). Every registered candidate
	// here was proven registered via NS (filterByNsExistence only returns
	// domains with NS records), so `registration.ns` is always non-empty.
	const primaryNsList = Array.from(primaryNs);
	const brand = extractBrandName(domain) ?? '';
	const ownershipByDomain = new Map<string, OwnershipAssessment>();
	for (const perm of registeredPerms) {
		const candidateNs = Array.from(lookalikeNsMap.get(perm) ?? []);
		ownershipByDomain.set(
			perm,
			classifyOwnership({
				seedDomain: domain,
				seedNs: primaryNsList,
				candidateDomain: perm,
				registration: { state: 'registered', ns: candidateNs, evidence: candidateNs.length > 0 ? ['ns'] : ['a'] },
				isSharedNsHost,
				seedNsUnresolved: seedNsUnmeasured,
			}),
		);
	}

	// Phase 2: Detail probe only registered domains
	const probeResults = await probeWithAdaptiveBatching(registeredPerms);
	const results: LookalikeResult[] = [];
	for (const result of probeResults) {
		if (result.status === 'fulfilled') {
			results.push(result.value);
		}
	}
	// Second silent-drop site (#781): a candidate already KNOWN registered, whose
	// infrastructure probe failed, disappears here.
	const probeUnresolved = probeResults.filter((r) => r.status === 'rejected').length;
	// Third silent-drop site (#831): a registered candidate whose A/MX lookups
	// REJECTED carries no positive signal and no measured absence — it cannot be
	// classified as active, and it must not be reported as registered-but-dark
	// either (the absence was unfetched). It is counted as unresolved so the
	// run reports itself incomplete instead of erasing the candidate.
	//
	// ⚠️ ANY degraded probe counts, not only the both-legs-empty case (review
	// follow-up): a candidate whose A resolved while its MX rejected is half
	// measured — its mail capability was never observed — so a run containing one
	// is a SAMPLE, not a census. Gating on `!hasA && !hasMX` let those runs report
	// `complete: true`, which is precisely the "partial run looks conclusive"
	// shape this enumeration contract exists to prevent.
	const infraUnknownCount = results.filter((r) => r.probeDegraded).length;
	/**
	 * Enumeration coverage for this run.
	 *
	 * `complete: false` means the candidate set is a SAMPLE, not a census — so a
	 * consumer diffing consecutive runs must not read a shrinking set as a
	 * deregistration, and a report must not present the list as exhaustive.
	 */
	const enumeration = {
		permutationsGenerated: permutations.length,
		permutationsProbed: permsToProbe.length,
		candidatesResolved: results.length,
		unresolvedCount: nsUnresolved + probeUnresolved + infraUnknownCount,
		complete: nsUnresolved + probeUnresolved + infraUnknownCount === 0,
	};

	// Enrichment (Defect L / issue #264): for each non-defensively-registered
	// lookalike with mail or web infrastructure, gather corroborating signals
	// so the calibrator can pick the right severity tier. Lookalikes the
	// ownership verdict already attributes to the same organisation skip
	// enrichment entirely (they short-circuit to info-severity
	// defensive-registration findings in the main loop below).
	const candidatesToEnrich: LookalikeResult[] = results.filter((r) => {
		const sameOwner = ownershipByDomain.get(r.domain)?.verdict === 'owned_by_seed';
		return !sameOwner && (r.hasMX || r.hasA);
	});
	const enrichment = await enrichLookalikes(candidatesToEnrich);

	// Same-entity correlation (issue #263): a flagged lookalike that shares the
	// scan domain's RDAP registrant org is almost certainly the org's own
	// defensive registration / regional subsidiary (e.g. a vendor's regional
	// presence on a DIFFERENT DNS provider, which the ownership verdict above
	// misses). We only fetch the primary's registrant org — and only apply the
	// correlation — when at least one enriched candidate would surface at
	// medium/high severity, so a clean scan pays no RDAP cost. The candidates'
	// own registrant orgs are already in `enrichment` (harvested from the same
	// fetch as registrationDays), so this adds exactly ONE extra RDAP fetch (the
	// primary), not one-per-candidate. The eligible set is capped at
	// SAME_ENTITY_RDAP_CAP, highest-severity first. Fail-soft: if the primary
	// RDAP org is unknown, NO correlation happens.
	//
	// FIX ROUND 1 (review finding F1): a match here NO LONGER suppresses the
	// threat axis — see the emission site below — and every use of it is gated
	// by `isSameEntityOrgMatch()`, which rejects privacy-proxy / redacted /
	// generic strings on BOTH sides.
	const sameEntityCandidates = computeSameEntityCandidates(results, ownershipByDomain, enrichment);
	// ONE RDAP fetch for the seed, reused for BOTH correlations: the registrant
	// org (unverified, wording-only) and the registry-published registrar ID
	// (the brand-held-registration signal). No extra network cost for the second.
	const primaryRegistration = sameEntityCandidates.length > 0 ? await probePrimaryRegistration(domain) : EMPTY_RDAP_PROBE;
	const primaryRegistrantOrg = primaryRegistration.registrantOrg;
	const sameEntityMatches = new Map<string, string>();
	/** Candidates the registration record corroborates as the seed org's own defensive registrations. */
	const brandHeldMatches = new Map<string, { registrarIanaId: string; registrarName: string | null; reason: DefensiveReason }>();
	for (const candidateDomain of sameEntityCandidates) {
		const corroborators = enrichment.get(candidateDomain);
		const candidateOrg = corroborators?.registrantOrg ?? null;
		if (candidateOrg !== null && isSameEntityOrgMatch(primaryRegistrantOrg, candidateOrg)) {
			sameEntityMatches.set(candidateDomain, candidateOrg);
		}
		const probe = results.find((r) => r.domain === candidateDomain);
		// An ABSENT probe is "we never looked", which is NOT "there is no mail" —
		// and the defensive-shape heuristic fires its `no-mx` reason on an empty
		// array. Defaulting to `[]` here would therefore manufacture a defensive
		// verdict out of a missing measurement, the exact
		// unmeasured-signal-compiled-into-an-affirmative-claim trap. Skip instead.
		// (`computeSameEntityCandidates` only ever names domains drawn from
		// `results`, so this is unreachable today — it is a guard against a
		// future caller widening the eligible set, not a live bug fix.)
		if (probe === undefined) continue;
		const brandHeld = isBrandHeldRegistration({
			seedDomain: domain,
			candidateDomain,
			seedRegistrarIanaId: primaryRegistration.registrarIanaId,
			candidateRegistrarIanaId: corroborators?.registrarIanaId ?? null,
			candidateMxExchanges: probe.mxExchanges,
			candidateNsHosts: Array.from(lookalikeNsMap.get(candidateDomain) ?? []),
		});
		if (brandHeld.brandHeld) {
			brandHeldMatches.set(candidateDomain, {
				registrarIanaId: brandHeld.registrarIanaId,
				registrarName: corroborators?.registrarName ?? null,
				reason: brandHeld.reason,
			});
		}
	}

	// Classify results on BOTH axes (Task 7b). The ownership verdict computed
	// above routes through the D4 gate so an ATTRIBUTION claim about a
	// shared-provider/no-signal candidate can never surface above info (see
	// classifyOwnership()'s JSDoc in ../lib/ownership-attribution); the
	// #264-calibrated OBSERVED-threat severity rides a separate finding that
	// asserts nothing about ownership.
	//
	// `highCount` is reachable again as of Task 7b: it counts threat-OBSERVATION
	// highs, which the ownership cap no longer touches. Under Task 7 it could
	// never increment and the summary finding below was dead code.
	let highCount = 0;
	/** The counted candidates, so the aggregate summary can name what it counted (invariant 4). */
	const highDomains: string[] = [];
	/** Their ownership verdicts — always non-owned, since owned candidates never reach the counter. */
	const highVerdicts = new Set<OwnershipVerdict>();
	/**
	 * EVERY non-owned candidate with a working mail host — a strictly WIDER set
	 * than `highDomains`, which additionally requires a #264 corroborator.
	 *
	 * Tracked separately because the summary finding used to be TITLED for this
	 * set ("N lookalike domains with mail capability detected") while being
	 * COUNTED from the narrower one (#779). Measured on openclaw.ai the title
	 * said 2 while six candidates in the SAME response carried `hasMX: true`;
	 * on openclaw.org it said 1 against 3. A three-fold undercount, in the one
	 * finding a consumer is most likely to read without expanding the per-domain
	 * detail — and it propagated into a client-facing report.
	 *
	 * A domain with working mail AND a live website is not the safer case: the
	 * site lends the mail credibility. Excluding it from a count labelled "mail
	 * capability" was the wrong direction to be wrong in.
	 */
	const mailCapableDomains: string[] = [];
	for (const result of results) {
		const ownership: OwnershipAssessment = ownershipByDomain.get(result.domain) ?? {
			verdict: 'unattributed',
			strength: 'none',
			signals: [],
			rationale: `No ownership signal is available for ${result.domain}.`,
		};
		const sameOwner = ownership.verdict === 'owned_by_seed';

		if (sameOwner) {
			// Structurally owned by the seed — the customer's own domain.
			findings.push(buildOwnedBySeedFinding(result, domain, ownership));
			// Task 7b requirement 5: an `owned_by_seed` candidate gets NO
			// threat-observation finding — the customer's own domain is not an
			// impersonation threat to itself. This `continue` (together with the
			// enrichment skip above) is the only thing enforcing that, so the 6(c)
			// test pins it against a disposable-MX fixture that would otherwise
			// calibrate to HIGH.
			continue;
		}

		if (!result.hasMX && !result.hasA) {
			// #831 — registered but dark: NS resolved, and the A/MX probe MEASURED
			// no infrastructure. "Held and dark" and "unregistered" are opposite
			// custody facts, so the candidate is surfaced (info, attribution axis,
			// never impersonation-scored) instead of dropped silently. A DEGRADED
			// probe is the one exception: the absence was unfetched, not measured
			// (#832's law), so the candidate is left to the enumeration
			// incompleteness accounting above rather than recorded as dark.
			if (!result.probeDegraded) {
				findings.push(buildRegisteredDarkFinding(result, domain, ownership));
			}
			continue;
		}

		const corroborators = enrichment.get(result.domain) ?? {
			registrationDays: null,
			mxOnDisposable: false,
			hasWebContent: true,
			registrantOrg: null,
		};
		const signals: LookalikeSignals = {
			hasA: result.hasA,
			hasMX: result.hasMX,
			registrationDays: corroborators.registrationDays,
			mxOnDisposable: corroborators.mxOnDisposable,
			hasWebContent: corroborators.hasWebContent,
		};
		const severity = calibrateLookalikeSeverity(signals);
		const corroboratorReasons = describeCorroborators(signals);

		// Same-entity correlation (issue #263): the calibrated severity is a
		// threat tier (low/medium/high), but if this lookalike's RDAP registrant
		// org matches the scan domain's, it's PLAUSIBLY the org's own defensive /
		// regional registration. It is REPORTED as such — see
		// `buildSharedRegistrantOrgFinding` — but the threat axis below is
		// emitted regardless. Only medium/high candidates are eligible (see
		// computeSameEntityCandidates); LOW web-only matches stay as-is (cheap,
		// low-noise, not worth the fetch).
		const matchedOrg = sameEntityMatches.get(result.domain);
		const brandHeld = brandHeldMatches.get(result.domain);
		if (brandHeld !== undefined) {
			findings.push(buildBrandHeldFinding(result, domain, ownership, brandHeld));
		} else if (matchedOrg !== undefined) {
			findings.push(buildSharedRegistrantOrgFinding(result, domain, ownership, matchedOrg));
		} else {
			// AXIS 1 — the ownership verdict caps the ATTRIBUTION finding's
			// severity. `attributionConfidence()` (fed the MX-overlap
			// corroboration signal below) governs WORDING/CONFIDENCE only.
			const mxOverlapsPrimary = result.mxExchanges.some((ex) => primaryMx.has(ex));
			const rawFinding = buildRawAttributionFinding(result, domain, severity, signals, corroboratorReasons);

			// Attribution pushed FIRST so a consumer scanning for the ownership
			// statement about a candidate finds it ahead of the threat observation.
			findings.push(applyOwnershipGate(rawFinding, ownership, brand, mxOverlapsPrimary));
		}

		// #832 — an UNMEASURED ownership verdict withholds the impersonation-
		// shaped finding (and its counters) for this candidate in this run: the
		// comparison that would justify "does not appear to belong to the
		// scanned organisation" never completed, and near-complete runs have
		// proven the same candidate `owned_by_seed` (jcpenny.com, full 8/8 NS
		// match). The attribution finding above still names the candidate with
		// its unmeasured verdict, and the run-level scan_status notice below
		// explains the withholding, so the non-answer is visible — not a record.
		if (ownership.verdict === 'unmeasured') continue;

		// AXIS 2 — the observed threat, at the severity the #264 matrix computed
		// and Task 7 used to discard. Emitted for EVERY non-owned candidate,
		// including one whose RDAP registrant org matched the seed's (fix round 1,
		// F1: that string is unverified and collision-prone, so it may annotate the
		// observation but must never switch the axis off). Only `owned_by_seed`
		// candidates (which `continue` above) and `unmeasured` candidates (#832)
		// are exempt.
		findings.push(
			buildThreatObservationFinding(
				result.domain,
				domain,
				severity,
				signals,
				ownership,
				corroboratorReasons,
				matchedOrg,
				brandHeld !== undefined,
			),
		);
		// `hasMX` is already false for an RFC 7505 null MX (`0 .`), which is the
		// explicit way a domain declines mail — so this counts real mail hosts,
		// not merely "an MX record exists".
		if (result.hasMX) mailCapableDomains.push(result.domain);
		if (result.hasMX && severity === 'high') {
			highCount++;
			highDomains.push(result.domain);
			highVerdicts.add(ownership.verdict);
		}
	}

	if (highCount > 0) {
		findings.push(buildStagingSummaryFinding({ seedDomain: domain, highCount, highDomains, highVerdicts, mailCapableDomains, enumeration }));
	} else if (mailCapableDomains.length > 0) {
		findings.push(buildMailCapableSummaryFinding({ seedDomain: domain, mailCapableDomains, enumeration }));
	}

	// If no active lookalikes found
	if (findings.length === 0) {
		findings.push(buildNoActiveInfrastructureFinding(domain, permutations.length, enumeration));
	}

	// #832 — run-level honesty notice: attribution was declined this run, and a
	// consumer reading findings must be able to tell that from a concluded
	// third-party verdict.
	if (seedNsUnmeasured) {
		// Count the verdicts that actually came out `unmeasured`, NOT the batch size
		// (review follow-up): classifyOwnership() deliberately preserves
		// `owned_by_seed` for an in-bailiwick candidate NS even when the seed lookup
		// failed, so in a mixed batch `registeredPerms.length` overstates — the
		// notice would claim candidates were unattributed that this run did attribute.
		const unmeasuredCandidateCount = [...ownershipByDomain.values()].filter((a) => a.verdict === 'unmeasured').length;
		findings.push(buildOwnershipUnmeasuredFinding(domain, unmeasuredCandidateCount));
	}

	if (!enumeration.complete) {
		findings.push(buildIncompleteEnumerationFinding(domain, enumeration));
	}

	// Recon enrichment: additive-only, fail-soft.
	//
	// FIX ROUND 1, F1 (2026-07-27, post-review): this block used to emit a
	// `medium`-severity `threat_observation` with NO `ownershipVerdict` and
	// `domain: domain` (the SEED, not any candidate) — a live violation of
	// this slice's own load-bearing safety property, caught by the Task 8
	// audit's adversarial review (`ownership-severity-gate.audit.test.ts`).
	// bv-recon's CT_LOOKALIKE check is scoped to the seed's own CT-log
	// neighbourhood; it does not always name a specific confusable domain, so
	// `extractReconMatchedDomain()` below may legitimately return null.
	if (reconOptions.reconBinding) {
		const reconResult = await callReconScan(
			reconOptions.reconBinding,
			reconOptions.reconAuthToken,
			'CT_LOOKALIKE',
			{ domain },
			undefined,
			reconOptions.onBindingDegradation,
		);
		const hit = reconResult && isReconHit(reconResult.status);
		if (hit && reconResult) {
			const matchedDomain = extractReconMatchedDomain(reconResult, domain);
			const detail = reconResult.details ?? `Threat intelligence corroborates CT-observed lookalike signal for ${domain}.`;

			if (matchedDomain) {
				// A named candidate — reuse the SAME ownership assessment the local
				// classification loop above computed when we also generated/probed
				// this permutation ourselves. When bv-recon names a domain outside
				// our own generated permutation set, default to `unattributed`
				// (never `owned_by_seed` — an externally-sourced, unverified match
				// is never sufficient to claim the candidate is the customer's own).
				const reconOwnership: OwnershipAssessment = ownershipByDomain.get(matchedDomain) ?? {
					// #832: when the seed's NS lookup failed, an externally-named
					// candidate is exactly as uncomparable as the locally-generated
					// ones — the run's attribution lane is down, so it inherits the
					// unmeasured verdict rather than a definitive-sounding default.
					verdict: seedNsUnmeasured ? 'unmeasured' : 'unattributed',
					strength: 'none',
					signals: [],
					rationale: seedNsUnmeasured
						? `Ownership of ${matchedDomain} was not assessed in this run: the nameserver lookup for ${domain} did not resolve, so no comparison was possible.`
						: `No ownership signal is available for ${matchedDomain}.`,
				};
				// Task 7b requirement 5: a candidate already known to be the
				// customer's own domain gets no threat_observation finding — this
				// enrichment is additive-only and adds nothing new for one.
				// #832: an `unmeasured` candidate gets none either — the recon
				// corroboration is a per-candidate impersonation-shaped claim, and
				// the run's degraded comparison cannot rule out that the candidate
				// is the customer's own (the scan_status notice covers the run).
				if (reconOwnership.verdict !== 'owned_by_seed' && reconOwnership.verdict !== 'unmeasured') {
					findings.push(buildReconCandidateFinding(matchedDomain, detail, reconOwnership));
				}
			} else {
				findings.push(buildReconScanStatusFinding(domain, detail));
			}
		}
	}

	const result = buildCheckResult('lookalikes', findings);
	// A degraded ownership comparison is TRANSIENT (throttled/timed-out seed NS
	// lookup), but `check_lookalikes` is cached for an hour and the dispatcher
	// skips cache writes only for `partial` results (review follow-up). Without
	// this, the withheld verdicts and suppressed threat observations from one
	// throttled run would be served for the full TTL after DNS recovered — the
	// non-answer outliving the condition that caused it. Same contract the
	// timeout path in checkLookalikes() already honours.
	if (seedNsUnmeasured) {
		result.partial = true;
	}
	return result;
}
