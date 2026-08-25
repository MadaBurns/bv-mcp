// SPDX-License-Identifier: BUSL-1.1

/**
 * PER-CANDIDATE finding construction for the lookalike check — one module per
 * emitted Finding shape, extracted VERBATIM from `check-lookalikes.ts` (pure
 * split, no behaviour change). Run-level (summary / `scan_status`) findings
 * live in `lookalike-summary-findings.ts`.
 *
 * TASK 7B TWO-AXIS SPLIT (human-partner ruling, 2026-07-27).
 *
 * The lookalike tool reports on TWO independent axes, and every finding it
 * emits declares which one it belongs to via `metadata.findingAxis`:
 *
 *  - `'attribution'` — WHO owns the candidate. Governed by
 *    `classifyOwnership()` + `capAttributionSeverity()`: every non-
 *    `owned_by_seed` verdict is capped at `info` with neutral wording
 *    (D4's load-bearing safety property — the scanner never claims someone
 *    else's domain is the customer's, and never demands the customer act on
 *    a domain it does not control). UNCHANGED by this task.
 *
 *  - `'threat_observation'` — WHAT the candidate is doing. Carries the #264
 *    calibrated severity from `calibrateLookalikeSeverity()`. Task 7 computed
 *    that severity and then capped it away, which made `highCount`, the HIGH
 *    summary finding, and every sub-100 `lookalikes` category score
 *    unreachable — a live typosquat with active MX on a disposable provider
 *    scored 100/passed. These findings assert NOTHING about ownership (they
 *    say explicitly that the domain does not appear to belong to the scanned
 *    organisation) and demand no action ON that domain; only defensive
 *    options on the scanned organisation's own side are suggested.
 *
 *  - `'scan_status'` — the RUN itself, not any candidate: the "no active
 *    lookalike domains detected" notices and the timeout notice. Always
 *    `info`. Split out in fix round 1 (F2) because forcing these into
 *    `'threat_observation'` made the threat-axis invariants below unstateable.
 *
 * INVARIANTS (true of this module and its summary sibling, pinned by
 * `test/check-lookalikes.spec.ts`, and what Task 8's cross-cutting audit keys
 * on):
 *   1. every finding carries one of the three literals;
 *   2. every `'scan_status'` finding is `info`;
 *   3. no `'threat_observation'` finding carries `ownershipVerdict ===
 *      'owned_by_seed'` — a threat observation is never about a domain the
 *      scanned organisation owns;
 *   4. every `'threat_observation'` finding names the candidate it observed via
 *      `lookalikeDomain` (per candidate, INCLUDING the named-candidate recon CT
 *      corroboration) or `lookalikeDomains` (the aggregate summary). Bare
 *      `domain` metadata (scoped to the scanned domain, not a candidate) only
 *      ever appears on the demoted `'scan_status'` finding emitted when recon
 *      names no specific candidate — never on a `'threat_observation'` finding.
 *
 * The axis marker is STRUCTURAL, not prose: downstream consumers (and Task
 * 8's cross-cutting audit) key on the exact literals, never on wording.
 */

import type { DefensiveReason } from '../lib/brand-defensive-registration';
import { buildNonOwnedGateFinding, capAttributionSeverity, type OwnershipAssessment } from '../lib/ownership-attribution';
import type { Finding } from '../lib/scoring';
import { createFinding } from '../lib/scoring';
import type { LookalikeResult } from './lookalike-dns';
import type { LookalikeSeverity, LookalikeSignals } from './lookalike-severity';

export type LookalikeFindingAxis = 'attribution' | 'threat_observation' | 'scan_status';

/**
 * Human phrasing for a {@link DefensiveReason} token. Internal enum values are
 * meaningless in a customer-facing report about a named organisation — the
 * same rule `UNKNOWN_REASON_PHRASES` exists for in `registration-state.ts`.
 *
 * WORDING CONSTRAINT: none of these may contain `missing`, `required`,
 * `not found`, or the `no <...> record` shape. `scoreIndicatesMissingControl()`
 * in the vendored scoring package matches finding TEXT, and a match on a
 * high-severity finding ZEROES the whole category score — the one way a
 * wording change in this file could move a number. Pinned by a boundary test.
 */
export const DEFENSIVE_REASON_PHRASES: Record<DefensiveReason, string> = {
	'redirect-to-target': 'its web root redirects back to the scanned domain',
	'parked-ns': 'its nameservers are at a domain-parking provider',
	'no-mx': 'it carries no active mail service',
};

/**
 * Build a short human-readable list of corroborating signals for the finding
 * detail. Empty string when none apply (mail-infra-alone case).
 */
export function describeCorroborators(signals: LookalikeSignals): string {
	const parts: string[] = [];
	if (signals.registrationDays !== null && signals.registrationDays < 90) {
		parts.push(`registered ${signals.registrationDays} day${signals.registrationDays === 1 ? '' : 's'} ago`);
	}
	if (signals.mxOnDisposable) parts.push('disposable MX provider');
	if (!signals.hasWebContent) parts.push('no reachable web content');
	return parts.join(', ');
}

/**
 * AXIS 1 — the candidate is STRUCTURALLY owned by the seed (the customer's own
 * domain). Emitted instead of, never alongside, a threat observation: Task 7b
 * requirement 5 is that an `owned_by_seed` candidate gets no threat finding at
 * all, since the customer's own domain is not an impersonation threat to itself.
 */
export function buildOwnedBySeedFinding(result: LookalikeResult, seedDomain: string, ownership: OwnershipAssessment): Finding {
	return createFinding(
		'lookalikes',
		`Lookalike domain likely owned by same entity: ${result.domain}`,
		'info',
		`The domain ${result.domain} is owned by the same organisation as ${seedDomain} (${ownership.rationale}).${result.hasMX ? ' Has active mail infrastructure.' : ''}${result.hasA ? ' Has web presence.' : ''}`,
		{
			lookalikeDomain: result.domain,
			hasA: result.hasA,
			hasMX: result.hasMX,
			ownershipVerdict: ownership.verdict,
			findingAxis: 'attribution' satisfies LookalikeFindingAxis,
		},
	);
}

/**
 * AXIS 1 — the registration record corroborates that this is the scanned
 * organisation's OWN defensive registration. Emitted INSTEAD of the neutral D4
 * gate template, which would otherwise state positively that the domain "is
 * registered to a different organisation" — a claim the nameserver evidence
 * alone never supported and which is simply false here.
 *
 * SEVERITY IS `info`, EXACTLY AS {@link applyOwnershipGate} WOULD HAVE CAPPED
 * IT. This branch changes what the report SAYS, never what it SCORES:
 * `capAttributionSeverity()` caps every non-`owned_by_seed` attribution finding
 * at `info` regardless, so swapping the prose moves no penalty. Pinned by the
 * boundary test in `test/ownership-attribution.spec.ts`.
 */
export function buildBrandHeldFinding(
	result: LookalikeResult,
	seedDomain: string,
	ownership: OwnershipAssessment,
	brandHeld: { registrarIanaId: string; registrarName: string | null; reason: DefensiveReason },
): Finding {
	const registrarLabel = brandHeld.registrarName
		? `${brandHeld.registrarName} (IANA ${brandHeld.registrarIanaId})`
		: `IANA registrar ${brandHeld.registrarIanaId}`;
	return createFinding(
		'lookalikes',
		`Confusable domain held at the same brand-protection registrar: ${result.domain}`,
		'info',
		`The domain ${result.domain} is a confusable variant of ${seedDomain}, and the registry publishes the SAME brand-protection registrar for both (${registrarLabel}). Its infrastructure also has the shape of a defensive registration — ${DEFENSIVE_REASON_PHRASES[brandHeld.reason]}. Brand-protection registrars do not sell to the general public and the IANA registrar ID is published by the registry rather than declared by the registrant, so this corroborates that ${result.domain} is held by the scanned organisation itself; it is not proof, since one such registrar serves many brands. Nameserver evidence is separate and did not link the two: ${ownership.rationale} Confirm against your own domain portfolio before treating ${result.domain} as an outside party's.`,
		{
			lookalikeDomain: result.domain,
			hasA: result.hasA,
			hasMX: result.hasMX,
			brandHeldRegistration: true,
			sharedRegistrarIanaId: brandHeld.registrarIanaId,
			defensiveReason: brandHeld.reason,
			// Ruling A holds: registrar evidence never manufactures
			// `owned_by_seed`. The STRUCTURAL verdict travels unchanged.
			ownershipVerdict: ownership.verdict,
			ownershipRationale: ownership.rationale,
			findingAxis: 'attribution' satisfies LookalikeFindingAxis,
		},
	);
}

/**
 * AXIS 1 — the registrant-org observation REPLACES the neutral D4 gate
 * template for this candidate (it is strictly more informative), but it
 * is still an attribution statement capped at info.
 *
 * F2 (2026-07-27 fix round 2): a RDAP registrant-org match is DELIBERATELY NOT
 * fed into `classifyOwnership()` as an ownership signal — the org field is
 * self-declared and unverified by most registries, so it must never be able to
 * silently produce an `owned_by_seed` verdict. Every candidate reaching this
 * branch therefore still carries the STRUCTURAL verdict computed earlier
 * (`third_party` here), and the verdict travels on this finding too
 * (`ownershipVerdict` in metadata) per the same "verdict travels on EVERY
 * classified finding" invariant `check-shadow-domains.ts` states for its own
 * emission sites. The title/prose does not assert common ownership outright —
 * it states plainly that this is a registrant-organisation SIGNAL, distinct
 * from (and weaker than) the structural NS-based evidence, whose own finding is
 * quoted verbatim.
 */
export function buildSharedRegistrantOrgFinding(
	result: LookalikeResult,
	seedDomain: string,
	ownership: OwnershipAssessment,
	matchedOrg: string,
): Finding {
	return createFinding(
		'lookalikes',
		`Lookalike domain shares registrant organisation with scanned domain: ${result.domain}`,
		'info',
		`The domain ${result.domain} shares the same RDAP registrant organisation as ${seedDomain} ("${matchedOrg}"), which may indicate a defensive registration or regional presence by the same owner. This is a registrant-organisation signal, not structural ownership evidence — RDAP registrant fields are self-declared and not independently verified. Nameserver-based evidence: ${ownership.rationale}${result.hasMX ? ' Has active mail infrastructure.' : ''}${result.hasA ? ' Has web presence.' : ''}`,
		{
			lookalikeDomain: result.domain,
			hasA: result.hasA,
			hasMX: result.hasMX,
			sharedRegistrantOrg: matchedOrg,
			ownershipVerdict: ownership.verdict,
			ownershipRationale: ownership.rationale,
			findingAxis: 'attribution' satisfies LookalikeFindingAxis,
		},
	);
}

/**
 * AXIS 1 — the UNGATED attribution finding for a candidate with no
 * registrar/registrant corroboration. Always routed through
 * {@link applyOwnershipGate} before emission: the ownership verdict caps its
 * severity, so a candidate with no ownership signal linking it to the scanned
 * organisation can never surface above info, regardless of how threatening its
 * raw infrastructure signals look. `attributionConfidence()` governs
 * WORDING/CONFIDENCE only — see {@link applyOwnershipGate}'s JSDoc.
 */
export function buildRawAttributionFinding(
	result: LookalikeResult,
	seedDomain: string,
	severity: LookalikeSeverity,
	signals: LookalikeSignals,
	corroboratorReasons: string,
): Finding {
	return result.hasMX
		? createFinding(
				'lookalikes',
				`Lookalike domain with mail infrastructure: ${result.domain}`,
				severity,
				`The domain ${result.domain} is registered with active mail servers (MX records), which could be used for phishing or email spoofing targeting ${seedDomain}.${corroboratorReasons ? ` Corroborating signals: ${corroboratorReasons}.` : ''}`,
				{
					lookalikeDomain: result.domain,
					hasA: result.hasA,
					hasMX: result.hasMX,
					registrationDays: signals.registrationDays,
					mxOnDisposable: signals.mxOnDisposable,
					hasWebContent: signals.hasWebContent,
					findingAxis: 'attribution' satisfies LookalikeFindingAxis,
				},
			)
		: createFinding(
				'lookalikes',
				`Lookalike domain registered: ${result.domain}`,
				severity,
				`The domain ${result.domain} is registered (has web presence) but no mail infrastructure detected. It could still be used for phishing websites targeting ${seedDomain}.${corroboratorReasons ? ` Corroborating signals: ${corroboratorReasons}.` : ''}`,
				{
					lookalikeDomain: result.domain,
					hasA: result.hasA,
					hasMX: result.hasMX,
					registrationDays: signals.registrationDays,
					mxOnDisposable: signals.mxOnDisposable,
					hasWebContent: signals.hasWebContent,
					findingAxis: 'attribution' satisfies LookalikeFindingAxis,
				},
			);
}

/**
 * AXIS 1 (attribution) ONLY — Task 7b. This caps what the report may CLAIM
 * about ownership; it does not and must not cap what the report may say was
 * OBSERVED. The observed-threat severity now travels on a separate finding
 * built by {@link buildThreatObservationFinding}, so capping here no longer
 * makes `highCount`, the HIGH summary finding, and every sub-100 `lookalikes`
 * category score unreachable (the defect the opus review found in Task 7).
 *
 * D4 severity ceiling for a lookalike finding, mirroring `applyOwnershipGate()`
 * in `check-shadow-domains.ts` — see that file's JSDoc for the full rationale;
 * this is the same pattern reused for a second tool so the two stay
 * consistent for downstream consumers. The neutral-wording sentence and
 * metadata shape live in `buildNonOwnedGateFinding()`
 * (`src/lib/ownership-attribution.ts`), shared with `check-shadow-domains.ts`
 * (fix round 2, F1) — the two tools had already drifted apart within this
 * slice when each hand-rolled its own copy.
 *
 * `owned_by_seed` findings pass through unclamped — `checkLookalikesCore`'s
 * main loop already emits its own dedicated "likely owned by same entity"
 * finding for that verdict before this function is ever reached, so in
 * practice every call here receives a non-owned verdict. The passthrough
 * branch exists anyway so the invariant is explicit and enforced at this
 * chokepoint rather than merely assumed by the caller.
 *
 * DEMOTE, NEVER DELETE (binding ruling): this returns a `Finding`, never
 * `null`/`undefined` — a real measurement (an active registration with
 * MX/A records) is never suppressed, only its severity capped and its
 * wording made neutral. `attributionConfidence()` governs WORDING/CONFIDENCE
 * ONLY; it can never move the ceiling, which `capAttributionSeverity()`
 * derives from `ownership.verdict` alone.
 */
export function applyOwnershipGate(finding: Finding, ownership: OwnershipAssessment, brand: string, corroborated: boolean): Finding {
	const ceiling = capAttributionSeverity(ownership.verdict);
	if (ceiling === 'unbounded') return finding;

	// `calibrateLookalikeSeverity()` never returns `'info'`, so unlike
	// `check-shadow-domains.ts` there is no local info-severity branch here —
	// every candidate reaching this point goes through the shared non-owned
	// rewrite. `postureNoun` MUST match `check-shadow-domains.ts`'s value
	// byte-for-byte (parity pinned by `test/ownership-attribution.spec.ts`).
	return buildNonOwnedGateFinding(finding, ownership, brand, corroborated, ceiling, {
		category: 'lookalikes',
		domainMetadataKey: 'lookalikeDomain',
		postureNoun: 'DNS/mail posture',
	});
}

/**
 * AXIS 2 — build the observed-threat finding for a NON-OWNED candidate
 * (Task 7b). Carries the #264 calibrated severity verbatim; the attribution
 * finding built by {@link applyOwnershipGate} carries the `info` cap.
 *
 * WORDING CONTRACT (customer-facing, legal-sensitive — BlackVeil names real
 * third-party organisations in reports). The text:
 *  - states only what was OBSERVED (MX/A presence, registration recency,
 *    disposable MX, absent web content) — no claim of intent.
 *    "Impersonation-shaped" / "consistent with pre-phishing staging" is the
 *    ceiling; the words "malicious"/"attacker" are deliberately absent;
 *  - says EXPLICITLY that the domain does not appear to belong to the scanned
 *    organisation, so no reader can mistake this for an ownership claim;
 *  - never uses "your", "shadow domain", or any ownership/control framing;
 *  - demands no action ON the observed domain. Only defensive options that
 *    need no access to it (monitor, block at the gateway, report for
 *    takedown) are offered.
 *
 * Pinned by `test/check-lookalikes.spec.ts`'s Task 7b block, which asserts
 * both the positive wording and the banned-framing negatives on title AND
 * detail (a split surface — right severity, ownership-framed prose — is the
 * failure mode that bit Task 6's first review pass).
 */
export function buildThreatObservationFinding(
	candidateDomain: string,
	seedDomain: string,
	severity: LookalikeSeverity,
	signals: LookalikeSignals,
	ownership: OwnershipAssessment,
	corroboratorReasons: string,
	sharedRegistrantOrg: string | undefined,
	/**
	 * True when `isBrandHeldRegistration` corroborated that the candidate
	 * is the scanned organisation's OWN defensive registration. Changes the
	 * closing REMEDIATION sentence only — the observation and its calibrated
	 * severity are emitted unchanged, per the F1 ruling that an attribution
	 * signal may annotate the threat axis but never switch it off or discount
	 * it. Telling a customer to report their own domain for takedown is not a
	 * severity question; it is simply wrong advice.
	 */
	brandHeld = false,
): Finding {
	const infraPhrase = signals.hasMX
		? `active mail infrastructure (MX records), so it is capable of sending mail that resembles ${seedDomain}`
		: 'web infrastructure (A records) and no active mail infrastructure';
	const observed = corroboratorReasons ? `${infraPhrase}; also observed: ${corroboratorReasons}` : infraPhrase;
	// FIX ROUND 1 (F1): when the #263 correlation found a shared registrant-org
	// string, it is RECORDED here — as an unverified observation — but it does
	// NOT reduce the severity and does not suppress this finding. An org string
	// anyone can type into a registrar form earns a sentence, not a discount.
	const registrantNote = sharedRegistrantOrg
		? ` Its RDAP registrant-organisation string matches the one published for ${seedDomain} ("${sharedRegistrantOrg}"); that field is self-declared, unverified by the registry, and frequently a shared privacy-service placeholder, so it is recorded but does not reduce what was observed here.`
		: '';
	// The attribution clause and the closing remediation clause both assume the
	// candidate is an outside party's. When the registration record corroborates
	// that it is the scanned organisation's OWN defensive registration, both are
	// replaced — the observation itself and its calibrated severity are
	// untouched, so nothing here moves a score.
	const attributionClause = brandHeld
		? `the registry publishes the same brand-protection registrar for it as for ${seedDomain}, so it is most likely the scanned organisation's own defensive registration`
		: `${candidateDomain} does not appear to belong to the scanned organisation, this finding claims no control over it, and no change to it is requested`;
	const remediationClause = brandHeld
		? `Because this looks like your own defensive registration, treat it as portfolio hygiene rather than a threat: confirm it against your domain portfolio, and keep it parked with mail explicitly disabled so it cannot be used to send. Do NOT report it for takedown without confirming ownership first.`
		: `Defensive options that need no access to ${candidateDomain}: monitor it, block or quarantine mail bearing that name at the gateway, and report it to its registrar or a takedown provider.`;
	return createFinding(
		'lookalikes',
		`Impersonation-shaped ${signals.hasMX ? 'infrastructure' : 'web infrastructure'} observed: ${candidateDomain}`,
		severity,
		`${candidateDomain} is a confusable variant of ${seedDomain} and was observed with ${observed}. This is an infrastructure observation only: ${attributionClause}.${registrantNote} ${remediationClause}`,
		{
			...(brandHeld ? { brandHeldRegistration: true } : {}),
			lookalikeDomain: candidateDomain,
			hasA: signals.hasA,
			hasMX: signals.hasMX,
			registrationDays: signals.registrationDays,
			mxOnDisposable: signals.mxOnDisposable,
			hasWebContent: signals.hasWebContent,
			findingAxis: 'threat_observation' satisfies LookalikeFindingAxis,
			// The verdict travels on EVERY classified finding, threat axis
			// included, so a consumer can read "high observed threat, NOT owned by
			// the customer" off a single object rather than correlating two.
			ownershipVerdict: ownership.verdict,
			...(sharedRegistrantOrg ? { sharedRegistrantOrg } : {}),
		},
	);
}
