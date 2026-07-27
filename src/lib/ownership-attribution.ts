// SPDX-License-Identifier: BUSL-1.1

/**
 * Ownership-attribution primitive (P2, 2026-07-26 correctness-defects design §4).
 *
 * Classifies a registered candidate domain's ownership relative to a seed
 * domain. `capAttributionSeverity()` below is the single gate that decides
 * whether a shadow-domain or lookalike finding may exceed `info` severity —
 * see `docs/superpowers/specs/2026-07-26-bv-mcp-correctness-defects-design.md`
 * §4 (P2) and §5 (D4).
 *
 * Pure function, no DNS I/O: callers gather NS records and registration
 * state themselves (via `resolveRegistration()` from `./registration-state`,
 * or an existing NS probe) and pass them in — mirroring the injectable-
 * dependency pattern already used by `correlateNs`
 * (`src/tenants/discovery/ns-correlator.ts`'s `NsCorrelationOptions.dnsQuery`).
 * This keeps `src/lib/` free of a dependency on `src/tenants/discovery/`:
 * the shared-NS-apex predicate is passed in as `isSharedNsHost` rather than
 * imported directly.
 *
 * LOAD-BEARING SAFETY PROPERTY (controller amendment 2, do not weaken):
 * severity gating keys ONLY on `verdict === 'owned_by_seed'` vs everything
 * else. The `third_party` / `unattributed` distinction changes report
 * wording, never severity — a misclassification between those two can never
 * produce a false high-severity finding. `capAttributionSeverity()` enforces
 * this and takes `verdict` ALONE — no other input can move the ceiling.
 *
 * DEMOTE, NEVER DELETE (controller amendment 1, binding ruling from the
 * human partner): `attributionConfidence()` is a CLASSIFIER of wording
 * confidence, not a severity gate and not a suppressor — see fix-round F1/F3
 * below for why it must never be consulted for the severity ceiling.
 * `capAttributionSeverity()` is the ONLY exported severity-decision surface:
 * it always returns a concrete, truthy value (a `Severity` or the
 * `'unbounded'` sentinel) — there is no `null`/`undefined` return a caller
 * could mistake for "omit this finding". A real measurement must never be
 * suppressed; only its severity is capped and its wording kept neutral.
 *
 * FIX ROUND 1 (2026-07-27, post-review): the first implementation had
 * `capAttributionSeverity()` consult the D4 label-length/corroboration guard
 * BEFORE the ownership verdict, so any non-owned candidate with a brand
 * label >= `MIN_ATTRIBUTION_LABEL_LENGTH` characters (e.g. `westpac`, a
 * competing bank) came back `'unbounded'` — the exact defect this slice
 * exists to fix, on the safety-critical function. Corrected:
 * `capAttributionSeverity()` now takes ONLY `verdict` and gates on ownership
 * FIRST. The label-length/corroboration guard (`attributionConfidence()`,
 * renamed from `passesAttributionGuard()`) still exists but now governs
 * WORDING/CONFIDENCE prose only — it is never consulted for severity, and
 * its non-boolean `'corroborated' | 'uncorroborated'` return shape (renamed
 * from a raw boolean) makes it read as a confidence classifier rather than
 * a permission gate a caller might branch into a suppression.
 *
 * TASK 7c (2026-07-27, two rulings amending the P2 signal table — see
 * `.superpowers/sdd/2026-07-26-slice4-ownership-attribution/task-7c-brief.md`):
 * Ruling A — the candidate-side signals (`soaInBailiwick`,
 * `spfIncludesSeedApex`, `httpRedirectToSeedApex`) are attacker-influenceable
 * and NEVER independently verdict-bearing; see the OWNERSHIP RULE note on
 * `ClassifyOwnershipInput`. Ruling B — an in-bailiwick NS observation is
 * ownership-bearing only when it comes from an actually-resolved NS answer
 * set; see `classifyOwnership()`'s precedence-table JSDoc and
 * `resolveRegistrationUncached()` in `./registration-state`.
 */

import type { CheckCategory, Finding, Severity } from '@blackveil/dns-checks/scoring';
import { createFinding } from '@blackveil/dns-checks/scoring';
import { getRegistrableDomain } from './public-suffix';
import { UNKNOWN_REASON_PHRASES, type RegistrationState } from './registration-state';

/** Final attribution verdict. */
export type OwnershipVerdict = 'owned_by_seed' | 'third_party' | 'unattributed';

/**
 * `classifyOwnership()` only ever returns `'strong'`, `'medium'`, or
 * `'none'` — there is no rule in the current precedence table that yields
 * `'weak'`. Kept out of the union rather than left as a dead member so a
 * caller `switch` can be exhaustive.
 */
export type OwnershipStrength = 'strong' | 'medium' | 'none';

export type OwnershipSignal =
	| 'ns_in_bailiwick'
	| 'ns_set_match'
	| 'ns_shared_provider_complete'
	| 'soa_in_bailiwick'
	| 'spf_include_seed'
	| 'http_redirect_seed'
	| 'distinct_infrastructure';

export interface OwnershipAssessment {
	verdict: OwnershipVerdict;
	strength: OwnershipStrength;
	signals: OwnershipSignal[];
	/** Human-readable, safe to surface in a report — never implies ownership beyond `verdict`. */
	rationale: string;
}

export interface ClassifyOwnershipInput {
	seedDomain: string;
	/** The seed's own NS hostnames. */
	seedNs: string[];
	candidateDomain: string;
	registration: RegistrationState;
	/**
	 * Injected shared-NS-apex predicate (`isSharedNsHost` from
	 * `src/tenants/discovery/shared-ns-hosts.ts`). Required so this module
	 * never imports from `src/tenants/discovery/` (see file header).
	 */
	isSharedNsHost: (nsHost: string) => boolean;
	/**
	 * Candidate-side corroboration inputs. Not gathered by any caller in this
	 * slice (neither tool parses SPF `include:` targets, SOA RNAME, or HTTP
	 * redirect targets today) — accepted here so a future slice can wire a
	 * real probe without touching this function's precedence logic again.
	 *
	 * OWNERSHIP RULE (Ruling A, 2026-07-27 task-7c — supersedes the prior F4
	 * "flagged, not fixed" note): all three of `soaInBailiwick`,
	 * `spfIncludesSeedApex`, and `httpRedirectToSeedApex` are
	 * attacker-influenceable. Unlike `ns_in_bailiwick` / `ns_set_match` /
	 * `ns_shared_provider_complete` (which all require the CANDIDATE's own
	 * resolved NS records to actually nest under or match the seed's — i.e.
	 * seed-side control), an attacker who registers `evilbnz.co.nz` can
	 * unilaterally publish an SPF `include:` pointing at the seed apex, an
	 * HTTP redirect to it, or an in-bailiwick SOA RNAME, with NO cooperation
	 * from the seed's owner. Ownership verdicts therefore require a seed-side
	 * signal. These three fields:
	 *  - may RAISE `strength`/wording confidence on a verdict ALREADY earned
	 *    by a seed-side signal (steps 2-4 in `classifyOwnership()`'s
	 *    precedence table);
	 *  - may serve as CORROBORATION for `attributionConfidence()`'s wording
	 *    channel;
	 *  - must NEVER, alone or in any combination with each other, produce
	 *    `owned_by_seed` — `classifyOwnership()` does not consult them at all
	 *    for the verdict.
	 * A future caller that wires a real probe for any of these MUST NOT let
	 * it alone (or all three together) produce `owned_by_seed`.
	 */
	soaInBailiwick?: boolean;
	spfIncludesSeedApex?: boolean;
	httpRedirectToSeedApex?: boolean;
}

/** Minimum ratio of dedicated (non-shared-provider) NS hosts shared with the seed to count as strong evidence. */
const DEDICATED_NS_MATCH_RATIO = 0.5;
/** Minimum absolute count of dedicated shared NS hosts, alongside the ratio above. */
const DEDICATED_NS_MATCH_MIN_COUNT = 2;

/** Minimum brand-label length below which a non-owned candidate needs corroboration to be worded with full confidence (D4). Governs WORDING ONLY — see `attributionConfidence()`. */
export const MIN_ATTRIBUTION_LABEL_LENGTH = 5;

function normHost(h: string): string {
	return h.trim().toLowerCase().replace(/\.$/, '');
}

/**
 * True when `nsHost` is the seed apex itself or a subdomain of it.
 *
 * The dot-boundary check on the `endsWith` branch is load-bearing: without
 * it, a lookalike like `evilbnz.co.nz` (or an NS host under it,
 * `ns1.evilbnz.co.nz`) would satisfy a bare `hostname.endsWith(seedApex)`
 * check against seed `bnz.co.nz`, because the substring `bnz.co.nz` appears
 * inside `evilbnz.co.nz` with no label separator in front of it. Requiring
 * the character immediately before the apex to be `.` (or an exact match)
 * closes that off.
 */
export function isInBailiwick(nsHost: string, seedApex: string): boolean {
	const host = normHost(nsHost);
	const apex = normHost(seedApex);
	if (!host || !apex) return false;
	return host === apex || host.endsWith('.' + apex);
}

/**
 * Classify a candidate's ownership relative to a seed domain.
 *
 * Precedence (design doc §4 P2, corrected per §3.3, and per Ruling A
 * 2026-07-27 task-7c — see the OWNERSHIP RULE note on
 * `ClassifyOwnershipInput`'s candidate-side fields):
 *  1. Non-registered / registration-unknown → `unattributed` (attribution is moot).
 *     RegistrationState is a discriminated union: only the `registered` arm
 *     carries an `ns` field at all, so an in-bailiwick match is structurally
 *     unreachable for `unregistered`/`unknown` (Ruling B) — this precedence
 *     step returns before `registration.ns` is ever read.
 *  2. NS in-bailiwick to the seed apex → `owned_by_seed`, strong. Because
 *     `registration.ns` is only ever populated from an ACTUALLY-RESOLVED NS
 *     answer set (see `resolveRegistrationUncached()` in
 *     `./registration-state`), a lame delegation — attacker sets NS =
 *     `ns1.bnz.co.nz` in the candidate's own parent-zone delegation, but the
 *     seed's server never actually serves that zone — SERVFAILs at
 *     resolution and never reaches this arm with a matching host (Ruling B:
 *     "in-bailiwick NS requires resolution evidence").
 *  3. NS set match on hosts NOT flagged shared, >=50% AND >=2 shared → `owned_by_seed`, strong.
 *  4. Complete (100%) NS set match where every shared host is on a SHARED provider → `owned_by_seed`, medium.
 *  5. Partial overlap confined to shared-provider hosts → not evidence (falls through silently —
 *     this is the ANZ/Westpac 1/6-Akamai trap: a single shared-provider NS host in common is
 *     operational plumbing, not ownership evidence).
 *  6. Registered with its own resolvable NS, no ownership signal → `third_party`.
 *  7. Everything else (no NS info at all) → `unattributed`.
 *
 * `soaInBailiwick` / `spfIncludesSeedApex` / `httpRedirectToSeedApex`
 * (Ruling A) are candidate-side, attacker-influenceable signals and play NO
 * role in this precedence table — they can never independently (or combined)
 * produce `owned_by_seed`; see the OWNERSHIP RULE note on
 * `ClassifyOwnershipInput` for what a future caller may use them for.
 */
export function classifyOwnership(input: ClassifyOwnershipInput): OwnershipAssessment {
	const { registration, candidateDomain } = input;

	if (registration.state === 'unregistered') {
		return {
			verdict: 'unattributed',
			strength: 'none',
			signals: [],
			rationale: `${candidateDomain} is not registered — there is nothing to attribute.`,
		};
	}
	if (registration.state === 'unknown') {
		// Amendment (3): render the human-readable phrase from
		// UNKNOWN_REASON_PHRASES, never the raw UnknownReason token — internal
		// enum values like 'empty_noerror' are meaningless in a customer-facing
		// report about a named organisation.
		return {
			verdict: 'unattributed',
			strength: 'none',
			signals: [],
			rationale: `${candidateDomain}'s registration status could not be determined — ${UNKNOWN_REASON_PHRASES[registration.reason]}.`,
		};
	}

	const normalisedSeedDomain = normHost(input.seedDomain);
	const seedApex = getRegistrableDomain(normalisedSeedDomain) ?? normalisedSeedDomain;
	const candidateNs = registration.ns.map(normHost).filter(Boolean);
	const seedNs = input.seedNs.map(normHost).filter(Boolean);

	const inBailiwickNs = candidateNs.filter((ns) => isInBailiwick(ns, seedApex));
	if (inBailiwickNs.length > 0) {
		return {
			verdict: 'owned_by_seed',
			strength: 'strong',
			signals: ['ns_in_bailiwick'],
			rationale: `${candidateDomain}'s nameserver(s) ${inBailiwickNs.join(', ')} are delegated under ${seedApex}.`,
		};
	}

	// Ruling A (2026-07-27, task-7c): soaInBailiwick / spfIncludesSeedApex /
	// httpRedirectToSeedApex are candidate-side, attacker-influenceable
	// signals (see the OWNERSHIP RULE note on `ClassifyOwnershipInput`) and
	// are DELIBERATELY not consulted here — they can never independently (or
	// combined) establish `owned_by_seed`. Only seed-side signals (this arm
	// and the two below) may do that.

	const sharedNs = candidateNs.filter((ns) => seedNs.includes(ns));
	const dedicatedShared = sharedNs.filter((ns) => !input.isSharedNsHost(ns));
	const seedTotal = seedNs.length;

	if (
		seedTotal > 0 &&
		dedicatedShared.length >= DEDICATED_NS_MATCH_MIN_COUNT &&
		dedicatedShared.length / seedTotal >= DEDICATED_NS_MATCH_RATIO
	) {
		return {
			verdict: 'owned_by_seed',
			strength: 'strong',
			signals: ['ns_set_match'],
			rationale: `${candidateDomain} shares ${dedicatedShared.length}/${seedTotal} dedicated nameservers with ${seedApex}.`,
		};
	}

	if (seedTotal > 0 && sharedNs.length === seedTotal && sharedNs.every((ns) => input.isSharedNsHost(ns))) {
		return {
			verdict: 'owned_by_seed',
			strength: 'medium',
			signals: ['ns_shared_provider_complete'],
			rationale: `${candidateDomain} matches the complete ${seedTotal}/${seedTotal} nameserver set on a shared provider. A full match is evidence; a partial match on the same provider would not be.`,
		};
	}

	if (candidateNs.length > 0) {
		return {
			verdict: 'third_party',
			strength: 'none',
			signals: ['distinct_infrastructure'],
			rationale: `${candidateDomain} is registered with its own nameservers, distinct from ${seedApex} — no ownership signal links it to this organisation.`,
		};
	}

	return {
		verdict: 'unattributed',
		strength: 'none',
		signals: [],
		rationale: `No ownership or third-party signal could be established for ${candidateDomain}.`,
	};
}

/** {@link attributionConfidence} return type — deliberately not a boolean; see its JSDoc for why. */
export type AttributionConfidence = 'corroborated' | 'uncorroborated';

/**
 * D4 WORDING/CONFIDENCE classifier: does a non-owned candidate's brand-label
 * match meet the bar to be worded with full confidence in a report, versus
 * hedged/neutral wording? THIS FUNCTION MUST NEVER BE CONSULTED FOR
 * SEVERITY — that is `capAttributionSeverity()`'s job, and it takes
 * `verdict` alone. (Renamed from `passesAttributionGuard()` in fix round 1:
 * the original boolean-returning name/shape invited exactly the misuse this
 * rename and the `'corroborated' | 'uncorroborated'` return type resist —
 * see F3 in the fix-round report.)
 *
 * `owned_by_seed` is always `'corroborated'` — it is the strongest available
 * corroborating brand signal by construction. Any other verdict needs
 * EITHER a brand label at least `MIN_ATTRIBUTION_LABEL_LENGTH` characters
 * long, OR an explicit corroborating signal supplied by the caller
 * (MX/SPF overlap with the primary domain is the one wired in this slice —
 * cert-SAN and page-content corroboration are not, since neither tool
 * fetches them today). Below the threshold with no corroboration, a short
 * brand label (e.g. `bnz`, 3 characters) collides with too much unrelated
 * global DNS for a bare label match to mean anything on its own — see spec
 * §5 D4. This is a WORDING signal only: whatever it returns, the finding is
 * still emitted, at the severity `capAttributionSeverity()` computed.
 */
export function attributionConfidence(verdict: OwnershipVerdict, brandLabel: string, corroborated: boolean): AttributionConfidence {
	if (verdict === 'owned_by_seed') return 'corroborated';
	return brandLabel.length >= MIN_ATTRIBUTION_LABEL_LENGTH || corroborated ? 'corroborated' : 'uncorroborated';
}

/**
 * THE single exported severity-decision surface (fix-round F1/F3). Every
 * non-owned candidate is capped at `'info'` — full stop, regardless of
 * brand-label length or corroboration. Those factors govern report WORDING
 * only, via `attributionConfidence()` above; they must never move the
 * severity ceiling. `owned_by_seed` is the only verdict exempt.
 *
 * DEMOTE, NEVER DELETE: this type has no falsy / null / undefined member,
 * so there is no value a caller could mistake for "omit this finding" —
 * every return is a concrete instruction to either leave the computed
 * severity alone (`'unbounded'`) or clamp it (`'info'`). The finding itself
 * is ALWAYS emitted by the caller; only its severity and wording change.
 *
 * Per the load-bearing safety property (controller amendment 2), `third_party`
 * and `unattributed` are capped identically — only `owned_by_seed` is ever
 * exempt.
 */
export function capAttributionSeverity(verdict: OwnershipVerdict): Severity | 'unbounded' {
	return verdict === 'owned_by_seed' ? 'unbounded' : 'info';
}

/**
 * Metadata shape every ownership-gated finding carries, owned or not.
 * Extracted (fix round 2, F1) after `check-lookalikes.ts` and
 * `check-shadow-domains.ts` each hand-built this same four-field object and
 * drifted apart within a single slice — see {@link buildNonOwnedGateFinding}.
 */
export function buildOwnershipGateMetadata(
	finding: Finding,
	ownership: OwnershipAssessment,
	confidence: AttributionConfidence,
): Record<string, unknown> {
	return {
		...finding.metadata,
		ownershipVerdict: ownership.verdict,
		ownershipRationale: ownership.rationale,
		attributionConfidence: confidence,
		severityCappedBy: 'ownership_attribution',
	};
}

/**
 * Per-tool knobs for {@link buildNonOwnedGateFinding}. Everything ELSE about
 * the neutral non-owned rewrite — the title template, the hedge sentence,
 * the metadata shape — is shared and must stay byte-identical across
 * callers; these three fields are the only legitimate axis of variation.
 */
export interface NonOwnedGateOptions {
	/** Check category the rewritten finding belongs to (e.g. `'lookalikes'`, `'shadow_domains'`). */
	category: CheckCategory;
	/** `finding.metadata` key that carries this finding's own domain/variant string. */
	domainMetadataKey: string;
	/**
	 * Noun phrase describing what's being reported on (e.g. `'DNS/mail
	 * posture'`). Callers MUST pass the same value so the hedge sentence
	 * reads identically regardless of which tool emitted it — see F1
	 * (2026-07-27 fix round 2): `check-lookalikes.ts` and
	 * `check-shadow-domains.ts` had already drifted to `'DNS/mail posture'`
	 * vs `'mail posture'` within a single slice before this was noticed.
	 */
	postureNoun: string;
}

/**
 * Build the shared neutral, severity-capped finding for a NON-OWNED
 * (`third_party`/`unattributed`) candidate whose raw calibrated severity was
 * ABOVE `info`. THE single place that sentence and its metadata shape are
 * assembled — `check-lookalikes.ts` and `check-shadow-domains.ts` each used
 * to hand-roll their own copy of this text and had already drifted apart
 * (F1, fix round 2): `check-lookalikes.ts` said "Its DNS/mail posture" and
 * never quoted the brand label, `check-shadow-domains.ts` said "Its mail
 * posture" and quoted `"${brand}"`. Both tools now call this function with
 * the same `postureNoun`, so they emit byte-identical wording for the same
 * verdict — verified by `test/ownership-attribution.spec.ts`'s cross-tool
 * parity test.
 *
 * Callers are responsible for the `ceiling === 'unbounded'` passthrough (an
 * `owned_by_seed` finding is returned unchanged, never routed here) and, for
 * tools whose raw finding CAN be `'info'`-severity already (unlike
 * `check-lookalikes.ts`, where `calibrateLookalikeSeverity()` never returns
 * `'info'`), for their own local info-severity branch — see
 * `check-shadow-domains.ts`'s `NEUTRAL_INFO_TITLES` handling, which stays
 * tool-local by design (only the shared sentence and metadata shape moved
 * here, per the fix-round instruction).
 */
export function buildNonOwnedGateFinding(
	finding: Finding,
	ownership: OwnershipAssessment,
	brand: string,
	corroborated: boolean,
	ceiling: Severity,
	options: NonOwnedGateOptions,
): Finding {
	const confidence = attributionConfidence(ownership.verdict, brand, corroborated);
	const domainValue = finding.metadata?.[options.domainMetadataKey];
	const domain = typeof domainValue === 'string' ? domainValue : 'This domain';
	const metadata = buildOwnershipGateMetadata(finding, ownership, confidence);

	const relation =
		ownership.verdict === 'third_party'
			? 'is registered to a different organisation'
			: 'could not be attributed to the scanned organisation';
	const hedge =
		confidence === 'uncorroborated'
			? ` The shared label is under ${MIN_ATTRIBUTION_LABEL_LENGTH} characters and nothing else corroborates a link, so the name similarity alone means little.`
			: '';
	return createFinding(
		options.category,
		`Unrelated domain, confusable label: ${domain}`,
		ceiling,
		`${domain} shares the "${brand}" label with the scanned domain but ${relation}. ${ownership.rationale} Its ${options.postureNoun} is reported for awareness only: no action by the scanned organisation is implied, and this finding asserts no control over ${domain}.${hedge}`,
		metadata,
	);
}
