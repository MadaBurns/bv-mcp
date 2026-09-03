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
 * Ruling A — the candidate-side signals (formerly `soaInBailiwick`,
 * `spfIncludesSeedApex`, `httpRedirectToSeedApex` on `ClassifyOwnershipInput`)
 * are attacker-influenceable and NEVER independently verdict-bearing. Ruling B
 * — an in-bailiwick NS observation is ownership-bearing only when it comes
 * from an actually-resolved NS answer set; see `classifyOwnership()`'s
 * precedence-table JSDoc and `resolveRegistrationUncached()` in
 * `./registration-state`.
 *
 * OWNERSHIP-ATTRIBUTION FOLLOWUPS, ITEM 2 (2026-07-27, "delete them" ruling):
 * the three candidate-side fields above were accepted on
 * `ClassifyOwnershipInput` but never read anywhere in `classifyOwnership()`'s
 * body — no caller ever populated them either (`check-lookalikes.ts` and
 * `check-shadow-domains.ts` only ever pass `seedNs`/`candidateNs`-derived
 * `registration`). Ruling A's "never verdict-bearing" rule made them
 * permanently inert; keeping accept-but-ignore fields that are themselves
 * attacker-influenceable is a pure footgun (a future caller could wire a real
 * probe expecting them to matter and never notice they're silently ignored,
 * or a "cleanup" could accidentally start reading them). DELETED rather than
 * left present-but-unused — see the `OWNERSHIP RULE` note on
 * `ClassifyOwnershipInput` below for the rule a future author re-wiring a
 * real SOA/SPF/redirect probe must re-derive.
 *
 * AMENDMENT — IN-BAILIWICK CONVERGENCE (2026-09-04, #864, regression of
 * #263). Ruling A's seed-side-only rule has an irreducible blind spot that
 * #864 measured live: a same-entity domain on a DIFFERENT DNS platform
 * (`amazon.com` on Route 53, `amazon.com.au` on Amazon's internal
 * `amzndns.*`) shares no nameserver with the seed, and the #263 RDAP
 * registrant tier is structurally blind for the pair — Verisign's `.com`
 * RDAP is thin (registrar only) and auDA's `.com.au` RDAP publishes no
 * registrant entity at all (observed 2026-09-04). No seed-side signal exists,
 * so the candidate was counted as an impersonation-capable third party.
 *
 * What IS observable (DoH, 2026-09-04): `amazon.com.au` MX →
 * `amazon-smtp.amazon.com` (the seed's own MX host) and SOA MNAME →
 * `dns-external-master.amazon.com` (its zone is mastered on a host inside the
 * seed's zone). Both are candidate-zone records, so Ruling A's "never alone"
 * clause stands unchanged — but its "never combined" clause is amended for
 * exactly ONE bounded conjunction, `assessBailiwickConvergence()` below:
 *
 *   MX (every real exchange inside the seed apex) AND SOA MNAME (inside the
 *   seed apex) → `owned_by_seed`, strength `medium`, evidence attached.
 *
 * Why this conjunction and not others (spoofing analysis):
 *   - MX alone is one attacker-written record and never qualifies (a squatter
 *     can copy the seed's MX string in seconds — pinned by a negative fixture).
 *   - SOA RNAME is NEVER verdict-bearing: managed providers template it, and
 *     for a seed that is itself a DNS operator the template lands inside the
 *     seed apex — every Route 53 zone carries RNAME
 *     `awsdns-hostmaster.amazon.com`, so a Route 53 squatter of amazon.com
 *     would otherwise qualify. It is recorded as evidence prose only.
 *   - SOA MNAME on a managed provider is always a PROVIDER host (Route 53 →
 *     `ns-*.awsdns-*`, Cloudflare → `*.ns.cloudflare.com`, Akamai →
 *     `a*.akam.net`), never inside an unrelated seed's apex, and managed
 *     providers do not let a tenant edit it. Placing MNAME inside the seed
 *     apex therefore requires the squatter to self-host authoritative DNS
 *     (or a rare provider that exposes MNAME) — AND to route the lookalike's
 *     inbound mail to the seed's own servers, forfeiting the receive channel.
 *   - Two record types, two different operational dependencies, both pointed
 *     INTO the seed's zone: the same "complete match, not partial" bar the
 *     `ns_shared_provider_complete` arm already accepts at `medium`.
 *
 * Residual (documented, not hidden): a squatter who self-hosts DNS with a
 * forged MNAME and sacrifices inbound mail can still earn the verdict; the
 * verdict is `medium`, names both records in `evidence`, and the finding
 * text quotes them so an analyst can see exactly what was matched. Seed-side
 * arms keep precedence — a strong NS match is never displaced by this one.
 */

import type { CheckCategory, Finding, Severity } from '@blackveil/dns-checks/scoring';
import { createFinding } from '@blackveil/dns-checks/scoring';
import { getRegistrableDomain } from './public-suffix';
import { UNKNOWN_REASON_PHRASES, type RegistrationState } from './registration-state';

/**
 * Final attribution verdict.
 *
 * `unmeasured` (#832) means the lookups feeding the ownership comparison were
 * DEGRADED — the seed's own NS set could not be fetched — so no comparison was
 * possible. It is NOT a claim about the candidate: a throttled run must never
 * publish the OPPOSITE attribution (`third_party`, "no ownership signal links
 * it…") for signals that were unfetched rather than absent. A definitive
 * `third_party` requires the same completeness bar `owned_by_seed` already
 * implies (the full-set comparison).
 */
export type OwnershipVerdict = 'owned_by_seed' | 'third_party' | 'unattributed' | 'unmeasured';

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
	| 'mx_in_bailiwick'
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
	/**
	 * The observed records a verdict rests on, when it rests on candidate-zone
	 * records (#864 in-bailiwick convergence). Absent for the seed-side NS arms,
	 * whose `rationale` already names the matched hosts. Surfaced verbatim in
	 * finding metadata so a consumer can audit what was matched.
	 */
	evidence?: OwnershipEvidence[];
}

/** One observed record backing an `owned_by_seed` verdict (#864). */
export interface OwnershipEvidence {
	/** Which record the value came from. `SOA.RNAME` is evidence prose only — never verdict-bearing (see file header). */
	record: 'MX' | 'SOA.MNAME' | 'SOA.RNAME';
	/** The observed host (lowercased, trailing dot stripped). */
	value: string;
	/** True when the host sits at or under the seed apex. */
	inSeedBailiwick: boolean;
}

/** SOA authority fields the #864 convergence arm consults. */
export interface SoaAuthority {
	/** Primary master nameserver (SOA MNAME). */
	mname: string;
	/** Responsible-party mailbox in domain-name form (SOA RNAME). */
	rname: string;
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
	 * True when the SEED's own NS lookup REJECTED (timeout / throttling), so
	 * `seedNs` is empty because it was UNFETCHED, not because the seed has no
	 * nameservers (#832). With this set, no set-comparison verdict is
	 * reachable: candidates that would otherwise fall through to the
	 * `third_party` arm come back `unmeasured` instead. The in-bailiwick arm
	 * still fires — it needs only the seed APEX, not the seed's NS answer, and
	 * a positive `owned_by_seed` from resolved candidate-side delegation
	 * evidence stays safe to publish.
	 */
	seedNsUnresolved?: boolean;
	/**
	 * #864 — the candidate's RESOLVED real MX exchange hosts (null-MX already
	 * excluded upstream). `undefined` = not probed; `[]` = probed, no mail.
	 * Consulted ONLY by the in-bailiwick convergence arm, and only in
	 * conjunction with {@link candidateSoa} — see the file-header amendment.
	 */
	candidateMx?: readonly string[];
	/**
	 * #864 — the candidate's SOA authority fields. `undefined` = not probed;
	 * `null` = probed and no SOA answered (or the probe rejected — then
	 * {@link candidateSoaUnresolved} says which).
	 */
	candidateSoa?: SoaAuthority | null;
	/**
	 * #864 — true when the candidate's SOA lookup REJECTED (timeout /
	 * throttling) rather than answering. With the MX precondition met, the
	 * convergence question was asked and not answered, so the verdict is
	 * `unmeasured` (#832's law) rather than the contrary `third_party`.
	 */
	candidateSoaUnresolved?: boolean;
	/**
	 * OWNERSHIP RULE — SEED-SIDE CONTROL ONLY (Ruling A, 2026-07-27 task-7c;
	 * fields DELETED 2026-07-27 ownership-attribution followups item 2 — see
	 * the file header "OWNERSHIP-ATTRIBUTION FOLLOWUPS, ITEM 2" note for why).
	 *
	 * `classifyOwnership()` verdicts require a SEED-side signal:
	 * `ns_in_bailiwick` / `ns_set_match` / `ns_shared_provider_complete` all
	 * require the CANDIDATE's own resolved NS records to actually nest under
	 * or match the SEED's — the seed's owner (or its DNS provider) is the one
	 * who put those records there.
	 *
	 * This input type used to also accept three CANDIDATE-side corroboration
	 * flags (`soaInBailiwick`, `spfIncludesSeedApex`, `httpRedirectToSeedApex`
	 * — SOA RNAME, SPF `include:` target, and HTTP redirect target,
	 * respectively). They were removed because they were dead: no caller ever
	 * populated them, and `classifyOwnership()` never read them. They were
	 * ALSO attacker-influenceable — an attacker who registers `evilbnz.co.nz`
	 * can unilaterally publish an SPF `include:` pointing at the seed apex, an
	 * HTTP redirect to it, or an in-bailiwick SOA RNAME, with NO cooperation
	 * from the seed's owner.
	 *
	 * A FUTURE AUTHOR wiring a real SOA/SPF/redirect probe MUST re-derive this
	 * rule, not rediscover the hole: any such candidate-side signal may only
	 * ever CORROBORATE — raise wording confidence via `attributionConfidence()`,
	 * or (if genuinely desired) raise `strength` on a verdict ALREADY earned
	 * by a seed-side signal — and must NEVER, alone or combined with any other
	 * candidate-side signal, be capable of producing `owned_by_seed` on its
	 * own. If reintroducing such fields, keep them optional inputs consulted
	 * strictly AFTER the seed-side precedence steps below decide the verdict.
	 *
	 * RE-DERIVED 2026-09-04 (#864): `candidateMx` + `candidateSoa` above are
	 * exactly such a reintroduction, bounded as the rule demands — optional,
	 * consulted after every seed-side arm, never verdict-bearing alone, and
	 * limited to the single MX ∧ SOA-MNAME conjunction whose spoofing cost is
	 * argued in the file header. SPF `include:` and HTTP redirect targets
	 * remain excluded: both are free-text declarations with no operational
	 * cost to forge.
	 */
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
 *  5b. (#864) In-bailiwick CONVERGENCE — every real MX exchange AND the SOA MNAME sit inside
 *     the seed apex → `owned_by_seed`, medium, with `evidence`. Requires the caller to have
 *     supplied `candidateMx` + `candidateSoa`; neither alone qualifies, and SOA RNAME never
 *     counts (see the file-header amendment for the spoofing analysis). If the MX precondition
 *     holds but the SOA lookup REJECTED, the verdict is `unmeasured`, not `third_party`.
 *  6. Registered with its own resolvable NS, no ownership signal → `third_party`.
 *  7. Everything else (no NS info at all) → `unattributed`.
 *
 * Candidate-side inputs (`candidateMx`, `candidateSoa`) are consulted ONLY at
 * step 5b, strictly after every seed-side arm, and only as the bounded
 * conjunction the 2026-09-04 amendment admits. SPF `include:` and HTTP
 * redirect targets remain excluded (deleted 2026-07-27, see the OWNERSHIP
 * RULE note on `ClassifyOwnershipInput`).
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

	// #864 — the in-bailiwick convergence arm needs only the seed APEX (like the
	// NS in-bailiwick arm above), so it is computed here and may still yield a
	// positive verdict under a degraded seed NS lookup; it is APPLIED only after
	// the seed-side set-comparison arms below, which keep precedence.
	const convergence = assessBailiwickConvergence(input, candidateDomain, seedApex);

	// #832 — degraded comparison inputs. The seed's NS lookup did not resolve,
	// so every arm below would be comparing against an UNFETCHED set: the
	// ns_set_match / shared-provider arms cannot fire (seedNs is empty), and
	// the third_party arm would publish "no ownership signal links it" about
	// signals nobody fetched — the exact non-answer-becomes-record defect this
	// verdict exists to prevent. Only the in-bailiwick arm above (which needs
	// the seed APEX, not its NS answer) may still produce a verdict.
	if (input.seedNsUnresolved) {
		if (convergence?.verdict === 'owned_by_seed') return convergence;
		return {
			verdict: 'unmeasured',
			strength: 'none',
			signals: [],
			rationale: `Ownership of ${candidateDomain} was not assessed in this run: the nameserver lookup for ${seedApex} did not resolve, so ${candidateDomain}'s nameservers could not be compared against it. This is a measurement gap, not evidence of third-party registration — re-run to attribute.`,
		};
	}

	// Ruling A (2026-07-27, task-7c): candidate-side declarations (SOA RNAME,
	// SPF include, HTTP redirect target — see the OWNERSHIP RULE note on
	// `ClassifyOwnershipInput`) are never consulted here, and no such inputs
	// even exist on this type any more (deleted 2026-07-27, ownership-
	// attribution followups item 2) — they can never independently (or
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

	// #864 — step 5b. Applied only once every seed-side arm has declined, so a
	// strong NS match is never displaced by this medium-strength verdict. Also
	// carries the `unmeasured` outcome for an asked-but-unanswered SOA probe.
	if (convergence !== null) return convergence;

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

/**
 * True when the candidate's RESOLVED real MX set is non-empty and EVERY
 * exchange sits at or under the seed apex — mail for the candidate is
 * delivered to the seed organisation's own mail hosts (#864). Exported so the
 * lookalike orchestrator can use the same predicate to gate the one extra SOA
 * lookup the convergence arm needs: the probe is issued only for candidates
 * that already satisfy this half, so a clean scan pays nothing.
 *
 * A single exchange OUTSIDE the seed apex disqualifies the whole set — a
 * squatter listing the seed's MX alongside their own would keep a working
 * receive channel, which is precisely what the conjunction is meant to cost.
 */
export function mxRoutedIntoSeed(candidateMx: readonly string[] | undefined, seedDomain: string): boolean {
	if (!candidateMx || candidateMx.length === 0) return false;
	const normalisedSeed = normHost(seedDomain);
	const seedApex = getRegistrableDomain(normalisedSeed) ?? normalisedSeed;
	return candidateMx.every((mx) => isInBailiwick(mx, seedApex));
}

/**
 * Step 5b of `classifyOwnership()` — the #864 in-bailiwick convergence arm.
 * Returns `null` when the arm has nothing to say (inputs absent, or the
 * conjunction unmet), an `owned_by_seed` assessment when BOTH halves hold, or
 * an `unmeasured` assessment when the MX half holds but the SOA probe was
 * asked and rejected. Never returns `third_party`: declining is the caller's
 * job, from seed-side evidence.
 */
function assessBailiwickConvergence(input: ClassifyOwnershipInput, candidateDomain: string, seedApex: string): OwnershipAssessment | null {
	if (!mxRoutedIntoSeed(input.candidateMx, seedApex)) return null;
	const mx = (input.candidateMx ?? []).map(normHost).filter(Boolean);

	if (input.candidateSoa === undefined) {
		// MX half holds but the caller never probed SOA: the arm cannot fire
		// (never on one attacker-written record) and it is not a measurement
		// gap either — nobody asked. Fall through to the seed-side outcome.
		return null;
	}
	if (input.candidateSoa === null) {
		if (input.candidateSoaUnresolved) {
			return {
				verdict: 'unmeasured',
				strength: 'none',
				signals: ['mx_in_bailiwick'],
				rationale: `${candidateDomain} routes its mail to ${mx.join(', ')} inside ${seedApex}, but its SOA lookup did not resolve this run, so whether its zone is also mastered inside ${seedApex} could not be assessed. This is a measurement gap, not evidence of third-party registration — re-run to attribute.`,
				evidence: mx.map((value) => ({ record: 'MX' as const, value, inSeedBailiwick: true })),
			};
		}
		return null;
	}

	const mname = normHost(input.candidateSoa.mname);
	const rname = normHost(input.candidateSoa.rname);
	if (!mname || !isInBailiwick(mname, seedApex)) return null;

	const evidence: OwnershipEvidence[] = [
		...mx.map((value) => ({ record: 'MX' as const, value, inSeedBailiwick: true })),
		{ record: 'SOA.MNAME', value: mname, inSeedBailiwick: true },
	];
	if (rname) evidence.push({ record: 'SOA.RNAME', value: rname, inSeedBailiwick: isInBailiwick(rname, seedApex) });

	return {
		verdict: 'owned_by_seed',
		strength: 'medium',
		signals: ['mx_in_bailiwick', 'soa_in_bailiwick'],
		rationale: `${candidateDomain} routes its mail to ${mx.join(', ')} and its zone is mastered on ${mname} — both inside ${seedApex}'s own infrastructure. Two distinct operational dependencies point into the seed's zone; either record alone would not qualify.`,
		evidence,
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
 * Per the load-bearing safety property (controller amendment 2), `third_party`,
 * `unattributed` and `unmeasured` are capped identically — only `owned_by_seed`
 * is ever exempt.
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
			: ownership.verdict === 'unmeasured'
				? 'could not be compared against the scanned organisation in this run — the lookups feeding the ownership comparison did not complete'
				: 'could not be attributed to the scanned organisation';
	const hedge =
		confidence === 'uncorroborated'
			? ` The shared label is under ${MIN_ATTRIBUTION_LABEL_LENGTH} characters and nothing else corroborates a link, so the name similarity alone means little.`
			: '';
	// #832: an `unmeasured` verdict must not be TITLED "Unrelated domain" — that
	// is the very third-party claim the degraded comparison failed to earn.
	const title =
		ownership.verdict === 'unmeasured'
			? `Confusable label, ownership unmeasured this run: ${domain}`
			: `Unrelated domain, confusable label: ${domain}`;
	return createFinding(
		options.category,
		title,
		ceiling,
		`${domain} shares the "${brand}" label with the scanned domain but ${relation}. ${ownership.rationale} Its ${options.postureNoun} is reported for awareness only: no action by the scanned organisation is implied, and this finding asserts no control over ${domain}.${hedge}`,
		metadata,
	);
}
