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
 * AMENDMENT — SEED-AUTHORISED CONVERGENCE (2026-09-04, #864, regression of
 * #263; reworked after PR #897 review). Ruling A's seed-side-only rule has a
 * blind spot #864 measured live: a same-entity domain on a DIFFERENT DNS
 * platform (`amazon.com` on Route 53, `amazon.com.au` on Amazon's internal
 * `amzndns.*`) shares no nameserver with the seed, and the #263 RDAP
 * registrant tier is structurally blind for the pair — Verisign's `.com`
 * RDAP is thin and auDA's `.com.au` RDAP publishes no registrant entity
 * (observed 2026-09-04). So the candidate was counted as an impersonation-
 * capable third party.
 *
 * Ruling A is NOT weakened: the verdict below still rests on a record ONLY
 * THE SEED CAN PUBLISH. The candidate-side half is a cheap PRE-FILTER, never
 * evidence. The two halves of `assessSeedAuthorisedConvergence()`:
 *
 *   1. PRE-FILTER (candidate-side, attacker-free, zero cost): every real MX
 *      exchange of the candidate sits inside the seed apex. Copying the
 *      seed's MX string is free for a SENDING squatter — a phishing sender
 *      never wanted the receive channel — so this half carries NO weight; it
 *      only decides which candidates are worth the seed-side lookups.
 *   2. VERDICT (seed-side): the candidate's DMARC record sends aggregate/
 *      forensic reports to a mailbox whose domain sits inside the seed apex,
 *      AND the seed has published the RFC 7489 §7.1 external-destination
 *      authorisation `<candidate>._report._dmarc.<receiver-domain>` TXT
 *      `v=DMARC1`. The DMARC record itself is candidate-published (free to
 *      forge); the authorisation record lives in the RECEIVER's zone, under
 *      the seed apex, and only its owner can publish it — a squatter cannot.
 *      A wildcard grant (`*._report._dmarc.<receiver>`, detected with a
 *      canary label) is a seed choice to accept reports about ANY domain, so
 *      it is evidence-only, never verdict-bearing.
 *
 * Live (DoH, 2026-09-04): `_dmarc.amazon.com.au` → CNAME `_dmarc.amazon.com`,
 * `rua=mailto:report<at>dmarc.amazon.com` (mailbox spelled out to keep the
 * secret scanner quiet); `amazon.com.au._report._dmarc.dmarc.
 * amazon.com` TXT `v=DMARC1` EXISTS; a random label under the same
 * `_report._dmarc` is NXDOMAIN (not a wildcard) and `amzndns.com` — which
 * reports to the same mailbox — has NO such record: a per-domain grant.
 *
 * REJECTED on the same live records: SOA MNAME (unverified free text in a
 * self-hosted zone — the first #897 revision used it and was correctly
 * blocked), SOA RNAME (Route 53 templates `awsdns-hostmaster.amazon.com` into
 * every tenant zone), the NS-platform chain (`amzndns.com` and public
 * `awsdns-33.com` carry the same RNAME), seed SPF (`spf1/2/3.amazon.com` name
 * no candidate), CT SAN overlap (0 of 3300 crt.sh certs cover both apexes),
 * SPF `include:` / HTTP redirect (free-text, deleted 2026-07-27).
 *
 * Residual, stated not hidden: a seed that is itself a DMARC report-
 * processing PROVIDER (Agari/Valimail-shaped) publishes authorisation records
 * for every customer, so a customer whose MX also sits inside that seed's
 * apex would attribute — the same provider-class residual the NS
 * in-bailiwick arm already carries for DNS providers. Strength is `medium`
 * and `evidence[]` names every record so a consumer can audit the match.
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
	| 'dmarc_report_authorised_by_seed'
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

/** One observed record backing (or, for the pre-filter, accompanying) an ownership assessment (#864). */
export interface OwnershipEvidence {
	/**
	 * Which record the value came from. `MX` is the candidate-side PRE-FILTER
	 * (never verdict-bearing — see file header); `DMARC.RUA` is the
	 * candidate-published report destination; `DMARC.REPORT_AUTHORISATION` is
	 * the SEED-published RFC 7489 §7.1 grant the verdict rests on.
	 */
	record: 'MX' | 'DMARC.RUA' | 'DMARC.REPORT_AUTHORISATION';
	/** The observed host / record name (lowercased, trailing dot stripped). */
	value: string;
	/** True when the host sits at or under the seed apex. */
	inSeedBailiwick: boolean;
}

/**
 * Outcome of the seed-side DMARC external-report authorisation probe (#864;
 * `probeDmarcReportAuthorisation()` in `src/tools/lookalike-dns.ts`).
 *
 *  - `authorised` — a receiver domain under the seed apex publishes a
 *    per-domain `<candidate>._report._dmarc.<receiver>` `v=DMARC1` record.
 *  - `wildcard` — the receiver answers `v=DMARC1` for a random label too, so
 *    the grant is not specific to this candidate (evidence-only).
 *  - `not_authorised` — the candidate reports into the seed apex but no grant
 *    exists (measured absence).
 *  - `no_seed_receiver` — the candidate's DMARC reports go nowhere inside the
 *    seed apex (or it has no DMARC record).
 *  - `candidate_unresolved` — the CANDIDATE-zone lookup (`_dmarc.<candidate>`)
 *    rejected. That zone is 100% attacker-controlled, so a failure there is a
 *    DECLINE, never a measurement gap: a squatter who blackholes its own
 *    `_dmarc` must not do better than one that publishes nothing (PR #897
 *    re-review, High). Falls through to the seed-side NS outcome with the
 *    threat observation retained.
 *  - `unresolved` — a SEED-zone lookup (the grant or its canary) REJECTED;
 *    nothing was measured on the only side that carries weight.
 */
export interface DmarcReportAuthorisation {
	status: 'authorised' | 'wildcard' | 'not_authorised' | 'no_seed_receiver' | 'candidate_unresolved' | 'unresolved';
	/** Report mailboxes (domain part) the candidate's DMARC record names inside the seed apex. */
	seedReceivers: string[];
	/** The receiver whose authorisation record matched (`authorised` / `wildcard` only). */
	receiverDomain?: string;
	/** The authorisation record NAME that answered `v=DMARC1` (`authorised` only). */
	authorisationRecord?: string;
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
	 * PRE-FILTER ONLY: copying the seed's MX is free for a sending squatter,
	 * so this never carries weight; it gates whether the seed-side probe in
	 * {@link dmarcReportAuthorisation} is worth issuing. See the file header.
	 */
	candidateMx?: readonly string[];
	/**
	 * #864 — the SEED-SIDE half: result of the DMARC external-report
	 * authorisation probe. `undefined` = not probed. The verdict rests on
	 * `status === 'authorised'` alone; `'unresolved'` (a SEED-zone lookup
	 * rejected) with the MX pre-filter met yields `unmeasured` (#832's law);
	 * every other status — including `'candidate_unresolved'`, the
	 * attacker-controlled `_dmarc.<candidate>` lookup failing — falls through
	 * to the seed-side NS outcome.
	 */
	dmarcReportAuthorisation?: DmarcReportAuthorisation;
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
	 * RE-DERIVED 2026-09-04 (#864): `candidateMx` above is a candidate-side
	 * field again — but it is a PRE-FILTER with no verdict weight, and the
	 * verdict it gates (`dmarcReportAuthorisation`) is a SEED-published record
	 * (RFC 7489 §7.1), which is exactly the seed-side control this rule
	 * demands. Consulted after every seed-side NS arm. SPF `include:`, HTTP
	 * redirect and SOA MNAME/RNAME remain excluded: all are free-text
	 * declarations a self-hosted zone can publish at no cost.
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
 *  5b. (#864) SEED-AUTHORISED convergence — pre-filter: every real MX exchange inside the seed
 *     apex (attacker-free, no weight); verdict: the seed publishes the RFC 7489 §7.1 DMARC
 *     report authorisation `<candidate>._report._dmarc.<receiver-under-seed>` → `owned_by_seed`,
 *     medium, with `evidence`. Requires the caller to have supplied `candidateMx` +
 *     `dmarcReportAuthorisation`. A wildcard grant is evidence-only. If the pre-filter holds but
 *     the seed-side probe REJECTED, the verdict is `unmeasured`, not `third_party`.
 *  6. Registered with its own resolvable NS, no ownership signal → `third_party`.
 *  7. Everything else (no NS info at all) → `unattributed`.
 *
 * The #864 inputs (`candidateMx`, `dmarcReportAuthorisation`) are consulted
 * ONLY at step 5b, strictly after every seed-side NS arm; the verdict there
 * rests on the seed-published authorisation record alone. SPF `include:`,
 * HTTP redirect and SOA fields remain excluded (see the OWNERSHIP RULE note
 * on `ClassifyOwnershipInput`).
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

	// #864 — the seed-authorised convergence arm needs only the seed APEX (like
	// the NS in-bailiwick arm above), so it is computed here and may still yield
	// a positive verdict under a degraded seed NS lookup; it is APPLIED only
	// after the seed-side set-comparison arms below, which keep precedence.
	const convergence = assessSeedAuthorisedConvergence(input, candidateDomain, seedApex);

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

	// #864 — step 5b. Applied only once every seed-side NS arm has declined, so
	// a strong NS match is never displaced by this medium-strength verdict. Also
	// carries the `unmeasured` outcome for an asked-but-unanswered seed probe.
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
 * exchange sits at or under the seed apex (#864). This is the PRE-FILTER for
 * step 5b and nothing more: a sending squatter can publish `MX 10 <seed's
 * MX>` in a self-hosted zone for free and forfeits nothing it wanted, so the
 * predicate carries no verdict weight. It exists so the seed-side probe is
 * issued only for candidates that already look like the seed's own mail
 * estate — a clean scan pays nothing.
 *
 * A single exchange OUTSIDE the seed apex disqualifies the set (a squatter
 * listing the seed's MX alongside its own is not shaped like a same-entity
 * domain at all).
 */
export function mxRoutedIntoSeed(candidateMx: readonly string[] | undefined, seedDomain: string): boolean {
	if (!candidateMx || candidateMx.length === 0) return false;
	const normalisedSeed = normHost(seedDomain);
	const seedApex = getRegistrableDomain(normalisedSeed) ?? normalisedSeed;
	return candidateMx.every((mx) => isInBailiwick(mx, seedApex));
}

/**
 * Extract the domain part of every `rua=` / `ruf=` `mailto:` destination in a
 * DMARC record (RFC 7489 §6.3), lowercased, deduplicated, in order of first
 * appearance. Size suffixes (`!10m`) and non-mailto URIs are dropped. Pure;
 * exported for direct unit testing and for `probeDmarcReportAuthorisation()`.
 */
export function parseDmarcReportReceivers(dmarcRecord: string): string[] {
	const out: string[] = [];
	for (const rawTag of dmarcRecord.split(';')) {
		const eq = rawTag.indexOf('=');
		if (eq === -1) continue;
		const key = rawTag.slice(0, eq).trim().toLowerCase();
		if (key !== 'rua' && key !== 'ruf') continue;
		for (const uri of rawTag.slice(eq + 1).split(',')) {
			const trimmed = uri.trim();
			if (!/^mailto:/i.test(trimmed)) continue;
			const mailbox = trimmed.slice('mailto:'.length).split('!')[0];
			const at = mailbox.lastIndexOf('@');
			if (at === -1) continue;
			const domain = normHost(mailbox.slice(at + 1));
			if (domain && !out.includes(domain)) out.push(domain);
		}
	}
	return out;
}

/**
 * Registrable apexes of DMARC report-PROCESSING services — organisations that
 * publish the RFC 7489 §7.1 `<domain>._report._dmarc.<receiver>` grant for
 * EVERY customer domain as a matter of business, so a grant under one of
 * these apexes says "customer", never "same owner". When the SEED apex is one
 * of these, step 5b declines (evidence-only) — the same defence
 * `SHARED_NS_APEXES` / `isSharedNsHost` gives the NS arms. Consulted for the
 * seed apex only, so an entry here can only ever WITHHOLD an attribution.
 * Add conservatively; a missing processor merely leaves the provider-class
 * residual documented in the file header.
 */
export const DMARC_REPORT_PROCESSOR_APEXES: ReadonlySet<string> = new Set([
	'agari.com',
	'valimail.com',
	'dmarcian.com',
	'ondmarc.com',
	'redsift.com',
	'proofpoint.com',
	'dmarcanalyzer.com',
	'mimecast.com',
	'easydmarc.com',
	'powerdmarc.com',
	'dmarcly.com',
	'sendmarc.com',
	'fraudmarc.com',
	'uriports.com',
	'mailhardener.com',
	'postmarkapp.com',
	'mxtoolbox.com',
	'dmarcdigests.com',
]);

/** True when `apex` (already a registrable domain) is a known DMARC report-processing service — see {@link DMARC_REPORT_PROCESSOR_APEXES}. */
export function isDmarcReportProcessorApex(apex: string): boolean {
	const host = normHost(apex);
	if (!host) return false;
	return DMARC_REPORT_PROCESSOR_APEXES.has(getRegistrableDomain(host) ?? host);
}

/**
 * Step 5b of `classifyOwnership()` — the #864 seed-authorised convergence
 * arm. Returns `null` when the arm has nothing to say (pre-filter unmet,
 * inputs absent, or no seed-published grant), an `owned_by_seed` assessment
 * when the seed has published the per-domain RFC 7489 §7.1 authorisation, or
 * an `unmeasured` assessment when the pre-filter held but the seed-side probe
 * rejected. Never returns `third_party`: declining is the caller's job, from
 * seed-side NS evidence.
 */
function assessSeedAuthorisedConvergence(
	input: ClassifyOwnershipInput,
	candidateDomain: string,
	seedApex: string,
): OwnershipAssessment | null {
	if (!mxRoutedIntoSeed(input.candidateMx, seedApex)) return null;
	const auth = input.dmarcReportAuthorisation;
	if (auth === undefined) return null;
	// A seed that is itself a DMARC report PROCESSOR publishes the §7.1 grant
	// for every customer, so the grant carries no ownership information there
	// (mirrors `isSharedNsHost` for the NS arms). Evidence-only: decline.
	if (isDmarcReportProcessorApex(seedApex)) return null;

	const mx = (input.candidateMx ?? []).map(normHost).filter(Boolean);
	const mxEvidence: OwnershipEvidence[] = mx.map((value) => ({ record: 'MX' as const, value, inSeedBailiwick: true }));

	// ONLY a SEED-zone lookup failure is a measurement gap. `candidate_unresolved`
	// (the attacker-controlled `_dmarc.<candidate>` lookup rejected) falls
	// through below with every other non-grant status — see the status docs.
	if (auth.status === 'unresolved') {
		return {
			verdict: 'unmeasured',
			strength: 'none',
			signals: ['mx_in_bailiwick'],
			rationale: `${candidateDomain} routes its mail to ${mx.join(', ')} inside ${seedApex}, but the lookup that would show whether ${seedApex} has authorised DMARC reporting for it did not resolve this run. This is a measurement gap, not evidence of third-party registration — re-run to attribute.`,
			evidence: mxEvidence,
		};
	}
	if (auth.status !== 'authorised' || !auth.receiverDomain || !auth.authorisationRecord) return null;

	const receiver = normHost(auth.receiverDomain);
	const record = normHost(auth.authorisationRecord);
	// Defence in depth: the probe already filtered receivers to the seed apex,
	// but the verdict must never rest on a grant published OUTSIDE it.
	if (!isInBailiwick(receiver, seedApex) || !isInBailiwick(record, seedApex)) return null;

	return {
		verdict: 'owned_by_seed',
		strength: 'medium',
		signals: ['mx_in_bailiwick', 'dmarc_report_authorised_by_seed'],
		rationale: `${seedApex} has published a DMARC external-report authorisation for ${candidateDomain} (${record} = v=DMARC1, RFC 7489 §7.1) — a record only the owner of ${receiver} can create — and ${candidateDomain} routes its mail to ${mx.join(', ')} inside ${seedApex}.`,
		evidence: [
			...mxEvidence,
			{ record: 'DMARC.RUA', value: receiver, inSeedBailiwick: true },
			{ record: 'DMARC.REPORT_AUTHORISATION', value: record, inSeedBailiwick: true },
		],
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
