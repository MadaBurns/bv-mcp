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
 *
 * AMENDMENT — SHARED-PLATFORM NS PAIRS (2026-09-09, #929, the mirror image of
 * #263/#864). The seed-side NS arms assumed that any nameserver NOT on a
 * known shared provider is "dedicated", and that a COMPLETE match on a
 * shared provider is medium evidence. Both assumptions fail on a platform
 * that hands EVERY tenant the identical set: `net-agents.dk`, `net-agent.dk`
 * and `net-agents.com` all delegate to `ns01.one.com` / `ns02.one.com`
 * (one.com shared hosting, DoH 2026-09-09) and were attributed to each other
 * at `strong` / confidence 1.00 on `ns_set_match` — a test that would also
 * attribute every other one.com customer, and that a squatter satisfies by
 * hosting the lookalike at one.com (earning the `info` ceiling the D4 gate
 * reserves for the seed's own domains). Ruling A's bar applies to NS too: a
 * verdict rests only on what the SEED alone can publish, and a
 * platform-assigned NS set is not that.
 *
 * Fix: (1) one.com joins `SHARED_NS_APEXES`, so its hosts never count as
 * dedicated; (2) the complete-match arm (step 4) now requires the injected
 * `isPooledSharedNsHost` predicate to accept EVERY matched host — only a
 * provider that draws hostnames per zone from a large pool (Akamai) makes an
 * identical complete set per-account evidence. The predicate is optional and
 * DEFAULTS CLOSED (nothing is pooled): a caller that omits it can never
 * credit a platform. (3) An overlap confined to shared-provider hosts that
 * does not earn step 4 now carries the `ns_shared_platform` signal and a
 * rationale naming the platform hosts: identical whole sets on a non-pooled
 * platform → `unattributed` (nothing distinct was observed, so the report
 * must not say "registered to a different organisation" about what may be
 * the customer's own alias), any other platform-confined overlap →
 * `third_party`. Same `info` ceiling either way; step 5b (the seed-published
 * DMARC grant) keeps precedence. (4) The dedicated
 * arm's rationale no longer says "dedicated"; it says the hosts are on no
 * known shared-tenant provider, which is what was actually checked.
 */

import type { CheckCategory, Finding, Severity } from '@blackveil/dns-checks/scoring';
import { createFinding } from '@blackveil/dns-checks/scoring';
import { extractBrandName, getRegistrableDomain } from './public-suffix';
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
	| 'ns_shared_platform'
	| 'mx_in_bailiwick'
	| 'dmarc_report_authorised_by_seed'
	| 'seed_infrastructure_match'
	| 'seed_label_cohort'
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
	 * #929 — injected POOLED-shared-provider predicate (`isPooledSharedNsHost`
	 * from `src/tenants/discovery/shared-ns-hosts.ts`): true for a shared
	 * provider that assigns hostnames per zone from a pool large enough that
	 * an identical COMPLETE set implies one account (Akamai). Step 4 credits a
	 * complete shared-provider match ONLY when every matched host passes this.
	 * OPTIONAL and DEFAULTS CLOSED — absent, no shared provider is pooled and
	 * step 4 can never fire — so a caller that forgets it fails safe (no
	 * platform is credited), never open. Must imply `isSharedNsHost`.
	 */
	isPooledSharedNsHost?: (nsHost: string) => boolean;
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
	 * #974 — the candidate's RESOLVED A addresses, the seed's A addresses and the
	 * seed's MX exchange hosts. `undefined` / `[]` = not probed or nothing
	 * resolved; either way step 5c cannot fire (fails closed to the prior
	 * outcome). Candidate-published and free to copy, so these can only WITHHOLD
	 * a `third_party` claim (→ `unattributed`), never earn `owned_by_seed` — see
	 * {@link seedInfrastructureMatch}.
	 */
	candidateA?: readonly string[];
	seedA?: readonly string[];
	seedMx?: readonly string[];
	/**
	 * #974 (reopened) — the run's OTHER fully-measured candidates, for the step-5d
	 * exact-label cohort corroborator ({@link seedLabelCohortMatch}). The caller
	 * passes it only when the candidate's own A/MX probe completed, and leaves out
	 * members whose probe was degraded. `undefined` / `[]` = step 5d cannot fire.
	 * Like the step-5c inputs, it can only WITHHOLD a `third_party` claim.
	 */
	labelCohort?: readonly LabelCohortMember[];
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

/** One resolved candidate's measured record sets, as {@link seedLabelCohortMatch} compares them. */
export interface LabelCohortMember {
	domain: string;
	a: readonly string[];
	ns: readonly string[];
	/** Real MX exchange hosts; `[]` = measured, no mail. */
	mx: readonly string[];
}

/** Minimum matched exact-label siblings besides the candidate itself, so a cohort is 3+ variants (#974). */
export const MIN_LABEL_COHORT_SIBLINGS = 2;

/**
 * Minimum exact-label cohort size — siblings plus the candidate itself, all
 * on the seed's A set — at which step 5d waives its shared-NS exclusion
 * (#974 live: `ltmcguinness.{com,net,co,io,ai,nz}`, a 6-member brand-TLD set
 * hosted on `ns1/ns2.siteground.net`, a `SHARED_NS_APEXES` platform). Below
 * this size the #929 guard against forming a cohort out of unrelated tenants
 * of one shared platform stays in force — a small shared-NS "cohort" is
 * exactly the accidental grouping that guard exists to reject.
 */
export const SEED_LABEL_COHORT_SHARED_NS_MIN = 5;

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
 * True when `candidateDomain` is an EXACT-LABEL TLD variant of the seed: it is
 * itself a registrable domain, its brand label equals the seed's, and it is not
 * the seed's own apex (`anz.co.nz` / `xero.com.au` for seed `anz.com` / `xero.com`).
 *
 * THE SHAPE OF A REGIONAL ESTATE, AND ONE A SQUATTER DOES NOT BUY — the rule
 * step 5d ({@link seedLabelCohortMatch}) already relies on, extracted here
 * (SQ-36) so the pooled-platform arm of `classifyOwnership()` can apply the SAME
 * bar rather than a second, drifting copy. A character edit (`bnz.co.nz` for
 * `anz.com`, `ltmcguiness.com` for `ltmcguinness.co.nz`) is NOT the exact label,
 * and edited names are what squatters register — so this predicate separates
 * "the organisation's other TLD" from "a typosquat", without ever asserting
 * which of the two it is: it only decides which arms may look further.
 */
export function isExactLabelTldVariant(candidateDomain: string, seedDomain: string): boolean {
	const seed = normHost(seedDomain);
	const seedLabel = extractBrandName(seed);
	const seedApex = getRegistrableDomain(seed);
	if (!seedLabel || !seedApex) return false;
	const candidate = normHost(candidateDomain);
	return candidate !== seedApex && getRegistrableDomain(candidate) === candidate && extractBrandName(candidate) === seedLabel;
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
 *  4. Complete (100%) NS set match where every shared host is on a POOLED shared provider
 *     (`isPooledSharedNsHost`, #929 — Akamai; defaults closed) → `owned_by_seed`, medium.
 *  5. Any other overlap confined to shared-provider hosts → not evidence. A partial overlap is
 *     the ANZ/Westpac 1/6-Akamai trap (a single pooled host in common is operational plumbing);
 *     a complete match on a NON-pooled platform (one.com `ns01`/`ns02`, #929) is what every
 *     tenant of that platform looks like. Falls through to 5b; if 5b declines: the candidate's
 *     WHOLE set is platform hosts the seed uses → `unattributed` (nothing distinct observed),
 *     any other platform-confined overlap → `third_party` — both carrying `ns_shared_platform`.
 *     (SQ-36) The MIRROR of that whole-set case on a POOLED platform: the seed's whole set is on
 *     one pooled provider and every candidate host is either on that same provider or inside the
 *     candidate's OWN registrable domain. A pooled provider assigns hostnames per zone, so
 *     NON-identity there is the provider's doing, and a self-referential nameserver names no
 *     operator — nothing distinct was observed → `unattributed`, `ns_shared_platform`. Consulted
 *     before the arms above, and like them it can never yield `owned_by_seed`.
 *  5b. (#864) SEED-AUTHORISED convergence — pre-filter: every real MX exchange inside the seed
 *     apex (attacker-free, no weight); verdict: the seed publishes the RFC 7489 §7.1 DMARC
 *     report authorisation `<candidate>._report._dmarc.<receiver-under-seed>` → `owned_by_seed`,
 *     medium, with `evidence`. Requires the caller to have supplied `candidateMx` +
 *     `dmarcReportAuthorisation`. A wildcard grant is evidence-only. If the pre-filter holds but
 *     the seed-side probe REJECTED, the verdict is `unmeasured`, not `third_party`.
 *  5c. (#974) The candidate's A set AND real MX set are each identical to the seed's
 *     ({@link seedInfrastructureMatch}) → `unattributed` with `seed_infrastructure_match` —
 *     never `owned_by_seed` (candidate-published, copyable). Replaces only a `third_party` outcome
 *     (step 5's platform-partial arm, step 6); step 5's whole-platform `unattributed` is kept.
 *  5d. (#974 reopened) The candidate is an exact-label TLD variant on the seed's A set, and 2+ other
 *     exact-label variants share its identical A, NS and MX sets on non-platform NS — or, when the
 *     cohort has {@link SEED_LABEL_COHORT_SHARED_NS_MIN}+ members (siblings plus the candidate), on a
 *     shared-tenant platform NS too (#974 large-cohort exception) —
 *     ({@link seedLabelCohortMatch}) → `unattributed` with `seed_label_cohort`. Same posture as 5c,
 *     consulted only when 5c declined.
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
	// #929 — defaults CLOSED: with no predicate injected, no shared provider is
	// pooled and the complete-match arm below is unreachable.
	const isPooled = input.isPooledSharedNsHost ?? (() => false);

	if (
		seedTotal > 0 &&
		dedicatedShared.length >= DEDICATED_NS_MATCH_MIN_COUNT &&
		dedicatedShared.length / seedTotal >= DEDICATED_NS_MATCH_RATIO
	) {
		// #929 — "dedicated" was the old word here. What is actually checked is
		// that none of the matched hosts sits on a KNOWN shared-tenant provider;
		// say that, not more.
		return {
			verdict: 'owned_by_seed',
			strength: 'strong',
			signals: ['ns_set_match'],
			rationale: `${candidateDomain} shares ${dedicatedShared.length}/${seedTotal} nameservers with ${seedApex} (${dedicatedShared.join(', ')}), none on a known shared-tenant provider.`,
		};
	}

	// #1039 — step 3b: an EXACT nameserver-set match that MIXES dedicated and
	// shared-provider hosts, which fell between the two arms either side of it.
	// Step 3 above declines because the off-platform hosts are a minority of the
	// set (barclays.co.uk carries all nine of barclays.com's hosts, but only the
	// three `ns*.barcap.com` are on no known shared provider — 3/9 = 33%, under
	// `DEDICATED_NS_MATCH_RATIO`); step 4 below declines because its
	// every-matched-host-is-shared test is false on those same three. Control
	// then reached the distinct-infrastructure arm, which publishes "no
	// ownership signal links it" about a byte-identical set — literally false.
	//
	// Both guards are load-bearing, because `owned_by_seed` does not merely lift
	// the severity cap: the lookalike surfaces drop the threat finding entirely
	// for an owned candidate, so a false positive here silently suppresses a
	// threat.
	//  - EXACT set equality, not overlap: a candidate carrying the seed's set
	//    PLUS its own host, or all but one of it, is a different shape and keeps
	//    its `third_party` verdict.
	//  - at least `DEDICATED_NS_MATCH_MIN_COUNT` DISTINCT matched hosts on no
	//    known shared-tenant provider. ⚠️ That is 2, NOT 1, and must not be
	//    "simplified" to 1: across 1,819 measured seed/candidate pairs the two
	//    bars behave identically (30 flips either way, none of them a genuine
	//    impersonation), so the stricter bar costs nothing measured and closes
	//    three shapes a squatter can buy with a self-service account — two
	//    `domaincontrol.com` hosts plus one unlisted host, two
	//    `registrar-servers.com` hosts plus one, and six `akam.net` plus one.
	//    Known residual under BOTH bars: a seed split across azure-dns (listed,
	//    but a small pool) plus a two-host unlisted provider. It was unobserved
	//    across those 1,819 pairs, so it is recorded here rather than paid for
	//    with a wider guard.
	const candidateNsUnique = [...new Set(candidateNs)];
	const seedNsUnique = [...new Set(seedNs)];
	const exactNsSetMatch =
		seedNsUnique.length > 0 &&
		candidateNsUnique.length === seedNsUnique.length &&
		candidateNsUnique.every((ns) => seedNsUnique.includes(ns));
	// Counted DISTINCT: a candidate that lists one off-platform host twice must
	// not reach the two-host bar on its own.
	const dedicatedSharedDistinct = [...new Set(dedicatedShared)];

	if (exactNsSetMatch && dedicatedSharedDistinct.length >= DEDICATED_NS_MATCH_MIN_COUNT) {
		return {
			verdict: 'owned_by_seed',
			strength: 'strong',
			signals: ['ns_set_match'],
			rationale: `${candidateDomain} delegates to exactly ${seedApex}'s complete ${seedNsUnique.length}-nameserver set (${seedNsUnique.join(', ')}), of which ${dedicatedSharedDistinct.length} (${dedicatedSharedDistinct.join(', ')}) are on no known shared-tenant provider — an account-level match on ${seedApex}'s own nameserver set.`,
		};
	}

	if (
		seedTotal > 0 &&
		sharedNs.length === seedTotal &&
		sharedNs.every((ns) => input.isSharedNsHost(ns)) &&
		sharedNs.every((ns) => isPooled(ns))
	) {
		return {
			verdict: 'owned_by_seed',
			strength: 'medium',
			signals: ['ns_shared_provider_complete'],
			rationale: `${candidateDomain} matches the complete ${seedTotal}/${seedTotal} nameserver set on a pooled shared provider (${sharedNs.join(', ')}). A full match is evidence there; a partial match on the same provider would not be.`,
		};
	}

	// #864 — step 5b. Applied only once every seed-side NS arm has declined, so
	// a strong NS match is never displaced by this medium-strength verdict. Also
	// carries the `unmeasured` outcome for an asked-but-unanswered seed probe.
	if (convergence !== null) return convergence;

	// #974 — step 5c. Every arm that could attribute has declined; before either
	// `third_party` arm below claims distinct infrastructure, check whether the
	// candidate in fact points at the SEED's own web and mail hosts. Applied
	// only where a `third_party` would otherwise be returned (the #929
	// whole-platform `unattributed` arm keeps its own, more specific rationale).
	const infraMatch = seedInfrastructureMatch(input);
	// #974 reopened — step 5d, consulted only when 5c declined. Both share the
	// `seedInfraAssessment` slot: they replace the same `third_party` outcomes.
	const cohortMatch = infraMatch === null ? seedLabelCohortMatch(input) : null;
	const seedInfraAssessment: OwnershipAssessment | null =
		infraMatch !== null
			? {
					verdict: 'unattributed',
					strength: 'none',
					signals: ['seed_infrastructure_match'],
					rationale: `${candidateDomain} does not share ${seedApex}'s nameserver set, but resolves to the same web address set (${infraMatch.a.join(', ')}) and the same mail hosts (${infraMatch.mx.join(', ')}) as ${seedApex} — the shape of the organisation's own brand-variant registration hosted by an agency or platform. Those records are self-published and can be copied, so ownership is not established either way.`,
				}
			: cohortMatch !== null
				? {
						verdict: 'unattributed',
						strength: 'none',
						signals: ['seed_label_cohort'],
						rationale: `${candidateDomain} does not share ${seedApex}'s nameserver set, but resolves to the same web address set (${cohortMatch.a.join(', ')}) as ${seedApex}, and ${cohortMatch.siblings.length} other exact-label variants (${cohortMatch.siblings.join(', ')}) share its identical address set, nameservers (${cohortMatch.ns.join(', ')}) and mail hosts (${cohortMatch.mx.length > 0 ? cohortMatch.mx.join(', ') : 'none'}) — the shape of the organisation's own brand-variant portfolio registered through one agency or registrar. Those records are self-published and can be copied, so ownership is not established either way.`,
					}
				: null;

	// #929 MIRROR — THE POOLED HALF (SQ-36; live anz.com / anz.co.nz, 2026-09-17).
	// On a POOLED provider (`POOLED_SHARED_NS_APEXES`, Akamai: six hostnames drawn
	// from ~128) the set is assigned PER ZONE, so two zones of the SAME account are
	// given DIFFERENT hostnames by design — measured: anz.com holds a1-206, a16-67,
	// a28-67, a7-66, a8-67, a9-67.akam.net; anz.co.nz holds a1-6, a12-66, a28-67,
	// a3-66, a6-65, a9-65.akam.net plus ns1/ns2.anz.co.nz. #929 established that an
	// IDENTICAL set on a UNIFORM platform observes nothing about ownership; the
	// mirror is that a NON-identical set on a POOLED platform observes nothing about
	// DISTINCTNESS: the difference is the provider's per-zone assignment, not the
	// candidate's own infrastructure. Without this arm the block below reports the
	// bank's own NZ domain as "registered to a different organisation" — the exact
	// false claim PR #937's review ruled the `third_party` sentence must never make.
	//
	// A nameserver inside the CANDIDATE's own registrable domain (ns1.anz.co.nz) is
	// a SELF-REFERENCE. Anyone who controls the candidate zone can publish one, so
	// under the OWNERSHIP RULE (see `ClassifyOwnershipInput`) it can never be
	// ownership evidence — and for the identical reason it is not DISTINCTNESS
	// evidence either: it names no operator. It is therefore counted as NEITHER
	// here, never as a signal.
	//
	// THE OUTCOME IS `unattributed`, NEVER `owned_by_seed`. A squatter that hosts
	// its lookalike on the seed's pooled provider gains only the neutral wording
	// every unattributed candidate already carries: the `info` ceiling
	// (`capAttributionSeverity()`) and the separate threat observation are
	// untouched. Any candidate host that is neither on the seed's pooled platform
	// nor self-referential — the squatter's own `ns1.attacker.example` — fails the
	// `every()` below and keeps the candidate out of this arm entirely.
	//
	// SCOPED TO EXACT-LABEL TLD VARIANTS ({@link isExactLabelTldVariant}), the bar
	// step 5d already uses. This is what keeps #929's pinned outcome intact: the
	// UNRELATED bnz.co.nz also sits wholly on Akamai and also shares one pooled
	// host with anz.co.nz, and a character-edit label is the squatter's shape — so
	// that pair stays `third_party` on the arm below. Only the brand's own other
	// TLD reaches this one.
	//
	// MEASURED BLAST RADIUS (63 registered seed/candidate pairs across 20 brands'
	// ccTLD estates, DoH 2026-09-17): two rows move. anz.co.nz `third_party` →
	// `unattributed` (the defect). adobe.fr keeps the same verdict and the same
	// signal and only takes its rationale from here instead of the whole-set arm
	// below — it is an exact-label variant whose hosts are a SUBSET of the seed's
	// Akamai set, so both arms describe it correctly. No pair gains `owned_by_seed`.
	const nsApex = (host: string): string => getRegistrableDomain(host) ?? host;
	const seedPooledApexes = new Set(seedNs.filter((ns) => isPooled(ns)).map(nsApex));
	const onSeedPooledPlatform = (ns: string): boolean => isPooled(ns) && seedPooledApexes.has(nsApex(ns));
	const candidateApex = getRegistrableDomain(normHost(candidateDomain)) ?? normHost(candidateDomain);
	if (
		isExactLabelTldVariant(candidateDomain, input.seedDomain) &&
		seedNs.length > 0 &&
		seedNs.every(onSeedPooledPlatform) &&
		candidateNs.length > 0 &&
		candidateNs.some(onSeedPooledPlatform) &&
		candidateNs.every((ns) => onSeedPooledPlatform(ns) || isInBailiwick(ns, candidateApex))
	) {
		const platformNs = candidateNs.filter(onSeedPooledPlatform);
		const selfNs = candidateNs.filter((ns) => !onSeedPooledPlatform(ns));
		const selfClause = selfNs.length > 0 ? `, plus nameserver(s) inside its own domain (${selfNs.join(', ')})` : '';
		return {
			verdict: 'unattributed',
			strength: 'none',
			signals: ['ns_shared_platform'],
			rationale: `${candidateDomain} is delegated to ${[...seedPooledApexes].join(', ')} (${platformNs.join(', ')})${selfClause} — the same DNS platform ${seedApex} uses, and one that assigns every zone its own hostnames from a shared pool, so two zones held by one account do not match there. Nothing distinct from ${seedApex} was observed, and nothing that identifies the registrant either: this is not ownership evidence in either direction.`,
		};
	}

	// #929 — an overlap that exists but is confined to shared-provider hosts.
	// Neither verdict below moves severity (the third_party / unattributed
	// split is wording only — see the file header); the choice is about what
	// was OBSERVED:
	//  - the candidate's WHOLE set is shared-platform hosts the seed also uses
	//    (one.com `ns01`/`ns02`; or a candidate that carries only the platform
	//    half of a seed that ALSO has its own hosts): the hosts are the
	//    platform's, assigned to every tenant, and NO distinct infrastructure
	//    was seen on the candidate. That is `unattributed` — "no ownership or
	//    third-party signal" — not `third_party`, whose report wording
	//    ("registered to a different organisation") would be a false claim
	//    about the customer's own alias hosted on the same platform (PR #937
	//    review, both rounds). The seed's total does NOT enter this test: the
	//    `third_party` sentence below must be literally true of the CANDIDATE.
	//  - anything else (the 1/6 Akamai partial; a one.com pair PLUS the
	//    squatter's own `ns1.attacker.example`): the candidate's REMAINING
	//    nameservers are distinct from the seed's, so `third_party` is what
	//    was measured, worded for the platform overlap rather than as
	//    "distinct infrastructure".
	if (candidateNs.length > 0 && sharedNs.length > 0 && dedicatedShared.length === 0) {
		const candidateWhollyOnPlatform = sharedNs.length === candidateNs.length;
		if (candidateWhollyOnPlatform) {
			return {
				verdict: 'unattributed',
				strength: 'none',
				signals: ['ns_shared_platform'],
				rationale: `${candidateDomain} delegates only to shared-tenant DNS platform hosts that ${seedApex} also uses (${sharedNs.join(', ')}), which that platform assigns to every customer — platform plumbing, not ownership evidence either way.`,
			};
		}
		if (seedInfraAssessment !== null) return seedInfraAssessment;
		return {
			verdict: 'third_party',
			strength: 'none',
			signals: ['ns_shared_platform'],
			rationale: `${candidateDomain} shares ${sharedNs.length}/${seedTotal} nameservers with ${seedApex} (${sharedNs.join(', ')}), all on a shared-tenant DNS platform that assigns the same hostnames to unrelated customers; its remaining nameservers are distinct from ${seedApex}'s — platform plumbing, not ownership evidence.`,
		};
	}

	if (seedInfraAssessment !== null) return seedInfraAssessment;

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
 * #974 corroborator bar (step 5c of `classifyOwnership()`). Returns the matched
 * sets when BOTH hold, else `null`:
 *
 *  1. the candidate's A set is non-empty and IDENTICAL to the seed's (same
 *     addresses, same count — an overlap is not enough), AND
 *  2. the candidate's real MX set is non-empty and IDENTICAL to the seed's.
 *
 * Neither leg alone is sufficient: a shared-hosting web IP (one server, many
 * tenants) or a multi-tenant mail provider (Google, M365, a host's antispam
 * relay) is exactly what an UNRELATED tenant of the same platform looks like —
 * the #929 lesson for NS, applied to A and MX. Together, exact web+mail
 * identity is what an SMB's agency-hosted defensive cohort looks like
 * (ltmcguinness.{com,net,co,io,ai} on the agency's NS, all on the seed's A and
 * MX), and what no typosquat running its OWN infrastructure looks like.
 *
 * WHY THE OUTCOME IS `unattributed`, NOT `owned_by_seed` (Ruling A, and the
 * #864 review that rejected candidate MX as verdict-bearing, 931f7b81d): both
 * legs are CANDIDATE-published and cost a squatter nothing to copy, and two
 * unrelated tenants of one platform can match both. So the match cannot earn
 * the ownership verdict — which would lift the attribution ceiling and switch
 * off the threat observation for a squatter who copied the records — but it
 * does falsify the `third_party` arm's "distinct infrastructure / no ownership
 * signal" claim, which is the defect. Severity is unaffected (`third_party` and
 * `unattributed` share the `info` ceiling).
 */
export function seedInfrastructureMatch(input: {
	candidateA?: readonly string[];
	seedA?: readonly string[];
	candidateMx?: readonly string[];
	seedMx?: readonly string[];
}): { a: string[]; mx: string[] } | null {
	const a = identicalNonEmptySet(input.candidateA, input.seedA, (v) => v.trim().toLowerCase());
	if (a === null) return null;
	const mx = identicalNonEmptySet(input.candidateMx, input.seedMx, normHost);
	if (mx === null) return null;
	return { a, mx };
}

function identicalNonEmptySet(
	left: readonly string[] | undefined,
	right: readonly string[] | undefined,
	norm: (v: string) => string,
): string[] | null {
	const l = new Set((left ?? []).map(norm).filter(Boolean));
	const r = new Set((right ?? []).map(norm).filter(Boolean));
	if (l.size === 0 || l.size !== r.size) return null;
	for (const v of l) if (!r.has(v)) return null;
	return [...l].sort();
}

/**
 * #974 (reopened) cohort corroborator bar (step 5d of `classifyOwnership()`).
 * Returns the matched cohort when ALL of these hold, else `null`:
 *
 *  0. the candidate is an EXACT-LABEL TLD variant of the seed: it is itself a
 *     registrable domain, its label equals the seed's, and it is not the seed's
 *     own apex (`ltmcguinness.com` for `ltmcguinness.co.nz`);
 *  1. its A set is IDENTICAL to the seed's non-empty A set;
 *  2. at least {@link MIN_LABEL_COHORT_SIBLINGS} OTHER exact-label variants in
 *     `labelCohort` share the candidate's identical A set, identical complete NS
 *     set and identical MX set, so 3+ variants match;
 *  3. no host in that shared NS set is on a shared-tenant platform
 *     (`isSharedNsHost`, i.e. `SHARED_NS_APEXES`) — UNLESS the exact-label
 *     cohort on the seed's A set (siblings plus the candidate) has at least
 *     {@link SEED_LABEL_COHORT_SHARED_NS_MIN} members, in which case the
 *     shared-NS exclusion is waived (#974 live).
 *
 * WHY: the live cohort (`ltmcguinness.{com,net,co,io,ai}`) sits on the seed's
 * A address but on an agency's NS and a hosting provider's antispam MX, so step
 * 5c's A+MX identity with the SEED never holds. The seed's A alone is not enough
 * either: its PTR is a cloud host and the MX is a host's gateway, so it may be a
 * shared hosting IP (#929's lesson for NS, applied to A). What adds the second
 * signal is the cohort: the exact brand label swept across several TLDs, every
 * one on one identical NS/MX estate AND on the seed's own web address. That is
 * how an organisation's agency registers a defensive portfolio.
 *
 * A TYPOSQUAT NEVER QUALIFIES, as candidate or as sibling: a character edit
 * (`ltmcguiness.com`) is not the exact label, and edited names are what
 * squatters buy. Condition 3 keeps unrelated tenants of one platform (Wix,
 * one.com) from forming a cohort by accident — SMALL cohorts. #974's REOPEN
 * evidence (SQ-23) was itself a live miss: `ltmcguinness`'s cohort is on
 * `siteground.net`, a `SHARED_NS_APEXES` platform, and condition 3 as
 * originally written rejected it outright regardless of cohort size. A
 * cohort of 5+ exact-label variants, all on the seed's A and one identical
 * NS/MX estate, is no longer the accidental 2-3-tenant grouping condition 3
 * exists to catch — it is a brand sweep that happens to be hosted on a
 * shared-tenant registrar. Below {@link SEED_LABEL_COHORT_SHARED_NS_MIN}
 * members, shared-NS candidates are rejected exactly as before.
 *
 * WHY `unattributed`, NOT `owned_by_seed`: every compared record is
 * CANDIDATE-published and free to copy, and a squatter's own portfolio also
 * shares one NS/MX estate. So, as with step 5c (Ruling A), the match can only
 * falsify the `third_party` arm's "distinct infrastructure / no ownership signal"
 * claim. It never earns ownership, never lifts the attribution ceiling, and
 * never moves severity — whatever the cohort size.
 */
export function seedLabelCohortMatch(input: {
	seedDomain: string;
	candidateDomain: string;
	registration: RegistrationState;
	isSharedNsHost: (nsHost: string) => boolean;
	candidateA?: readonly string[];
	seedA?: readonly string[];
	candidateMx?: readonly string[];
	labelCohort?: readonly LabelCohortMember[];
}): { a: string[]; ns: string[]; mx: string[]; siblings: string[] } | null {
	if (input.registration.state !== 'registered' || input.candidateMx === undefined || !input.labelCohort?.length) return null;
	const isExactLabelVariant = (domain: string): boolean => isExactLabelTldVariant(domain, input.seedDomain);
	const candidate = normHost(input.candidateDomain);
	if (!isExactLabelVariant(candidate)) return null;

	const a = identicalNonEmptySet(input.candidateA, input.seedA, (v) => v.trim().toLowerCase());
	if (a === null) return null;
	const ns = [...new Set(input.registration.ns.map(normHost).filter(Boolean))].sort();
	if (ns.length === 0) return null;
	const mx = [...new Set(input.candidateMx.map(normHost).filter(Boolean))].sort();

	const siblings = input.labelCohort
		.filter(
			(member) =>
				normHost(member.domain) !== candidate &&
				isExactLabelVariant(member.domain) &&
				identicalNonEmptySet(member.a, a, (v) => v.trim().toLowerCase()) !== null &&
				identicalNonEmptySet(member.ns, ns, normHost) !== null &&
				identicalSet(member.mx, mx),
		)
		.map((member) => normHost(member.domain))
		.sort();

	// #974 — condition 3 (no shared-tenant NS host) is waived only for a
	// large-enough cohort: siblings.length + 1 counts the candidate itself.
	// Below SEED_LABEL_COHORT_SHARED_NS_MIN, a shared-platform NS set behaves
	// exactly as before — the #929 guard against an accidental small grouping
	// of unrelated platform tenants stays in force.
	if (ns.some((host) => input.isSharedNsHost(host)) && siblings.length + 1 < SEED_LABEL_COHORT_SHARED_NS_MIN) return null;

	return siblings.length >= MIN_LABEL_COHORT_SIBLINGS ? { a, ns, mx, siblings } : null;
}

/** Set identity that, unlike {@link identicalNonEmptySet}, treats two measured-empty sets as identical. */
function identicalSet(left: readonly string[], right: readonly string[]): boolean {
	return right.length === 0 ? left.map(normHost).filter(Boolean).length === 0 : identicalNonEmptySet(left, right, normHost) !== null;
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
export type AttributionConfidence = 'corroborated' | 'single_signal' | 'uncorroborated';

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
 *
 * #974 — `'corroborated'` means a second, independent signal actually agrees
 * (the caller's `corroborated` flag), not merely that the label is long. A
 * non-owned verdict whose only support is the verdict's own signal (e.g. NS
 * non-overlap) with a long-enough label is `'single_signal'`: it used to read
 * `'corroborated'`, over-claiming a one-signal `third_party`. Consumers that
 * gate on `!== 'uncorroborated'` (the #863 rollup) treat both the same.
 */
export function attributionConfidence(verdict: OwnershipVerdict, brandLabel: string, corroborated: boolean): AttributionConfidence {
	if (verdict === 'owned_by_seed' || corroborated) return 'corroborated';
	return brandLabel.length >= MIN_ATTRIBUTION_LABEL_LENGTH ? 'single_signal' : 'uncorroborated';
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
 *
 * SQ-36 — `ownershipStrength` / `ownershipSignals` travel here too. They used to
 * appear ONLY on `buildOwnedBySeedFinding()` (`src/tools/lookalike-findings.ts`),
 * so a NON-owned finding published a verdict with no machine-readable trace of
 * WHICH arm reached it: a consumer auditing `third_party` on anz.co.nz saw an
 * absent signal list and could not tell "evaluated, every arm declined" from
 * "never evaluated". The arrays are the same ones `classifyOwnership()` already
 * returned — this surfaces them, it does not change a verdict, a signal or a
 * severity (`capAttributionSeverity()` still keys on `verdict` ALONE).
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
		ownershipStrength: ownership.strength,
		ownershipSignals: ownership.signals,
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
	// #929 (PR #937 review): `unattributed` earns no "Unrelated" title either —
	// nothing was measured that says the domain is anyone else's.
	const title =
		ownership.verdict === 'unmeasured'
			? `Confusable label, ownership unmeasured this run: ${domain}`
			: ownership.verdict === 'unattributed'
				? `Confusable label, ownership not established: ${domain}`
				: `Unrelated domain, confusable label: ${domain}`;
	return createFinding(
		options.category,
		title,
		ceiling,
		`${domain} shares the "${brand}" label with the scanned domain but ${relation}. ${ownership.rationale} Its ${options.postureNoun} is reported for awareness only: no action by the scanned organisation is implied, and this finding asserts no control over ${domain}.${hedge}`,
		metadata,
	);
}
