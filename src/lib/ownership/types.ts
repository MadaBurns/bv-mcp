// SPDX-License-Identifier: BUSL-1.1

/** Ownership attribution: verdict, signal and input types plus the cohort/length constants. Split verbatim from `../ownership-attribution` (SQ-539). */

import type { RegistrationState } from '../registration-state';

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
	 *
	 * Candidate DMARC `p=reject`, including a stricter policy than the seed's,
	 * does not establish ownership (#1192, SQ-302): the candidate controls that
	 * policy and can still send aligned, authenticated mail. Strict policy is
	 * not a seed-published authorisation or an ownership-confidence input here.
	 * Likewise, a certificate SAN naming the seed and candidate demonstrates
	 * validation for those names, not common organisational ownership (#1188).
	 * A shared platform may obtain that validation for unrelated customers;
	 * reciprocal CT lookup can observe the same issuance again. Discovery's
	 * bounded provenance describes observed certificates, not seed-side control.
	 *
	 * The §7.1 arm requires every candidate MX inside the seed's own bailiwick
	 * (`mxRoutedIntoSeed`), which excludes gateway-relayed portfolios.
	 * KNOWN UNATTRIBUTED SHAPE: a regional sibling on its own DNS platform
	 * behind a managed mail gateway (e.g. `*.pphosted.com`) has NO reachable
	 * path to `owned_by_seed`, BY DESIGN (operator ruling 2026-10-17 on #1188 /
	 * #1192) — do not file it again. It stays `unattributed`; certificate SAN
	 * co-listing cannot rescue it even as wording-only corroboration (SQ-337,
	 * see the CT SAN note in the file header).
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
export const DEDICATED_NS_MATCH_RATIO = 0.5;
/** Minimum absolute count of dedicated shared NS hosts, alongside the ratio above. */
export const DEDICATED_NS_MATCH_MIN_COUNT = 2;

/** Minimum brand-label length below which a non-owned candidate needs corroboration to be worded with full confidence (D4). Governs WORDING ONLY — see `attributionConfidence()`. */
export const MIN_ATTRIBUTION_LABEL_LENGTH = 5;
