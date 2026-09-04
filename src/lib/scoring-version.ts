// SPDX-License-Identifier: BUSL-1.1

/**
 * Scoring-model version + config fingerprint, stamped into scan output for
 * reproducibility. A dated client report once became unreproducible in two days
 * because nothing in the output recorded which scoring policy produced it. These
 * two stamps fix that: `SCORING_MODEL_VERSION` pins the policy, and
 * `computeScoringConfigHash()` fingerprints any active `SCORING_CONFIG` override.
 *
 * Runtime-agnostic, Workers-safe (no Node APIs, no `@blackveil/dns-checks` import).
 */

/**
 * Semver for the **scoring policy** — deliberately distinct from the package /
 * server version (`SERVER_VERSION`), which tracks the deployed code, not the
 * scoring model.
 *
 * BUMP THIS whenever scoring policy changes in a way that alters scores or grades:
 * category weights, profile weights, grade thresholds, severity penalties, the
 * `passed`/missing-control rule, a severity reclassification (e.g. the DNSSEC
 * severity decouple — `critical`→`high` with the penalty preserved via
 * `penaltyOverride`), or a change to how the scoring **profile** is detected (the
 * detected profile selects the per-profile weight table via `getProfileWeights`).
 * Bumping it lets a report consumer detect that two scans of the same domain ran
 * under different scoring policies.
 *
 * History:
 * - 1.0.0 — baseline policy as of v3.7.0 (DNSSEC decouple, profile-aware auto scoring).
 * - 1.1.0 — profile detection now requires an active observed control (`controlPresent`)
 *   instead of bare `passed`/finding prose. Corrects `enterprise_mail` over-fire and
 *   sparse-domain misdetection; per-domain score impact is bounded (~±2 pts).
 * - 1.2.0 — `enterprise_mail` now requires enforcing DMARC (p=quarantine|reject) behind a
 *   managed provider, not provider + any one auto-provisioned control (DKIM). Tightens the
 *   stricter-lens membership; reclassified domains move to `mail_enabled` (slightly more lenient).
 * - 1.3.0 — non-apex scan targets no longer fire a false NS/CAA/DNSSEC "missing record"
 *   finding: a subdomain that owns no NS RRset inherits its zone apex's posture
 *   (resolveZoneApex). Removes the CRITICAL missingControl-zero on delegated-parent
 *   subdomains (e.g. mail-sending hosts). Apex-domain scores are unchanged.
 * - 1.4.0 — three measurement-vs-measurement-failure corrections. (a) `detectDomainContext`'s
 *   `failureRatio` now counts only MEASURED checks, so a timed-out/errored check can no
 *   longer push a domain into the lenient `minimal` weight table — i.e. the measurement
 *   failure no longer selects the lens that grades the domain. Scans in which every check
 *   completed are unaffected. (b) A scan completing under `thresholds.evidenceSufficiency`
 *   (default 60%) of its attempted checks is now UNGRADED (`overall`/`grade` null,
 *   `evidenceInsufficient: true`) rather than receiving a confident letter. Grade bands,
 *   category weights and the check matrix are unchanged. (c) Compliance/reporting surfaces
 *   (`map_compliance`, `generate_fix_plan`, `map_csc_products`, `compare_baseline`,
 *   `prioritize_csc_leads`) now ABSTAIN on a check that never completed — `not_assessed` /
 *   `assessed: false` — rather than grading it as a pass or fail; see the `[3.37.0]`
 *   CHANGELOG.md entry for the full per-tool breakdown.
 * - 1.5.0 — three new detection families that penalise previously-unmeasured defects. No
 *   weight, tier, grade band, severity penalty or profile-detection rule changed; scores move
 *   only because real defects are now seen. (a) NS: lame delegation — a delegated nameserver
 *   whose hostname resolves to no address cannot answer for the zone, the "Sitting Ducks"
 *   hijack precondition. Partial (some NS resolving) is a scored `high`; total is routed to
 *   the inconclusive path, NOT scored 0. (b) CAA: a long RRset TTL widens the CA reuse window
 *   (the CA/Browser Forum BRs permit issuing within the TTL **or** 8 hours, whichever is
 *   GREATER), and a CAA policy on an unsigned zone is strippable in transit — read from the
 *   lookup's own AD flag. Both `low`/`info`. (c) DKIM: `s=` admitting neither `email` nor `*`,
 *   `h=` omitting sha256, sha1 alongside sha256, and multiple RRs at one selector. Also two
 *   parser fixes that REMOVE false positives — folding whitespace around `=` is RFC-legal and
 *   previously made every tag on such a record read as absent (for `p=` that surfaced as a
 *   spurious revoked-key finding), and `t=` is an unordered colon list so `t=s:y` missed test
 *   mode. A domain may therefore move in EITHER direction under 1.5.0.
 * - 1.6.0 — MTA-STS absence no longer zeroes its category. The `mta_sts` absence findings
 *   ("No MTA-STS record found", "No MTA-STS or TLS-RPT records found") dropped their
 *   `missingControl: true` metadata, so absence is now a GRADED `medium` (ordinary −15
 *   severity penalty, category ~85) instead of a category-zeroing missing control. This
 *   matches CAA, SVCB-HTTPS and TLS-RPT, which already decline to zero on absence. Evidence:
 *   a 1,000-domain corpus scan (2026-08-03) measured `mta_sts` at a mean 3.3 with 96.5% of
 *   687 measured domains at exactly 0 — a control almost nobody deploys is a flat constant
 *   penalty, not a discriminator. This is an UPWARD re-grade for the large majority of
 *   domains; a domain that already published MTA-STS is unaffected. A deployed-but-BROKEN
 *   policy still keeps its confident `high`/`medium` findings — only ABSENCE changed. No
 *   weight (MTA-STS stays 3, protective), tier, grade band, severity penalty or
 *   profile-detection rule changed. Also recalibrated in this version: the CAA long-TTL
 *   staleness threshold moved from an arbitrary 24h to the CA/Browser Forum 8-hour reuse-window
 *   floor (the only non-arbitrary crossover — below it the floor dominates); the same corpus
 *   observed a maximum CAA TTL of 6h across 135 RRsets, so this finding fires ~never either
 *   way and no score moves because of it.
 * - 1.7.0 — Mailjet joins the core SPF trust-surface catalog, so its trust-surface finding
 *   now participates in the existing weak-DMARC corroboration rule instead of always reading
 *   `info`. The worker post-processor reconstructs its DMARC context from the CORE's trust-surface
 *   finding metadata and falls back to no-corroboration when the core recognised nothing; a
 *   Mailjet-only SPF record previously produced no core finding, so it always took that fallback.
 *   With Mailjet cataloged, a Mailjet include on a domain with `p=none` and relaxed alignment now
 *   surfaces as `medium` (ordinary −15 severity penalty on `spf`) rather than `info` — the same
 *   treatment the other 18 cataloged platforms already received. Domains with enforcing DMARC are
 *   unaffected. No weight, tier, grade band, severity penalty, missing-control rule or
 *   profile-detection rule changed. The affected population is unmeasured against the corpus.
 * - 1.8.0 — the SPF trust surface is scored ONCE instead of twice (#637). `analyzeTrustSurface`
 *   emitted an AGGREGATE "SPF trust surface: N shared platforms" finding (`high`, −25 under
 *   corroboration) AND ALSO charged `medium` (−15) per platform for the SAME condition. The
 *   per-platform findings are now always `info` (penalty 0); the aggregate is unchanged and
 *   remains the single scored signal. This is a DOUBLE-COUNT removal, not a recalibration: no
 *   weight, tier, grade band, severity penalty (`SEVERITY_PENALTIES` untouched),
 *   missing-control rule, corroboration/elevation rule or profile-detection rule changed. The
 *   per-platform findings remain present and fully detailed (same prose, same
 *   `dmarcCorroborated`/`dmarcPolicy`/`dmarcAlignmentMode` metadata) — only the repeated
 *   penalty is gone. Measured: the `spf` category moves UPWARD ONLY, by 0 / +15 / +30 / +60 /
 *   +75 points at 0 / 1 / 2 / 4 / 6 corroborated shared platforms; every multi-platform domain
 *   converges on 75 for the trust surface alone. github.com went `spf` 0 → 35 and overall
 *   67 → 70 (NIST display grade D → C) on its real 19-category `enterprise_mail` roster. A
 *   domain publishing NO SPF record still scores 0 — restoring the discrimination the stacked
 *   penalty had erased, since a valid working record and no record at all both read 0 before.
 *   No domain can move down: the change only lowers severities, and the two `spf` category
 *   interactions (`no_spf_no_dmarc`, `no_spf_no_dkim`) are gated on `maxScore: 0`, so a higher
 *   `spf` can only stop them firing. Applied identically to BOTH copies of the analyzer (core
 *   `packages/dns-checks/src/checks/spf-trust-surface.ts` + worker
 *   `src/tools/spf-trust-surface.ts`); the worker post-processor never recomputes the score, so
 *   the score change originates entirely in the core package — direct package consumers
 *   (bv-web-prod) re-grade identically.
 * - 1.8.0 — `txt_hygiene` stops charging per-record for one condition (#642). The jurisdiction
 *   and stale-integration loops emitted one finding PER RECORD, so a domain with six records
 *   from the same service paid six penalties for a single problem. Both now group by service
 *   and emit one finding carrying `recordCount` + `records` metadata. UPWARD ONLY, and capped
 *   at +1 point overall: `txt_hygiene` is a hardening category, and the hardening tier is
 *   binary (1.0 pt iff `score >= 50 && passed`), so the category can gain at most its single
 *   point. Anti-flattening confirmed: four DISTINCT problems still produce four penalties —
 *   only repeats of the SAME problem consolidate.
 * - 1.8.0 — the non-mail email-auth downgrade is now GATED ON INHERITED ENFORCEMENT and runs
 *   for the first time (#643). Two defects compounded here. (1) The predicate `hasNoMx` tested
 *   for a finding title no production path emits, so `adjustForNonMailDomain` had never once
 *   run against real DNS. (2) Underneath it, the downgrade was UNGATED: `severity: 'info'` was
 *   assigned outside the `apexDmarcCovers` conditional, so that boolean only selected a prose
 *   string while EVERY no-MX domain would have been downgraded. Repairing (1) alone would have
 *   shipped (2): measured at +7 to +23 points across ~28.6% of domains, crossing two to three
 *   NIST display bands, and handing a clean pass to domains `check_mx` concurrently reports as
 *   spoofable. That is unsound — absent MX means the domain cannot RECEIVE mail and says
 *   nothing about whether it can be SPOOFED AS A SENDER, which is what SPF/DKIM/DMARC defend.
 *   So the downgrade now fires ONLY where the parent's DMARC `sp=`/`p=` is `quarantine` or
 *   `reject` — real inherited enforcement, and what CLAUDE.md had documented all along. Apex
 *   domains have no parent to inherit from and therefore never qualify. Net effect vs the
 *   PRODUCTION baseline (where the downgrade never ran): unchanged for every apex domain, and
 *   for subdomains changed only where enforcing parent coverage demonstrably exists.
 * - 1.9.0 — omitted hardening categories are no longer scored as failed controls. A consumer
 *   submitting a PARTIAL roster now has every absent hardening category excluded uniformly,
 *   matching the core/protective absent-result semantics; submitted-and-measured hardening
 *   failures stay in the denominator as failures, and timeout/error results stay inconclusive.
 *   UPWARD for partial-roster consumers, no change for a full 19-category `scan_domain` roster.
 *   (Entry backfilled — the constant was bumped in the 3.47.0 cut without a history line.)
 * - 1.10.0 — the CORE SPF trust surface now COUNTS unrecognized shared senders (#572 part 2).
 *   `analyzeTrustSurface` in `packages/dns-checks` recognised only CATALOGED multi-tenant
 *   platforms and emitted its aggregate at `matchedPlatforms.length > 1`, while the worker copy
 *   (`src/tools/spf-trust-surface.ts`) had ALSO counted hosts matched by a generic heuristic —
 *   any include/redirect target carrying an `spf` / `_spf` / `spfNN` label — since #566. The two
 *   copies therefore disagreed on the ONE number that is scored: `platformCount`, and whether the
 *   aggregate fires at all. The core adopts the worker's heuristic verbatim, closing the last
 *   behavioural gap between them (the catalog gap closed in 3.42.0, #572 part 1).
 *
 *   DOWNWARD ONLY, and by exactly one severity step. The per-member findings are `info` (0
 *   penalty) as of 1.8.0, so an unrecognized sender can only ever change the score by pushing
 *   `delegated.length` across the aggregate's `> 1` threshold. Affected shape: a domain with
 *   exactly ONE cataloged platform plus at least one uncataloged `spf`-labelled include (or zero
 *   cataloged plus two or more uncataloged) — it previously produced NO aggregate and now
 *   produces one. Magnitude when weak DMARC corroborates: the aggregate is `high`, so the `spf`
 *   category moves 100 → 75, ≈3 points of overall score on a representative healthy 19-category
 *   `mail_enabled` roster (measured: 97 → 94). Uncorroborated, the aggregate is `info` and the
 *   score does not move at all — only the finding list grows. Domains already at 2+ cataloged
 *   platforms see only a larger `platformCount` and longer prose, never a new penalty; domains
 *   with no shared senders are untouched. First-party hosts (`mail.mycompany.com`) do NOT match
 *   the heuristic and are never counted. Corroboration is broad — anything short of
 *   `p=reject; pct=100` with strict alignment on both `aspf`/`adkim` — so the affected population
 *   is essentially "the qualifying include shape", not "the qualifying DMARC posture"; it is
 *   UNMEASURED against the 1,000-domain corpus. No weight, tier, grade band, severity penalty
 *   (`SEVERITY_PENALTIES` untouched), missing-control rule, corroboration/elevation rule or
 *   profile-detection rule changed. The change lands in the CORE package, so direct package
 *   consumers (bv-web-prod calls `checkSPF`, never the worker wrapper) re-grade identically and
 *   stop under-counting; the worker's OUTPUT is unchanged, because its post-processor already
 *   replaced the core's trust-surface findings with exactly these.
 * - 1.11.0 — a CLAIMABLE lame delegation is now `critical` with a DECLARED `verified`
 *   confidence, and `ns` importance moves 2 → 3 in `mail_enabled` and `enterprise_mail` only
 *   (`non_mail`/`web_only` were already 3; `minimal` 1 and `authoritative_dns_infra` 15 are
 *   untouched — a flat "2→3" would have double-bumped two profiles). Severity ALONE would have
 *   moved nothing: `verifiedCriticalCount` counts findings that are both `critical` AND
 *   `verified`, and confidence is only `verified` when explicitly declared, so the stamp is
 *   what makes the escalation register. DOWNWARD, and only for domains where claimability was
 *   MEASURED — the dead nameserver's registrable base domain must answer NXDOMAIN, so an
 *   attacker can register it and become authoritative; SERVFAIL/REFUSED/NODATA never qualify.
 *   Measured on a `mail_enabled` roster with dmarc degraded to 75: **97 (A+) → 82 (B+)**,
 *   exactly the −15 `criticalOverallPenalty`, with the `ns` category at 60 in BOTH arms. No
 *   grade ceiling is involved: the finding sets no missing control and
 *   `PROFILE_CRITICAL_CATEGORIES` is untouched. Prevalence 130 of 94,826 domains scanned on
 *   the dns-recon lane (0.137%) — a LANE figure, not corpus-wide. Total-lame is unchanged and
 *   still routes to the inconclusive path: a zone whose nameservers all failed to resolve is a
 *   measurement failure, not a hijackable domain. No weight outside `ns`, no tier, grade band,
 *   `SEVERITY_PENALTIES` entry, missing-control rule or profile-detection rule changed.
 * - 1.12.0 — a domain's own NAME can no longer zero a category. `scoreIndicatesMissingControl`
 *   matched `MISSING_CONTROL_REGEX` against a finding's title AND detail, and many findings
 *   interpolate the scanned domain, a nameserver host, an MX host or a policy URL into that
 *   detail — so any subject whose NAME contained `missing`/`required`/`not found` zeroed the
 *   category, and (dnssec being critical in every profile) also tripped the 64-point
 *   critical-gap ceiling. Measured LIVE in production: `missingkids.org` scored `dnssec` 0 and
 *   overall 64/D where `github.com` scored 60 and 88/A on BYTE-IDENTICAL findings. The gate now
 *   tests a subject-data-free projection (`redactSubjectData`) — URLs, emails and DNS-name-shaped
 *   tokens redacted, plus an opt-in `metadata.subjectTerms` for values that are not structurally
 *   recognisable. The regex and every emitted string are UNCHANGED; only the gate's input moves,
 *   so authored prose still zeroes exactly as before (all four intended zeroers re-verified).
 *   UPWARD only, and only for subjects whose own identifiers contained a trigger word.
 *   Second change, same class: a deployed-but-broken MTA-STS policy no longer scores worse than
 *   no policy at all — the `max_age`-omitted case measured 0/FAILED and is now 88/pass, giving
 *   the ladder enforce 100 > testing 95 > MX-gap 90 > RFC-invalid 88 > unretrievable 85 =
 *   mode:none 85 = absent 85. An UNRETRIEVABLE policy (404/5xx, redirect, oversized body) ties
 *   absence rather than beating it: publishing a TXT record plus a CNAME to any 404 host needs
 *   no HTTPS service, certificate or policy file, so an earlier cut of this ladder handed it +3
 *   over deploying nothing. 88 is reserved for a policy that is genuinely served and merely
 *   RFC-invalid — the line is retrievability, not validity.
 *   No parity fixture expectation moved. `SEVERITY_PENALTIES`, weights, tiers, grade bands,
 *   profile detection and the missing-control RULE are all untouched.
 * - 1.13.0 — DMARC `pct=`/`ri=` tokens are now parsed STRICTLY per RFC 7489 §6.3 ABNF
 *   (`pct` is 1*3DIGIT, `ri` is 1*DIGIT), plus two measurement-integrity guards that move no
 *   score any production scan produces. (a) The strict parse is a NEW DETECTION on
 *   trailing-garbage tokens: `parseInt`'s prefix-parsing accepted `pct=100%` / `pct=100abc`
 *   as a valid 100 (no finding) and `ri=86400x` as a valid 86400 (no finding); both now draw
 *   the EXISTING `medium` invalid-value finding at its existing −15 penalty — RFC 7489
 *   §6.6.3 has receivers discard syntactically invalid records, so a malformed tag can mean
 *   no DMARC at all at strict receivers, and scoring the token as valid asserted something
 *   the RFC contradicts. Tokens like `pct=50abc` merely swap which medium finding fires
 *   (partial-coverage → invalid; same penalty); `pct=050` stays ABNF-valid. DOWNWARD only,
 *   by one medium (−15) per malformed tag, and ONLY for records carrying a malformed
 *   `pct=`/`ri=` token; the affected population is UNMEASURED against the corpus — plausibly
 *   small but not written up as zero. No parity fixture carries such a token. (b) The
 *   critical-gap ceiling can no longer be armed by an UNMEASURED check: `buildGenericContext`
 *   now gates its `missingControls` population on `isCheckMeasured` like every sibling map,
 *   and `computeGenericScore` ignores a gap key that is simultaneously transient. Latent —
 *   no current transient finding text matches `MISSING_CONTROL_REGEX` — but the latency was
 *   an accident of today's error strings (`buildDnsErrorResult` passes upstream DNS error
 *   text through verbatim), guaranteed by nothing. (c) `scoreIndicatesMissingControl` now
 *   takes its confidence through `inferFindingConfidence`'s validated declared-then-infer
 *   read: an out-of-union declared `confidence` (unvalidated cache re-read) previously
 *   disarmed zeroing silently; it now falls through to inference like an undeclared finding.
 *   Also declared (`missingControl: true`) on the DMARC no-record finding — behaviour-neutral,
 *   the prose already zeroed; the flag makes the intent survive a reword. `SEVERITY_PENALTIES`,
 *   weights, tiers, grade bands and profile detection are all untouched.
 * - 1.14.0 — two previously-unmeasured email/DNS defects now affect category scores using
 *   existing penalties. (a) DNSSEC can no longer treat a resolver's AD flag as proof that an
 *   unsigned zone is protected: a validated pass now requires both a child DNSKEY and a parent
 *   DS. The affected shape (AD=true with neither record) moves DOWN from 100 to the canonical
 *   unsigned-zone score of 60 and no longer emits an affirmative cryptographic-verification
 *   claim. (b) The measured `resend` DKIM selector joins the bounded default probe list, so a
 *   weak key that was previously hidden behind another sender's healthy key now receives the
 *   existing legacy-RSA finding and penalty. Affected domains can move DOWN from a clean pass;
 *   no severity, weight, tier, grade band, missing-control rule or profile-detection rule
 *   changed. The DMARC `p=none; sp=none` correction shipped in the same package is explicitly
 *   score-neutral (its new finding is `info`) but restores the evidence consumed by attack-path
 *   analysis. Affected population for all three shapes is unmeasured against the corpus.
 * - 1.15.0 — relaxed SPF alignment (`aspf=r`/unset) is a severity reclassification `low` →
 *   `info` (#842): the "Relaxed SPF alignment" DMARC finding no longer carries the −5 low
 *   penalty, and its detail now states the precondition for strict alignment instead of a
 *   bare "consider aspf=s". Rationale, measured not theoretical: the classifier receives
 *   only record-derived facts, so whether strict alignment is ACHIEVABLE cannot be
 *   determined — and for any ESP-relayed domain (Resend, SendGrid, Mailchimp, Postmark,
 *   SES with a custom MAIL FROM) the return-path sits on a subdomain, so `aspf=s`
 *   guarantees SPF-alignment failure on 100% of that traffic and converts a two-legged
 *   DMARC posture into a one-legged one. Following the old advice on our own production
 *   domain rejected 21 legitimate messages outright (1,045 aggregate-report records,
 *   2026-08-30) whenever DKIM also failed. UPWARD only, +5 on the `dmarc` category for
 *   every domain with `aspf=r`/unset (the common case); `aspf=s` domains and the strict
 *   fixture are unchanged, and `adkim` (whose strict mode does not depend on the
 *   return-path) keeps its existing low. Five DMARC parity fixtures moved up by exactly 5.
 *   The finding title is unchanged (assess_spoofability matches it by prefix). No weight,
 *   tier, grade band, `SEVERITY_PENALTIES` entry, missing-control rule or
 *   profile-detection rule changed.
 * - 1.16.0 — a missing-control rule correction on `dnssec` (#850). A DS or DNSKEY lookup
 *   that THREW, next to published DNSSEC material on the other leg, was recorded as a
 *   MEASURED broken chain: `missingControl: true` zeroed the category, and because `dnssec`
 *   is critical in all six profiles the `criticalGapCeiling` then capped the WHOLE domain at
 *   64 — grade D for a genuinely signed zone, caused by a transient resolver failure. The
 *   unmeasured shape now returns the repo's standard non-answer contract instead
 *   (`checkStatus: 'error'` + `score: 0` + `partial`), so the category is EXCLUDED from the
 *   scan score and renormalized rather than scored 0, and the transient-zero retry can fire.
 *   `controlPresent` moves from `false` to `undefined` on that path — "could not be
 *   determined", not a definitive "not working" — which also removes it as a
 *   profile-detection input for those runs. Scores move UPWARD and only for scans that hit
 *   the failed-probe path; a scan in which both legs answered is bit-for-bit unchanged. No
 *   weight, tier, grade band, `SEVERITY_PENALTIES` entry or severity label changed.
 *   (`check_dnssec_chain`'s parallel ordering fix in #852 is NOT reflected here: it is a
 *   standalone tool whose category is outside the `CheckCategory` union, so it contributes
 *   nothing to a scan score.)
 * - 1.17.0 — structured `metadata.missingControl: true` and legacy deterministic prose now
 *   feed one canonical missing-control predicate at every scoring layer. Before this change,
 *   both paths zeroed the category in `buildCheckResult`, but `buildGenericContext` populated
 *   the whole-scan `missingControls` map from prose inference alone. On an otherwise identical
 *   measured DMARC roster, structured intent therefore produced 71/C+ while equivalent prose
 *   armed the critical-gap ceiling and produced 64/C. The structured declaration now also
 *   drives the critical-gap ceiling and email-bonus guards; timeout/error checks remain gated
 *   by `isCheckMeasured` and cannot assert absence. DOWNWARD only for measured critical
 *   categories whose finding declares `missingControl: true` without also matching the legacy
 *   prose regex; findings that already matched prose and all inconclusive results are unchanged.
 *   Affected population is UNMEASURED. No weight, tier, grade band, severity penalty,
 *   profile-detection rule or check roster changed.
 * - 1.18.0 — corrected two affirmative-safety inversions. A DNSKEY without a parent DS
 *   is an RFC 4033 insecure delegation, not a bogus chain: it now scores 60 like an
 *   unsigned zone and no longer arms the critical-gap grade-D ceiling. Well-formed TLSA
 *   records whose certificate association has not been compared against the served
 *   certificate now receive a low deduction instead of an unsupported perfect score.
 *   UPWARD for DNSSEC islands; DOWNWARD for domains publishing unverified TLSA records.
 * - 1.19.0 — DMARC `p=none` is a missing ENFORCEMENT control. The `DMARC policy set to
 *   none` finding moves `medium` → `high` and declares `missingControl: true`, zeroing
 *   the dmarc category (was ~75–85) and arming the critical-gap ceiling (64, NIST
 *   display D) in the profiles where dmarc is critical — `mail_enabled` /
 *   `enterprise_mail` only; non-mail profiles gain no ceiling. Rationale: a receiver
 *   applying p=none takes no action on failing mail (RFC 9989 §5.1.4 "Monitoring
 *   Mode"), so for enforcement it is equivalent to publishing nothing — BitSight
 *   grades the two identically, and no surveyed grader treats p=none as protective.
 *   NZ SGE mandates p=reject on all email-enabled domains by October 2026. Operator
 *   ratified 2026-09-01 (bv-web-prod research spec
 *   docs/superpowers/specs/2026-09-01-dmarc-pnone-and-nonmail-grading-research.md).
 *   MEASURED population (2,000-domain random sample of the bv-web GSI corpus,
 *   direct DoH probe, n=1,953 measured): 12.7% of domains publish p=none (vs 75.7%
 *   no record, 11.7% enforcing); of the p=none cohort, 50.0% scored >64 before this
 *   change (mean 65.1) and would now cap, 32.7% drop a NIST display letter
 *   (C/B/A → D). DOWNWARD only, and only for p=none domains; absent/enforcing
 *   postures and every other category are bit-for-bit unchanged. The finding TITLE
 *   is unchanged (impersonation escalation, dmarcIsWeak, spoofability posture and
 *   rollout planning all match on it). No weight, tier, grade band,
 *   `SEVERITY_PENALTIES` entry or profile-detection rule changed.
 * - 1.20.0 — `web_only` weights the NON-SENDER LOCKDOWN (Option B of the 2026-09-01
 *   research spec, operator ratified 2026-09-02). `web_only` identity weights move
 *   from 0 to the values `non_mail` has always carried — spf 0→2, dmarc 0→3,
 *   mx 0→1 (dkim stays 0: a non-sender cannot earn sender DKIM marks; the NZ SGE
 *   blank-key wildcard variant was examined and not adopted). The per-check rubric
 *   already scored the lockdown correctly (check-mx: no-MX+no-SPF → spoofable,
 *   missingControl, 0; no-MX+`v=spf1 -all` → "Correctly-configured non-mail
 *   domain" per NIST SP 800-177r1 §4.4.2; RFC 7505 null MX recognized; dmarc:
 *   reject/quarantine/none graded) — zero weight simply multiplied it away, so a
 *   fully spoofable unconfigured domain and a locked-down one scored identically.
 *   Weights-only, NO ceiling: spf/dmarc stay OUT of
 *   `PROFILE_CRITICAL_CATEGORIES.web_only`. MEASURED population (same 2,000-domain
 *   GSI corpus sample, 3-record DoH probe 2026-09-02, n=1,926 measured): 59.6% of
 *   the corpus has no MX; of that cohort 93.1% publishes NONE of the lockdown
 *   records (0.4% has the full triple), so a p=none-style hard cap would re-grade
 *   ~55% of the index in one release — the weights bound the movement to ≤11.3
 *   points instead (spf+dmarc = 5/33 of the 70-pt core tier + mx = 1/28 of
 *   protective; measured live anchor fundhaus.app 82/B → ≈76/NIST C). DOWNWARD for
 *   un-locked-down no-MX domains, UPWARD-neutral (unchanged 100) for locked-down
 *   ones; `non_mail` and every mail profile are bit-for-bit unchanged.
 * - 1.21.0 — the SCANNER'S OWN I/O failure inside `checkMTASTS` no longer scores the
 *   domain (issue #889, dns-checks 1.33.0). Three catch paths used to convert a thrown
 *   policy fetch (ECONNRESET, TLS/egress failure, the package's own 4s
 *   `AbortSignal.timeout`, a `RobotsDisallowedError` from the gate, a resolver failure
 *   for `mta-sts.<domain>`) or a rejecting `_smtp._tls` / `_mta-sts` TXT lookup into a
 *   SCORED finding with no `checkStatus` — `medium` "policy fetch failed" (category 85)
 *   and `low` "DNS query failed" (category 95) — folded into the profile score as a
 *   measured deficiency, byte-for-byte indistinguishable from a domain that lacks the
 *   control. They now return the not-assessed shape the rest of the model already uses
 *   (`checkMX`, `buildDnsErrorResult`): `checkStatus: 'timeout'` (AbortError /
 *   TimeoutError) or `'error'`, `score: 0`, `passed: false`, `partial: true`, and an
 *   `info` finding carrying `inconclusive: true` + `notAssessedReason`
 *   (`policy_fetch_failed` | `dns_query_failed` | the existing `robots_disallowed`
 *   vocabulary), so the category is EXCLUDED and renormalised (shown n/a) and the
 *   scan-path transient-zero retry can fire. A DEFINITE answer is unchanged: a non-ok
 *   HTTP status on the policy URL keeps its `high`, an empty TXT answer keeps its graded
 *   absence finding, and the MX-coverage sub-check keeps its silent abstention.
 *   A TLS-RPT lookup failure beside a DEFINITE MTA-STS measurement (a policy 404, a
 *   missing record) does NOT abstain the category: the measured findings score as
 *   before and the sub-probe failure rides along as an unscored `info` (was −5).
 *   Direction: NOT one-way. The category is EXCLUDED and the profile weights are
 *   renormalised over the remaining measured categories, so the overall score moves
 *   toward the mean of those categories — UP when that mean exceeds the 85 / 95 the
 *   failed probe used to contribute, DOWN when it is below. Only scans that hit the
 *   failed-probe path are affected; every measured scan is bit-for-bit unchanged. No
 *   weight, tier, grade band, `SEVERITY_PENALTIES` entry or profile-detection rule
 *   changed. Population UNMEASURED against the corpus (a scanner-side transient by
 *   definition has no stable prevalence).
 * - 1.22.0 — `check_dane_https` VERIFIES TLSA pins against the certificate the host
 *   serves (issue #841, dns-checks 1.34.0). The served leaf / SPKI / chain digests are
 *   captured by bv-tls-probe over the operator-only `BV_TLS_PROBE` binding (paid-tier
 *   scans only, launched only when TLSA records exist) and compared per RFC 7671 —
 *   DANE-EE / PKIX-EE against the leaf, DANE-TA / PKIX-TA against any served chain member,
 *   matching types 0/1/2 as full data / SHA-256 / SHA-512. The scoring inversion this
 *   issue measured (a stale pin at 100, its removal at 95) ends: the ladder is now
 *   VERIFIED 100 (`info`, `certificateMatchVerified: true`) > ABSENT 95 (unchanged `low`)
 *   > MISMATCH 75 (`high` "pin does not match the served certificate", −25). A probe that
 *   was attempted but returned no certificate (cold-cache "pending", capture failure,
 *   off-host redirect, host mismatch) is UNMEASURED: an `info` with `inconclusive: true`
 *   + `notAssessedReason`, no deduction, `partial: true` (not cached, re-tried next scan)
 *   and NO `checkStatus` — the TLSA measurement itself is real, so the category stays
 *   completed. A trust-anchor pin (usage 0 / 2) that matches no RETAINED chain entry
 *   while the probe reports `chainTruncated` is likewise an `info` abstention
 *   (`notAssessedReason: 'chain_truncated'`, cached normally — persistent for the host),
 *   never a mismatch; leaf usages (1 / 3) are unaffected by truncation. Direction: DOWNWARD only for domains whose DANE-HTTPS pin does not match
 *   the served certificate (100 or 95 → 75, ≈0.09 overall points at protective weight 2);
 *   UPWARD 95 → 100 for verified pins on operator deploys. Absence is unchanged; every
 *   self-host without the binding (and `check_dane`, SMTP/25, which the HTTPS-only probe
 *   cannot serve) is bit-for-bit unchanged at the 1.18.0 posture. CEILING SAFETY:
 *   `dane_https` is in `PROFILE_CRITICAL_CATEGORIES` for `non_mail` / `web_only`, so a
 *   `high` that read as a missing control would cap the whole scan at 64; the mismatch
 *   prose is kept clear of the `MISSING_CONTROL_REGEX` triggers, declares no
 *   `missingControl`, and the package test proves both predicates decline and a web_only
 *   scan with a mismatch stays above 64. Also in this version: maturity staging counts a
 *   DANE pin toward Stage 4 only when the finding carries `certificateMatchVerified:
 *   true` (previously a title regex promoted unverified SMTP pins). No weight, tier, grade
 *   band, `SEVERITY_PENALTIES` entry or profile-detection rule changed. Population
 *   UNMEASURED against the corpus: DANE-for-HTTPS adoption is ≈0% and the mismatch rate
 *   within it is unknown; the only measured instance is the issue's own repro domain.
 */
export const SCORING_MODEL_VERSION = '1.22.0';

/** Marker returned for an unset / default (un-overridden) scoring config. */
const DEFAULT_CONFIG_MARKER = 'default';

/**
 * Recursively serialize a value with sorted object keys at every level, so that
 * two semantically-identical configs with different key ordering serialize
 * identically. `ScoringConfig` is nested (weights, profileWeights, thresholds,
 * grades, baselineFailureRates), so top-level-only sorting is insufficient.
 */
function stableStringify(value: unknown): string {
	if (value === null || typeof value !== 'object') {
		return JSON.stringify(value) ?? 'null';
	}
	if (Array.isArray(value)) {
		return `[${value.map((v) => stableStringify(v)).join(',')}]`;
	}
	const entries = Object.keys(value as Record<string, unknown>)
		.sort()
		.map((key) => `${JSON.stringify(key)}:${stableStringify((value as Record<string, unknown>)[key])}`);
	return `{${entries.join(',')}}`;
}

/** FNV-1a 32-bit hash over a string → short lowercase hex. Standalone (no side effects). */
function fnv1a(input: string): string {
	let hash = 0x811c9dc5;
	for (let i = 0; i < input.length; i += 1) {
		hash ^= input.charCodeAt(i);
		hash = Math.imul(hash, 0x01000193);
	}
	return (hash >>> 0).toString(16);
}

/**
 * Deterministic short hex fingerprint of the **effective** scoring config.
 *
 * Hash the parsed/merged config object (not the raw env string), so that an
 * equivalent override with different whitespace or key order yields the same
 * fingerprint, and even a partial override produces a distinct full-config hash.
 * An unset / `null` / `undefined` config returns the fixed `'default'` marker —
 * the only fallback, used by un-threaded or test callers. Note the production
 * scan paths always pass a fully-populated effective config (even with no
 * `SCORING_CONFIG` override, `parseScoringConfigCached(undefined)` yields the
 * full default config), so they emit a hex hash, never `'default'`.
 */
export function computeScoringConfigHash(config?: unknown): string {
	if (config === undefined || config === null) return DEFAULT_CONFIG_MARKER;
	return fnv1a(stableStringify(config));
}
