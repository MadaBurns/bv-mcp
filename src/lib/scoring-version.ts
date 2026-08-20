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
 */
export const SCORING_MODEL_VERSION = '1.12.0';

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
