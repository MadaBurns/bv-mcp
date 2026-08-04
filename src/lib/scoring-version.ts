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
 */
export const SCORING_MODEL_VERSION = '1.7.0';

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
