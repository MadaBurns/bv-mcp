// SPDX-License-Identifier: BUSL-1.1

import type { ScanDomainResult } from '../scan-domain';
import type { CheckResult, Finding } from '../../lib/scoring';
import { isGraded, computeScanEvidence } from '../../lib/scoring';
import type { OutputFormat } from '../../handlers/tool-args';
import { sanitizeOutputText } from '../../lib/output-sanitize';
import { resolveImpactNarrative } from '../explain-finding';
import { SCORING_MODEL_VERSION, computeScoringConfigHash } from '../../lib/scoring-version';
import { DNS_CHECKS_PACKAGE_VERSION } from '../../lib/dns-checks-version';
import { displayGradeFor, formatScoreGrade, isCompletedCheck, isMeasured, normalizeCheckStatus, UNGRADED_DISPLAY } from '../../lib/ungraded-display';

// All three live in a tiny leaf module so every formatter in src/tools/ can share
// them without importing the scan orchestrator. Re-exported here because this is
// where consumers have always found UNGRADED_DISPLAY — new importers should take it
// from the leaf module directly.
export { UNGRADED_DISPLAY };

/** Structured scan result for machine-readable consumption (e.g., CI/CD actions). */
export interface StructuredScanResult {
	domain: string;
	/**
	 * Overall 0–100 score, or `null` when the domain was NOT graded — no checks
	 * ran (invalid domain, budget exceeded, NXDOMAIN, unresolvable zone). `null`
	 * means "not measured", never "measured and scored zero". Consumers MUST
	 * exclude a null score from comparison, ranking and policy evaluation rather
	 * than coercing it: `null < n` is `true` and `null - n` is `NaN` in JS.
	 */
	score: number | null;
	/** Display grade letter, or `null` when `score` is null. Never a sentinel string. */
	grade: string | null;
	/** Pass/fail verdict, or `null` when the domain was not graded. */
	passed: boolean | null;
	/**
	 * `false` when NO check contributed a measurement at all (zero `checks`).
	 * Distinct from "checks ran but most failed" — that state is not represented
	 * here. Invariant: `measured === false` implies `score === null`.
	 */
	measured: boolean;
	maturityStage: number | null;
	maturityLabel: string | null;
	/**
	 * Per-category numeric score, or `null` when the category is not applicable to this
	 * domain (mirrored in `notApplicableCategories`). Cluster-3 reconciliation invariant:
	 * for every `cat` in `notApplicableCategories`, `categoryScores[cat] === null`.
	 * This eliminates the contradictory "spf: 100 AND spf in notApplicableCategories"
	 * shape the v3.3.12 fact-check surfaced (defect G).
	 */
	categoryScores: Record<string, number | null>;
	findingCounts: { critical: number; high: number; medium: number; low: number };
	/**
	 * The individual findings `findingCounts` above only tallies — same source
	 * (`result.score.findings`), same order (as produced, not re-sorted), no cap on
	 * length. Field-for-field passthrough of `Finding` (`packages/dns-checks/src/types.ts`)
	 * minus its optional `metadata` bag, which can carry per-check internals not meant
	 * for a general consumer. `detail` is already sanitized by `createFinding()` at
	 * construction time, so it is passed through verbatim, not re-sanitized here.
	 */
	findings: Array<{ category: string; title: string; severity: 'critical' | 'high' | 'medium' | 'low' | 'info'; detail: string }>;
	/** Detected scoring profile; null when the scan produced no evidence to infer one. */
	scoringProfile: string | null;
	scoringSignals: string[];
	scoringNote: string | null;
	adaptiveWeightDeltas: Record<string, number> | null;
	/** Percentile rank within the scoring profile population (0–100). Null when insufficient benchmark data. */
	percentileRank: number | null;
	/** Composite email spoofability score (0–100, higher = more spoofable). Null when not computed. */
	spoofabilityScore: number | null;
	/** Category interaction effects applied as post-scoring adjustments. */
	interactionEffects: Array<{ ruleId: string; penalty: number; narrative: string }>;
	/** Execution status per check category. 'completed' = ran normally, 'timeout' = per-check timeout, 'error' = threw. */
	checkStatuses: Record<string, 'completed' | 'timeout' | 'error'>;
	/** DNSSEC configuration source. `tld_inherited` is retained only for backward-compatible parsing of older scan records; current checks require DNSKEY+DS and emit `domain_configured`. */
	dnssecSource: 'domain_configured' | 'tld_inherited' | null;
	/** CDN provider detected from HTTP response headers. null when no CDN detected or check did not run. */
	cdnProvider: string | null;
	/**
	 * Categories the scan MEASURED (a `CheckResult` was recorded) and found genuinely
	 * inapplicable to this domain (no MX → mail-only categories under
	 * `web_only`/`non_mail`). Always reported as `null` in `categoryScores` to avoid a
	 * misleading 100 or 0.
	 *
	 * **Semantic change (as of blackveil-dns 3.37.0, ships alongside
	 * `@blackveil/dns-checks` 1.7.0): this array is now DISJOINT from
	 * `inconclusiveCategories`.** It previously conflated two reasons — a deliberate
	 * skip and a measurement failure — and `inconclusiveCategories` was documented as a
	 * subset of it. A consumer that read this array as the union of "not scored" must
	 * now read `notApplicableCategories.concat(inconclusiveCategories)`.
	 *
	 * Caveat: a category can appear here with no `CheckResult` at all if it still has a
	 * `categoryScores` entry — via Rule 2 (`MAIL_ONLY_CATEGORIES_FOR_NON_MAIL_PROFILE`,
	 * which fires at ANY score) or Rule 3's narrower `categoryScores[cat] === 100`
	 * branch — a library-consumer-only path (see `isCategoryNonApplicable`'s no-check
	 * branches) that the production scan engine never produces.
	 */
	notApplicableCategories: string[];
	/**
	 * Categories whose `null` score is due to a measurement FAILURE — the check timed
	 * out or errored (`checkStatuses[cat]` is `'timeout'`/`'error'`) — rather than the
	 * control genuinely not applying. Treat these as "could not measure / retry later".
	 *
	 * **DISJOINT from `notApplicableCategories`** as of blackveil-dns 3.37.0 (ships
	 * alongside `@blackveil/dns-checks` 1.7.0; previously a subset of it). The two
	 * states are deliberately separate: *inconclusive* means we could not measure it;
	 * *not applicable* means we measured and it does not apply. Both are `null` in
	 * `categoryScores`. Empty when every check ran.
	 */
	inconclusiveCategories: string[];
	/**
	 * How much of this scan actually ran: `attempted` checks submitted, `completed`
	 * that finished, and their `ratio`. Present on every result so a report reader can
	 * judge the scan's own coverage instead of inferring it from a missing grade.
	 */
	evidence: { attempted: number; completed: number; ratio: number };
	/**
	 * `true` when the scan completed too few checks to be graded, so `score` and
	 * `grade` are `null` for a MEASUREMENT reason rather than a security one.
	 * Mutually exclusive with `measured === false` ("nothing ran at all"): this flag is
	 * only ever `true` when `evidence.attempted > 0`. Enforced at `buildStructuredScanResult`
	 * (not merely documented): `computeScanScore`'s own zero-check branch stamps
	 * `evidenceInsufficient: true` on a zero-checks result, which is suppressed to `false`
	 * here so the invariant holds even though the underlying producer does not honor it.
	 */
	evidenceInsufficient: boolean;
	/** Human-readable explanation when `evidenceInsufficient` is `true`; `null` otherwise. */
	evidenceNote: string | null;
	timestamp: string;
	cached: boolean;
	/**
	 * Scoring-policy semver (distinct from package/server version) that produced
	 * this result — bumped whenever weights/severities/thresholds change. Pins the
	 * scoring model for report reproducibility. See `lib/scoring-version.ts`.
	 *
	 * ⚠️ NOT the `@blackveil/dns-checks` npm version — that is the sibling field
	 * `dnsChecksPackageVersion`. The two are independent namespaces that both look
	 * like semver and overlap numerically, which has twice been misread as an
	 * "engine version gap" (#707).
	 */
	scoringModelVersion: string;
	/**
	 * Version of the `@blackveil/dns-checks` engine package this build bundles —
	 * emitted alongside `scoringModelVersion` so the two namespaces can be told
	 * apart from one response (#707). It moves on every package release (code,
	 * detections, fixes); `scoringModelVersion` moves only when scoring POLICY
	 * changes, so it advances far more slowly and legitimately lags. Neither is
	 * the reproducibility anchor for a published score — `scoringConfigHash` is.
	 * See `lib/dns-checks-version.ts`.
	 */
	dnsChecksPackageVersion: string;
	/**
	 * Deterministic fingerprint of the **effective** scoring config — a short hex
	 * hash of the merged config object (the default config produces one stable
	 * fixed hash; any `SCORING_CONFIG` override produces a distinct one). On the
	 * production scan paths this is always a hex hash, since the effective config
	 * is always fully populated. The literal `'default'` marker appears only when
	 * no config object was available to fingerprint (un-threaded / test callers and
	 * batch error placeholders). Lets a consumer detect that two scans ran under
	 * different scoring config. See `lib/scoring-version.ts`.
	 */
	scoringConfigHash: string;
	/**
	 * Tri-state DNS resolution signal. `false` for NXDOMAIN / non-resolving
	 * domains; `'broken'` when the zone exists but SERVFAILs (DNSSEC-bogus or
	 * lame delegation) — neither has a posture to assess. Omitted when unknown —
	 * additive-optional, so tolerant downstream parsers are unaffected.
	 */
	resolves?: boolean | 'broken';
}

/**
 * Categories that are intrinsically mail-only — under `web_only`/`non_mail`
 * profiles (no MX) they should be reported as N/A regardless of underlying score.
 * `bimi` requires DMARC enforcement to publish; `mta_sts` and `dkim` are inbound-
 * /outbound-mail features; `mx` has no meaning when there are no MX records.
 *
 * `dane` (issue #639) is the SMTP-only DANE category — `check-dane.ts` probes TLSA
 * at `_25._tcp.<mx-host>` and nothing else; HTTPS DANE is the separate `dane_https`
 * category, which is NOT mail-only and is deliberately absent from this set. On a
 * domain with no usable MX the check says so in prose ("SMTP DANE not applicable
 * (no inbound mail)") yet emits an all-info `CheckResult` scoring a full 100 — a
 * perfect mark for a control the domain had no opportunity to fail, while
 * `dkim`/`mta_sts`/`bimi`/`mx` on the same domain were correctly nulled.
 *
 * Listing it here is a REPORTING change only: it nulls `categoryScores.dane` and
 * files the category under `notApplicableCategories`. The overall score is computed
 * upstream by `computeScanScore` and is untouched — DANE still contributes its
 * hardening-tier point there. Excluding it from the scoring denominator re-grades
 * every non-mail domain and is an operator decision (see #639).
 */
const MAIL_ONLY_CATEGORIES_FOR_NON_MAIL_PROFILE = new Set<string>(['dkim', 'mta_sts', 'bimi', 'mx', 'dane']);
/** Email categories that current behaviour already downgrades to info under non-mail profiles. */
const EMAIL_CATEGORIES_HEURISTIC_NA = new Set<string>(['spf', 'dmarc', 'dkim', 'mta_sts']);

/**
 * Decide whether a single check should be reported as N/A given the active scoring profile.
 * The rules combined are the single source of truth that `categoryScores` and
 * `notApplicableCategories` both derive from (defect G — single-source CategoryEvaluation).
 *
 * For any category carrying a `CheckResult` (`check` is defined), this function answers
 * ONLY "we measured, and it genuinely does not apply" — it is never asked about a check
 * that timed out or errored: the caller short-circuits those into `inconclusiveCategories`
 * before reaching here. (A former "Rule 1" returned `true` for a timed-out/errored check,
 * which filed a MEASUREMENT FAILURE as a deliberate N/A — the conflation this removal
 * fixes.)
 *
 * Caveat (the `check === undefined` branches of Rule 2 and Rule 3, out of scope for this
 * fix): a category with NO `CheckResult` at all — i.e. never run, not even attempted —
 * can still be filed as N/A here: unconditionally via Rule 2 (any score) when the
 * category is mail-only, or via Rule 3's narrower `categoryScores[cat] === 100` branch
 * for the heuristic email categories. This is a library-consumer-only path (the
 * production scan engine always records a `CheckResult` for every category it seeds a
 * score for, so it never produces this shape); a hand-built `categoryScores`/`checks`
 * pair from an external caller could reach it.
 */
export function isCategoryNonApplicable(check: CheckResult | undefined, category: string, profile: string, score: number | undefined): boolean {
	const isNonMailProfile = profile === 'non_mail' || profile === 'web_only';
	if (!isNonMailProfile) return false;

	// Rule 2 (defect H): under web_only/non_mail, intrinsically mail-only categories
	// are always N/A — even if the check produced a numeric 0 (pre-fix non-mail pattern).
	if (MAIL_ONLY_CATEGORIES_FOR_NON_MAIL_PROFILE.has(category)) return true;

	// Rule 3 (legacy heuristic — refined): a non-mail profile downgrades missing
	// email findings to info; when ALL of an email category's findings are info AND
	// none of them indicate a record was found, treat as N/A. A finding whose title
	// signals presence of a configured record (e.g. "SPF record found",
	// "DMARC record found") flips the category back to applicable — fixes the case
	// where an anti-spoof SPF `-all` is published but findings happen to all be info.
	if (EMAIL_CATEGORIES_HEURISTIC_NA.has(category)) {
		if (check) {
			const allInfo = check.findings.length > 0 && check.findings.every((f: Finding) => f.severity === 'info');
			const noFindings = check.findings.length === 0 && check.score === 100;
			const hasPositiveSignal = check.findings.some((f: Finding) => {
				const t = f.title.toLowerCase();
				return (
					/record (found|configured)|properly configured|valid|configured/.test(t) &&
					!/no\s+\S+\s+record/.test(t) &&
					!/not found/.test(t) &&
					!/missing/.test(t)
				);
			});
			if ((allInfo || noFindings) && !hasPositiveSignal) return true;
		} else if (score === 100) {
			// Category absent from checks but seeded to 100 by the engine.
			return true;
		}
	}

	return false;
}

/**
 * Render the prose row for a category the scan could NOT measure — the check timed out or
 * errored, so it is excluded from the weighted score rather than zeroed.
 *
 * Deliberately distinct from the `∅ … N/A` row: "we measured and it does not apply" and "we
 * could not measure it" are different states that the structured payload has always kept
 * disjoint (`notApplicableCategories` vs `inconclusiveCategories`), and collapsing them in
 * prose is what let a never-run web check read as a clean bill of health.
 *
 * Pure string formatting — reads no score and changes none.
 */
function formatUnmeasuredCategoryRow(category: string, check: CheckResult | undefined): string {
	const reason = check?.checkStatus === 'timeout' ? 'check timed out' : 'check did not complete';
	return `  ⊘ ${category.toUpperCase().padEnd(10)} n/a (not measured — ${reason})`;
}

/** Optional enrichment data for structured scan results. */
export interface ScanResultEnrichment {
	percentileRank?: number | null;
	spoofabilityScore?: number | null;
	/**
	 * Precomputed fingerprint of the effective scoring config, threaded from the
	 * call site that holds the parsed config (`runtimeOptions.scoringConfig`). When
	 * omitted, `buildStructuredScanResult` falls back to the hash `scanDomain`
	 * stamped onto the result itself, and only then to the `'default'` marker.
	 */
	scoringConfigHash?: string;
}

/** Build a machine-readable structured result from a scan. */
export function buildStructuredScanResult(result: ScanDomainResult, enrichment?: ScanResultEnrichment): StructuredScanResult {
	// checkStatuses
	const checkStatuses: Record<string, 'completed' | 'timeout' | 'error'> = {};
	for (const check of result.checks) {
		checkStatuses[check.category] = normalizeCheckStatus(check.checkStatus);
	}

	// dnssecSource
	const dnssecCheck = result.checks.find((c) => c.category === 'dnssec');
	let dnssecSource: 'domain_configured' | 'tld_inherited' | null = null;
	if (dnssecCheck) {
		for (const f of dnssecCheck.findings) {
			const src = f.metadata?.dnssecSource;
			if (src === 'domain_configured' || src === 'tld_inherited') {
				dnssecSource = src as 'domain_configured' | 'tld_inherited';
				break;
			}
		}
		// Only infer `domain_configured` when the zone is actually signed. An UNSIGNED
		// zone now scores 60 (penaltyOverride −40) and therefore `passed === true`
		// (60 ≥ 50, no missingControl), so a `passed`-only fallback wrongly stamped
		// unsigned domains as `domain_configured`. Exclude the DNSSEC deficiency findings
		// — "DNSSEC not enabled" (60, passes), and the broken/failing chains (0, fail) —
		// so only a genuinely validated/configured zone (no deficiency finding) defaults
		// to `domain_configured`.
		const dnssecDeficient = dnssecCheck.findings.some(
			(f) => f.title === 'DNSSEC not enabled' || f.title === 'DNSSEC chain of trust incomplete' || f.title === 'DNSSEC validation failing',
		);
		if (dnssecSource === null && dnssecCheck.passed && !dnssecDeficient && isCompletedCheck(dnssecCheck)) {
			dnssecSource = 'domain_configured';
		}
	}

	// cdnProvider
	const httpCheck = result.checks.find((c) => c.category === 'http_security');
	let cdnProvider: string | null = null;
	if (httpCheck) {
		for (const f of httpCheck.findings) {
			const cdn = f.metadata?.cdnProvider;
			if (typeof cdn === 'string') {
				cdnProvider = cdn;
				break;
			}
		}
	}

	// --- Single-source CategoryEvaluation pass (defect G + H) ---
	// `notApplicableCategories` and `categoryScores` are now derived from the same
	// per-category applicability decision. This eliminates the "spf: 100 AND spf in
	// notApplicableCategories" overlap surfaced in the 2026-05-28 fact-check round.
	const profile = result.context?.profile ?? 'mail_enabled';
	const sourceCategoryScores: Record<string, number> = result.score.categoryScores ?? {};
	const checksByCategory = new Map<string, CheckResult>();
	for (const check of result.checks) {
		checksByCategory.set(check.category, check);
	}

	// Union of categories present in either the score map or the checks array.
	const allCategoryKeys = new Set<string>([...Object.keys(sourceCategoryScores), ...result.checks.map((c) => c.category)]);

	const notApplicableCategories: string[] = [];
	const inconclusiveCategories: string[] = [];
	const categoryScores: Record<string, number | null> = {};
	for (const category of allCategoryKeys) {
		const check = checksByCategory.get(category);
		const rawScore: number | undefined = Object.prototype.hasOwnProperty.call(sourceCategoryScores, category)
			? sourceCategoryScores[category]
			: undefined;

		// INCONCLUSIVE — the check timed out or threw, so we could not measure it. This is
		// checked FIRST and returns early, because it must win over any profile-based
		// applicability rule: a check that never ran cannot be declared inapplicable on the
		// strength of the profile it would have been judged under. Disjoint from
		// `notApplicableCategories`; the score is null in both cases. A category with no
		// `CheckResult` at all (`check === undefined`) is never inconclusive by this rule —
		// `isCompletedCheck` only answers the question for a check that actually ran.
		if (check !== undefined && !isCompletedCheck(check)) {
			inconclusiveCategories.push(category);
			categoryScores[category] = null;
			continue;
		}

		if (isCategoryNonApplicable(check, category, profile, rawScore)) {
			notApplicableCategories.push(category);
			categoryScores[category] = null;
		} else if (rawScore !== undefined) {
			categoryScores[category] = rawScore;
		}
		// If neither in sourceCategoryScores nor non-applicable, skip — preserves prior
		// "only keys with a score appear" behaviour.
	}

	// The RATIO is a fact about the checks this report is rendering, so derive it here
	// with the same exported helper the engine uses (one definition, no drift). The
	// VERDICT belongs to the scorer alone — the wire layer never re-decides whether a
	// scan was gradeable from these checks; it only reads `result.score.evidenceInsufficient`.
	//
	// The one thing the wire DOES enforce itself is the `evidence.attempted > 0` guard.
	// This is not a second opinion on the verdict: `computeScanScore`'s own zero-check
	// branch (checks.length === 0) stamps `evidenceInsufficient: true` on a result that
	// also has `measured: false` — a shape that, read naively, would violate this
	// interface's documented invariant that the two are mutually exclusive. The guard
	// refuses to RAISE the flag for the "nothing ran at all" state that `measured: false`
	// already owns; it never suppresses a true insufficiency the score actually raised
	// for a scan that attempted something (`evidence.attempted > 0` in every real
	// insufficiency case). `evidenceNote` is gated on this ENFORCED flag, not the raw
	// score flag, so it is non-null only when `evidenceInsufficient` is `true`.
	const evidence = computeScanEvidence(result.checks);
	const evidenceInsufficient = result.score.evidenceInsufficient === true && evidence.attempted > 0;

	return {
		domain: result.domain,
		score: result.score.overall,
		grade: displayGradeFor(result.score),
		passed: result.score.overall === null ? null : result.score.overall >= 50,
		measured: isMeasured(result.checks),
		// `?? null` alone is not enough: the three degraded builders all emit a
		// maturity OBJECT carrying a placeholder `stage: 0`, so the guard never
		// fires and a literal 0 — whose canonical label is "Unprotected" — reaches
		// any consumer charting this number or mapping it through its own
		// stage->label table. Gate on the scan having actually scored, exactly as
		// generate_fix_plan does one layer up. The LABEL is kept: "Does not resolve"
		// is information, not a fabricated verdict.
		// The `indeterminate` half is the #574 case, and `isGraded` cannot see it: the
		// scan IS graded (the affected hosts scored 67 with 17/19 checks completed —
		// a 0.894 evidence ratio, far over the 0.6 sufficiency threshold), yet the
		// ladder's one load-bearing input was never measured, so its stage number is
		// not a measurement either. Same treatment, same reason: withhold the NUMBER,
		// keep the LABEL.
		maturityStage: isGraded(result.score) && result.maturity?.indeterminate !== true ? (result.maturity?.stage ?? null) : null,
		maturityLabel: result.maturity?.label ?? null,
		categoryScores,
		findingCounts: {
			critical: result.score.findings.filter((f: Finding) => f.severity === 'critical').length,
			high: result.score.findings.filter((f: Finding) => f.severity === 'high').length,
			medium: result.score.findings.filter((f: Finding) => f.severity === 'medium').length,
			low: result.score.findings.filter((f: Finding) => f.severity === 'low').length,
		},
		findings: result.score.findings.map((f: Finding) => ({
			category: f.category,
			title: sanitizeOutputText(f.title),
			severity: f.severity,
			detail: f.detail,
		})),
		scoringProfile: result.context?.profile ?? 'mail_enabled',
		scoringSignals: (result.context?.signals ?? []).map((s: string) => s.replace(/[<>&"']/g, '')),
		scoringNote: result.scoringNote ?? null,
		adaptiveWeightDeltas: result.adaptiveWeightDeltas ?? null,
		percentileRank: enrichment?.percentileRank ?? null,
		spoofabilityScore: enrichment?.spoofabilityScore ?? null,
		interactionEffects: (result.interactionEffects ?? []).map((e) => ({
			ruleId: e.ruleId,
			penalty: e.penalty,
			narrative: e.narrative,
		})),
		checkStatuses,
		dnssecSource,
		cdnProvider,
		notApplicableCategories,
		inconclusiveCategories,
		evidence,
		evidenceInsufficient,
		evidenceNote: evidenceInsufficient ? (result.score.evidenceNote ?? null) : null,
		timestamp: result.timestamp,
		cached: result.cached,
		scoringModelVersion: SCORING_MODEL_VERSION,
		dnsChecksPackageVersion: DNS_CHECKS_PACKAGE_VERSION,
		// Three-step, most-specific-first: an explicitly threaded hash wins; else the
		// hash `scanDomain` stamped onto this very result (so a caller that passes no
		// enrichment — every npm-package consumer of this function — still reports the
		// config the scan actually ran under); only a hand-built result with neither
		// falls back to the `'default'` marker.
		scoringConfigHash: enrichment?.scoringConfigHash ?? result.scoringConfigHash ?? computeScoringConfigHash(),
		// Additive-optional: only emit `resolves` when known (omit otherwise so
		// tolerant downstream parsers see the same shape they always have).
		...(result.resolves !== undefined ? { resolves: result.resolves } : {}),
	};
}

export function formatScanReport(result: ScanDomainResult, format: OutputFormat = 'full'): string {
	const lines: string[] = [];

	const displayGrade = displayGradeFor(result.score);
	lines.push(`DNS Security Scan: ${result.domain}`);
	lines.push(`${'='.repeat(40)}`);
	lines.push(`Overall Score: ${formatScoreGrade(result.score.overall, displayGrade)}`);
	// The engine bakes the canonical 9-band grade into `summary` ("…Grade: X"); rewrite
	// that one token to the display (NIST) grade so the text never disagrees with the
	// score line above. No-op when the scan was never graded at all — the summary of a
	// degraded scan is a prose reason, not a graded verdict, and must survive verbatim.
	lines.push(
		displayGrade === null ? `${result.score.summary}` : result.score.summary.replace(/Grade: [A-F][+-]?/g, `Grade: ${displayGrade}`),
	);
	// Name the coverage gap explicitly. A reader must be able to see that a scan was
	// partial without reverse-engineering it from the category table.
	const reportEvidence = computeScanEvidence(result.checks);
	if (reportEvidence.attempted > 0 && reportEvidence.completed < reportEvidence.attempted) {
		// Floor, never round, the achieved percentage — the same rule `buildEvidenceNote`
		// (packages/dns-checks/src/scoring/evidence.ts) uses for the summary line above.
		// Rounding here while that helper floors let the SAME measurement render two
		// different percentages on consecutive lines (e.g. 11/19 = "57%" in the summary,
		// "58%" here) — a self-contradiction commit 33608fe1 already fixed once in
		// `buildEvidenceNote` itself; this is the sibling fix for this second renderer.
		lines.push(
			`Checks completed: ${reportEvidence.completed}/${reportEvidence.attempted} (${Math.floor(reportEvidence.ratio * 100)}%) — the rest did not complete`,
		);
	}
	lines.push('');

	if (result.maturity) {
		// The prose must abstain on exactly the condition `buildStructuredScanResult`
		// abstains on (`maturityStage: isGraded(...) ? stage : null`). The three degraded
		// builders all emit a maturity object carrying a PLACEHOLDER `stage: 0`, whose
		// canonical label is "Unprotected" — so an NXDOMAIN scan printed
		// "Stage 0 — Does not resolve" directly under "Overall Score: not measured",
		// while its own structuredContent said `maturityStage: null` and
		// generate_fix_plan said "not measured" for the same domain.
		//
		// The LABEL is kept either way: "Does not resolve" is information. Only the
		// NUMBER — the part that charts, sorts and maps through a stage table — is
		// withheld, and the ungraded token takes its place so the same state reads the
		// same way here as everywhere else. A GRADED domain that genuinely sits at
		// stage 0 still prints "Stage 0"; that zero is a measurement.
		//
		// #574 adds the second condition: a graded scan whose ladder abstained
		// (`indeterminate`) also has no stage NUMBER to print, for the same reason —
		// the number behind it is a placeholder, not a measurement. Its label carries
		// the state ("Not determined (TLS not measured)") and its description explains
		// the gap, so the reader loses nothing.
		const stageText =
			isGraded(result.score) && result.maturity.indeterminate !== true ? `Stage ${result.maturity.stage}` : UNGRADED_DISPLAY;
		if (format === 'compact') {
			lines.push(`Maturity: ${stageText} — ${result.maturity.label}`);
		} else {
			lines.push(`Email Security Maturity: ${stageText} — ${result.maturity.label}`);
			lines.push(result.maturity.description);
			if (result.maturity.nextStep) {
				lines.push(`Next step: ${result.maturity.nextStep}`);
			}
		}
		lines.push('');
	}

	if (format === 'full') {
		if (result.context) {
			const signalSummary = result.context.signals.length > 0 ? result.context.signals.join(', ') : 'default';
			lines.push(`Scoring Profile: ${result.context.profile} (${signalSummary})`);
			lines.push('');
		}

		if (result.scoringNote) {
			lines.push(result.scoringNote);
			lines.push('');
		}
	}

	// The prose table asks the SAME applicability question as `buildStructuredScanResult`
	// and must therefore ask it through the SAME predicate. It used to carry its own
	// hand-rolled copy scoped to `['spf','dmarc','dkim','mta_sts']`, which had already
	// drifted: `bimi`/`mx` were N/A with a null score in `structuredContent` while this
	// table printed them as a clean `100/100` for the same scan. One definition now, so
	// the two views cannot disagree again (#639).
	const profileForNa = result.context?.profile ?? 'mail_enabled';
	const checksByCategoryForNa = new Map<string, CheckResult>((result.checks ?? []).map((c) => [c.category, c]));

	lines.push('Category Scores:');
	lines.push('-'.repeat(30));
	const renderedCategories = new Set<string>();
	for (const [category, score] of Object.entries(result.score.categoryScores) as [string, number][]) {
		renderedCategories.add(category);
		const naCheck = checksByCategoryForNa.get(category);
		// An inconclusive check (timeout/error) is NOT "not applicable" — same precedence
		// as the structured builder, which short-circuits those before asking.
		const inconclusive = naCheck !== undefined && !isCompletedCheck(naCheck);
		if (inconclusive) {
			lines.push(formatUnmeasuredCategoryRow(category, naCheck));
			continue;
		}
		if (isCategoryNonApplicable(naCheck, category, profileForNa, score)) {
			lines.push(`  ∅ ${category.toUpperCase().padEnd(10)} N/A (no MX records — control does not apply)`);
			continue;
		}
		const status = score >= 80 ? '✓' : score >= 50 ? '⚠' : '✗';
		lines.push(`  ${status} ${category.toUpperCase().padEnd(10)} ${score}/100`);
	}
	// A check that timed out or errored is EXCLUDED from `categoryScores` by the scoring
	// engine — correctly, since it is renormalized out rather than scored a misleading 0
	// (see `computeScanScore`, whose own comment promises these are "shown as n/a, never a
	// misleading 0"). But nothing rendered them, so the category simply had NO ROW here and
	// a reader could not tell "passed the web checks" from "the web checks never ran" —
	// which is the common case, not the exotic one: across a 2,123-domain NZ corpus
	// `http_security` was measured on 1,579 and `ssl` on 1,741, and on Chinese domains `ssl`
	// failed 72.5%. The summary "Checks completed: N/M" line names the COUNT; this names
	// WHICH. `structuredContent` has always reported them via `inconclusiveCategories` plus a
	// null `categoryScores` entry, so this closes a prose-only gap and brings the two views
	// back into agreement (the same class of divergence as #639).
	//
	// Rendering only: no score, weight, severity or profile is read or written here, and the
	// rows added are for categories the score map does not contain.
	for (const check of result.checks ?? []) {
		if (renderedCategories.has(check.category) || isCompletedCheck(check)) continue;
		renderedCategories.add(check.category);
		lines.push(formatUnmeasuredCategoryRow(check.category, check));
	}
	lines.push('');

	const nonInfoFindings = result.score.findings.filter((finding: Finding) => finding.severity !== 'info');
	if (nonInfoFindings.length > 0) {
		lines.push('Findings:');
		lines.push('-'.repeat(30));
		for (const finding of nonInfoFindings) {
			if (format === 'compact') {
				const isHighPriority = finding.severity === 'critical' || finding.severity === 'high';
				const detailLimit = isHighPriority ? 4000 : 300;
				lines.push(
					`  [${finding.severity.toUpperCase()}] ${sanitizeOutputText(finding.title, 120)} — ${sanitizeOutputText(finding.detail, detailLimit)}`,
				);
				continue;
			}

			lines.push(`  [${finding.severity.toUpperCase()}] ${sanitizeOutputText(finding.title, 120)}`);
			lines.push(`    ${sanitizeOutputText(finding.detail)}`);
			const verificationStatus =
				finding.category === 'subdomain_takeover' && finding.metadata?.verificationStatus
					? String(finding.metadata.verificationStatus)
					: undefined;
			if (verificationStatus) {
				lines.push(`    Takeover Verification: ${sanitizeOutputText(verificationStatus, 80)}`);
			}
			const proofRequired =
				finding.category === 'subdomain_takeover' && finding.metadata?.proofRequired ? String(finding.metadata.proofRequired) : undefined;
			if (proofRequired) {
				lines.push(`    Proof Required: ${sanitizeOutputText(proofRequired, 120)}`);
			}
			const confidence = finding.metadata?.confidence ? String(finding.metadata.confidence) : undefined;
			if (confidence) {
				lines.push(`    Confidence: ${sanitizeOutputText(confidence, 80)}`);
			}
			const narrative = resolveImpactNarrative({
				category: finding.category,
				severity: finding.severity,
				title: finding.title,
				detail: finding.detail,
			});
			if (narrative.impact) {
				lines.push(`    Potential Impact: ${narrative.impact}`);
			}
			if (narrative.adverseConsequences) {
				lines.push(`    Adverse Consequences: ${narrative.adverseConsequences}`);
			}
		}
	} else {
		lines.push('No security issues found.');
	}

	if (format === 'full' && result.interactionEffects && result.interactionEffects.length > 0) {
		lines.push('');
		lines.push('Interaction Effects:');
		lines.push('-'.repeat(30));
		for (const effect of result.interactionEffects) {
			lines.push(`  [-${effect.penalty}] ${effect.narrative}`);
		}
	}

	if (result.cached) {
		lines.push('');
		lines.push('(Results served from cache)');
	}

	lines.push('');
	lines.push(`Scan completed: ${result.timestamp}`);
	if (format === 'full') {
		// Both stamps, labelled by what they track. The prose report is where the
		// namespace confusion of #707 started: "Scoring model: v1.10.0" alone reads
		// like the engine package version to anyone who vendors that package.
		lines.push(`Scoring model: v${SCORING_MODEL_VERSION} (scoring policy) | dns-checks package: v${DNS_CHECKS_PACKAGE_VERSION} (engine code)`);
	}
	return lines.join('\n');
}
