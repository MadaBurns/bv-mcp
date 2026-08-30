// SPDX-License-Identifier: BUSL-1.1

import {
	CATEGORY_TIERS,
	type CheckCategory,
	type CheckResult,
	type Finding,
	inferFindingConfidence,
	findingsIndicateMissingControl,
	type ScanScore,
} from './model';
import type { DomainContext } from './profiles';
import { detectDomainContext, getProfileWeights, PROFILE_CRITICAL_CATEGORIES, PROFILE_EMAIL_BONUS_ELIGIBLE } from './profiles';
import type { ScoringConfig } from './config';
import { DEFAULT_SCORING_CONFIG } from './config';
import { buildEvidenceNote, computeScanEvidence, isCheckMeasured, isEvidenceSufficient, EVIDENCE_SUFFICIENCY_THRESHOLD } from './evidence';
import { computeGenericScore } from './generic';
import type { DomainResolutionSignal } from './resolution';
import { buildUnresolvableNote, isMeasurableDomain, resolveScanResolutionState } from './resolution';
import type { GenericScoringContext, FindingSeverityCounts } from './generic';

interface ImportanceProfile {
	importance: number;
}

/**
 * Per-category importance used for REMEDIATION ORDERING — not for scoring.
 *
 * Its only consumer is `src/tools/generate-fix-plan.ts`, which ranks findings by
 * `IMPORTANCE_WEIGHTS[finding.category].importance` to decide what to fix first. No scoring
 * path reads it: the three-tier score weights every category from `PROFILE_WEIGHTS` (via
 * `getProfileWeights` / `DomainContext.weights`). Editing these numbers reshuffles a fix
 * plan; it does not move a single score.
 *
 * The name is misleading, and the deprecation note that used to sit here — redirecting readers
 * to the core/protective weight constants below — was doubly wrong: this table is live, and the
 * two it pointed at are the dead ones.
 *
 * Left un-renamed deliberately: it is a published npm export with an external call site.
 */
export const IMPORTANCE_WEIGHTS: Record<CheckCategory, ImportanceProfile> = {
	spf: { importance: 10 },
	dmarc: { importance: 16 },
	dkim: { importance: 10 },
	dnssec: { importance: 10 },
	ssl: { importance: 8 },
	mta_sts: { importance: 2 },
	ns: { importance: 0 },
	caa: { importance: 0 },
	subdomain_takeover: { importance: 3 },
	mx: { importance: 2 },
	bimi: { importance: 0 },
	tlsrpt: { importance: 1 },
	lookalikes: { importance: 0 },
	shadow_domains: { importance: 0 },
	txt_hygiene: { importance: 0 },
	http_security: { importance: 3 },
	dane: { importance: 1 },
	ptr: { importance: 1 },
	mx_reputation: { importance: 0 },
	srv: { importance: 0 },
	zone_hygiene: { importance: 0 },
	dane_https: { importance: 2 },
	svcb_https: { importance: 1 },
	subdomailing: { importance: 3 },
	brand_discovery: { importance: 0 },
	authoritative_dns_infra: { importance: 0 },
	dnskey_strength: { importance: 1 },
};

/**
 * Core-tier importance weights (SPF, DMARC, DKIM, DNSSEC, SSL).
 *
 * @deprecated NOT read at runtime — by anything. The doc comment this replaces asserted that
 * the three-tier scoring formula consumed it. That was false: the formula weights categories
 * from `DomainContext.weights` (i.e. `PROFILE_WEIGHTS` via `getProfileWeights`), and the only
 * config-sourced fallback (`buildGenericContext`'s `context === undefined` branch) reads
 * `ScoringConfig.coreWeights`, never this constant. A repo-wide search finds zero readers;
 * the sole importers are the barrel re-exports (`scoring/index.ts`, `src/lib/scoring.ts`).
 *
 * Retained rather than deleted ONLY because `@blackveil/dns-checks` is a published npm
 * package and this is part of its `./scoring` export surface — removal is a breaking change
 * for external consumers and is a major-version decision, not a cleanup. Editing these
 * numbers has no effect on any score. Use {@link PROFILE_WEIGHTS} / `ScoringConfig.profileWeights`.
 */
export const CORE_WEIGHTS: Record<string, number> = {
	dmarc: 16,
	dkim: 10,
	spf: 10,
	dnssec: 10,
	ssl: 8,
	authoritative_dns_infra: 0,
};

/**
 * Protective-tier importance weights.
 *
 * @deprecated NOT read at runtime — carried the same false scoring-formula claim, and has the
 * same zero-reader status, as {@link CORE_WEIGHTS}; see that doc for the full rationale and for
 * why it is kept on the published surface rather than deleted.
 */
export const PROTECTIVE_WEIGHTS: Record<string, number> = {
	subdomain_takeover: 4,
	http_security: 3,
	mta_sts: 3,
	subdomailing: 3,
	mx: 2,
	caa: 2,
	ns: 2,
	lookalikes: 2,
	shadow_domains: 2,
};

/** Map numeric score to letter grade */
export function scoreToGrade(score: number, config?: ScoringConfig): string {
	const g = config?.grades ?? DEFAULT_SCORING_CONFIG.grades;
	if (score >= g.aPlus) return 'A+';
	if (score >= g.a) return 'A';
	if (score >= g.bPlus) return 'B+';
	if (score >= g.b) return 'B';
	if (score >= g.cPlus) return 'C+';
	if (score >= g.c) return 'C';
	if (score >= g.dPlus) return 'D+';
	if (score >= g.d) return 'D';
	return 'F';
}

/**
 * Narrow a {@link ScanScore} to one that carries a real measurement.
 *
 * `false` means the scan produced no gradeable result at all — the correct
 * response is to ABSTAIN (skip the rule, omit the entry, render "not measured"),
 * never to substitute a default. Substituting `0`/`'F'` is the fabricated-grade
 * defect this guard exists to prevent.
 */
export function isGraded(score: ScanScore): score is ScanScore & { overall: number; grade: string } {
	return score.overall !== null && score.grade !== null;
}

/** The 6 letters the NIST-aligned DISPLAY scale can emit. */
export type NistGrade = 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';

/**
 * NIST-aligned 6-band thresholds — the SINGLE customer-facing DISPLAY scale that
 * BlackVeil products consolidated on (2026-06-29). This is intentionally DISTINCT
 * from the canonical 9-band {@link scoreToGrade}, which stays for internal logic,
 * back-compat, and cohort/percentile math (and any third-party lib consumer). The
 * score is unchanged; only which letter a customer-facing surface displays.
 */
export const NIST_GRADE_THRESHOLDS = {
	A_PLUS: 95,
	A: 90,
	B: 80,
	C: 70,
	D: 60,
} as const;

/** Map a 0-100 score to the NIST-aligned 6-band DISPLAY grade. Pure; no config. */
export function nistScoreToGrade(score: number): NistGrade {
	if (score >= NIST_GRADE_THRESHOLDS.A_PLUS) return 'A+';
	if (score >= NIST_GRADE_THRESHOLDS.A) return 'A';
	if (score >= NIST_GRADE_THRESHOLDS.B) return 'B';
	if (score >= NIST_GRADE_THRESHOLDS.C) return 'C';
	if (score >= NIST_GRADE_THRESHOLDS.D) return 'D';
	return 'F';
}

/** Default critical categories used when no context is provided. */
const DEFAULT_CRITICAL_CATEGORIES: CheckCategory[] = ['spf', 'dmarc', 'dkim', 'ssl'];

/**
 * Build a GenericScoringContext from CheckResult[] + DomainContext.
 *
 * This bridges the concrete bv-mcp types (CheckResult, CheckCategory, Finding)
 * to the generic scoring engine's string-keyed inputs.
 */
function buildGenericContext(
	results: CheckResult[],
	categoryScores: Record<CheckCategory, number>,
	allFindings: Finding[],
	context: DomainContext | undefined,
	config: ScoringConfig,
): GenericScoringContext {
	// --- Build weights map (flat importance values) ---
	const weights: Record<string, number> = {};

	if (context) {
		for (const category of Object.keys(context.weights) as CheckCategory[]) {
			weights[category] = context.weights[category].importance;
		}
	} else {
		// Merge core + protective from config; hardening categories get 0
		for (const [key, value] of Object.entries(config.coreWeights)) {
			weights[key] = value;
		}
		for (const [key, value] of Object.entries(config.protectiveWeights)) {
			weights[key] = value;
		}
		// Ensure hardening categories are in weights (with 0 from config defaults)
		for (const cat of Object.keys(CATEGORY_TIERS) as CheckCategory[]) {
			if (CATEGORY_TIERS[cat] === 'hardening' && !(cat in weights)) {
				weights[cat] = 0;
			}
		}
	}

	// --- Build missingControls map ---
	// Only mark a category as missing when an actual result exists and
	// findingsIndicateMissingControl returns true. Absent categories must NOT
	// be marked missing — the original engine's critical gap ceiling check
	// requires an actual result (`result && findingsIndicateMissingControl(...)`),
	// and absent categories default to 100 with no zeroing.
	//
	// Only a MEASURED check may assert absence. An errored/timed-out check's synthetic
	// findings must never arm the critical-gap ceiling: a failed measurement cannot prove
	// a control is missing (#638's rule, applied to this map like its siblings below).
	// Without the gate, an error message that happens to contain "not found"/"no … record"
	// — `buildDnsErrorResult` passes upstream DnsQueryError text through verbatim under its
	// "DNS query" prefix — would cap a scan at the ceiling for a category the same scan
	// excluded as inconclusive.
	const missingControls: Record<string, boolean> = {};
	const resultMap = new Map<CheckCategory, CheckResult>();
	for (const result of results) {
		resultMap.set(result.category, result);
		if (isCheckMeasured(result.checkStatus) && findingsIndicateMissingControl(result.findings)) {
			missingControls[result.category] = true;
		}
	}

	// --- Build transientFailures map ---
	// A check whose execution failed (checkStatus 'timeout'/'error', or any other non-measured
	// status) is INCONCLUSIVE — we couldn't measure it. That is distinct from a genuinely-missing
	// control (missingControl). Exclude inconclusive categories from the weighted score
	// (renormalized over the rest) rather than scoring them 0, so a transient fetch/DNS failure
	// doesn't make the overall score fluctuate. See generic.ts: transientFailures keys are
	// skipped in the tier partition. Uses the shared `isCheckMeasured` allowlist predicate (see
	// evidence.ts) rather than a local denylist: a `checkStatus` value outside the closed
	// 'completed'|'timeout'|'error' union (reachable via an unvalidated cache re-read) must also
	// be excluded here, not silently treated as measured and scored at full weight.
	const transientFailures: Record<string, boolean> = {};
	for (const result of results) {
		if (!isCheckMeasured(result.checkStatus)) {
			transientFailures[result.category] = true;
		}
	}

	// A category that produced no result was not submitted by this scan roster. Exclude it
	// uniformly regardless of tier: it is neither a weighted result nor a hardening failure.
	for (const cat of Object.keys(CATEGORY_TIERS) as CheckCategory[]) {
		if (!resultMap.has(cat)) {
			transientFailures[cat] = true;
		}
	}

	// --- Build hardeningPassed map ---
	// The generic engine derives the hardening denominator from the keys in this map. Add only
	// submitted, measured hardening results. A measured failure therefore remains a `false` key,
	// while omitted and inconclusive categories are excluded.
	const hardeningPassed: Record<string, boolean> = {};
	for (const result of results) {
		if (CATEGORY_TIERS[result.category] === 'hardening' && isCheckMeasured(result.checkStatus)) {
			hardeningPassed[result.category] = result.passed && result.score >= 50;
		}
	}

	// --- Extract provider confidence from findings metadata ---
	const providerConfidence: Record<string, number> = {};
	for (const finding of allFindings) {
		const confidence = finding.metadata?.providerConfidence;
		if (typeof confidence === 'number' && Number.isFinite(confidence)) {
			// Use a synthetic key per finding to preserve the original per-finding averaging behavior.
			// The original engine averages ALL providerConfidence values across all findings.
			// The generic engine averages all values in the providerConfidence map.
			const key = `_finding_${Object.keys(providerConfidence).length}`;
			providerConfidence[key] = confidence;
		}
	}

	// --- Build finding severity counts ---
	// Critical penalty: original only counts findings with severity=critical AND confidence=verified.
	// Generic applies penalty when findingSeverityCounts.critical > 0.
	// To match: pass only verified critical findings as the critical count.
	const verifiedCriticalCount = allFindings.filter((f) => f.severity === 'critical' && inferFindingConfidence(f) === 'verified').length;

	// For critical penalty equivalence, use verified-only count as the "critical" count.
	// The original engine only applies the penalty for verified critical findings.
	const findingSeverityCounts: FindingSeverityCounts = {
		critical: verifiedCriticalCount,
		high: allFindings.filter((f) => f.severity === 'high').length,
		medium: allFindings.filter((f) => f.severity === 'medium').length,
		low: allFindings.filter((f) => f.severity === 'low').length,
		info: allFindings.filter((f) => f.severity === 'info').length,
	};

	// --- Critical categories ---
	const criticalCategories = context ? PROFILE_CRITICAL_CATEGORIES[context.profile] : DEFAULT_CRITICAL_CATEGORIES;

	// --- Email bonus eligibility ---
	// Original engine requires actual SPF and DMARC results to exist for the bonus
	// (!!spfResult && !!dmarcResult). Absent DKIM qualifies (dkimNotDeterministicallyMissing = !dkimResult || ...).
	// Disable email bonus entirely when SPF or DMARC has no result to match original behavior.
	let emailBonusEligible = context ? PROFILE_EMAIL_BONUS_ELIGIBLE[context.profile] : true;
	if (!resultMap.has('spf') || !resultMap.has('dmarc')) {
		emailBonusEligible = false;
	}

	// --- Build the summary-compatible severity counts ---
	// The original summary uses ALL critical findings (not just verified) for the summary text.
	// We store the "display" counts separately and use them to override the summary after scoring.
	// (The findingSeverityCounts above has verifiedCriticalCount for the penalty calculation.)

	return {
		categoryScores: { ...categoryScores },
		tierMap: { ...CATEGORY_TIERS },
		weights,
		missingControls,
		transientFailures,
		hardeningPassed,
		criticalCategories: [...criticalCategories],
		emailBonusEligible,
		providerConfidence: Object.keys(providerConfidence).length > 0 ? providerConfidence : undefined,
		findingSeverityCounts,
	};
}

/**
 * Compute the overall scan score from individual check results using the three-tier formula.
 *
 * Delegates to `computeGenericScore` internally, building a `GenericScoringContext` from
 * the concrete `CheckResult[]` and optional `DomainContext`.
 *
 * Three tiers:
 * - **Core** (default 70 points): Weighted accumulation of foundational categories (SPF, DMARC, DKIM, DNSSEC, SSL).
 *   `findingsIndicateMissingControl()` can zero a category's contribution from structured intent or deterministic/verified prose.
 * - **Protective** (default 20 points): Weighted accumulation of active defense categories.
 *   No `findingsIndicateMissingControl()` override.
 * - **Hardening** (default 10 points): Binary pass/fail — each category with score >= 50 contributes
 *   `tierSplit.hardening / hardeningCount` points. Never subtracts.
 *
 * When a `DomainContext` is provided, uses profile-specific weights partitioned by CATEGORY_TIERS,
 * critical gap categories, and email bonus eligibility instead of defaults.
 */
/** Per-scan inputs that are neither check results nor scoring policy. */
export interface ScanScoreOptions {
	/**
	 * Explicit resolution signal from the caller's own apex probe.
	 *
	 * Accepts bv-mcp's orchestrator tri-state verbatim (`true` / `false` / `'broken'`) as
	 * well as the package-native spellings. When supplied it WINS over the derived floor —
	 * an apex probe is better evidence than inference from the roster.
	 *
	 * OPTIONAL BY DESIGN, and the guard does not depend on it: omitting it falls back to
	 * {@link deriveResolutionState}. A guard that fires only on an explicit input is
	 * silently disabled by a producer that forgets to pass it.
	 */
	resolution?: DomainResolutionSignal;
}

export function computeScanScore(
	results: CheckResult[],
	context?: DomainContext,
	config?: ScoringConfig,
	options?: ScanScoreOptions,
): ScanScore {
	// Only categories that produced a conclusive result appear here. A category that was NEVER
	// run (absent from `results`) is "not measured", NOT a perfect 100 — seeding it to 100 both
	// showed a misleading phantom score (a never-run category read as clean) and, via the generic
	// engine's `?? 100` default, silently awarded it full weight, masking real findings the
	// dedicated deep-scan tools surface (e.g. lookalikes/shadow_domains are excluded from the
	// scan_domain roster). Transient (timeout/error) checks are likewise excluded. See
	// buildGenericContext, which excludes both classes from the weighted overall (renormalized).
	const categoryScores: Partial<Record<CheckCategory, number>> = {};
	const allFindings: Finding[] = [];

	const cfg = config ?? DEFAULT_SCORING_CONFIG;
	// The `?? EVIDENCE_SUFFICIENCY_THRESHOLD` fallback is deliberate — a consumer
	// vendoring an older copy of this package (or hand-building a `ScoringConfig`
	// that predates this key) can hand us a `thresholds` object with no
	// `evidenceSufficiency` property at all, i.e. `undefined`, which `??` catches
	// and replaces with the constant.
	//
	// The [0, 1] clamp below is a SECOND enforcement of the same rule `config.ts`
	// already applies inside `parseScoringConfig` — that clamp only runs for
	// configs that were parsed from a `SCORING_CONFIG` JSON string. `computeScanScore`
	// is a published, directly-callable API: a caller can hand-build a `ScoringConfig`
	// object and pass it straight in, bypassing `parseScoringConfig` (and its clamp)
	// entirely. Without clamping here too, a hand-built `{ thresholds: {
	// evidenceSufficiency: 60 } }` (an operator's percent-not-ratio typo) would ungrade
	// every scan that reaches this function directly, not just every scan that goes
	// through env-var config parsing. `??` runs FIRST so a missing key still falls back
	// to the named constant before the clamp ever sees it.
	//
	// The `Number.isFinite` guard handles a THIRD hand-built shape `??` cannot catch:
	// a non-null but non-finite value, e.g. `evidenceSufficiency: Number(undefined)`
	// (NaN) from a consumer's own coercion bug. `??` only substitutes on `null`/
	// `undefined`, so a NaN sails past it straight into `Math.max(0, Math.min(1, NaN))`,
	// which is itself NaN — and `ratio >= NaN` is `false` for every ratio, so the gate
	// would fire on EVERY scan, ungrading the whole fleet from a single bad config value.
	// A non-finite threshold is treated the same as a missing one: fall back to the
	// named constant instead of clamping garbage.
	const rawEvidenceThreshold = cfg.thresholds.evidenceSufficiency ?? EVIDENCE_SUFFICIENCY_THRESHOLD;
	const evidenceThreshold = Math.max(
		0,
		Math.min(1, Number.isFinite(rawEvidenceThreshold) ? rawEvidenceThreshold : EVIDENCE_SUFFICIENCY_THRESHOLD),
	);

	if (results.length === 0) {
		// Zero submitted evidence is NEVER sufficient, unconditionally — this is not a
		// policy knob. A published SSOT must not hand a confident grade (the legacy
		// seeded 100/'A+') to a caller that submitted nothing to measure. See
		// evidence.ts's `isEvidenceSufficient` doc for the same invariant.
		const evidence = { attempted: 0, completed: 0, ratio: 0 };
		const evidenceNote = buildEvidenceNote(evidence, evidenceThreshold);
		return {
			overall: null,
			grade: null,
			categoryScores: categoryScores as Record<CheckCategory, number>,
			findings: [],
			summary: evidenceNote,
			evidence,
			evidenceInsufficient: true,
			evidenceNote,
		};
	}

	// --- Non-resolving domain gate ---
	// Runs BEFORE any scoring work, because on a domain that does not resolve the check
	// results are not weak evidence — they are anti-evidence. A dead name has no bad DNSSEC
	// to find, no dangling CNAME to take over, no lax DANE record, so those checks score 100
	// for the absence of problems only a real domain could have. No weighting of those
	// numbers is correct, because the premise that they measure something is false.
	//
	// Explicit signal wins; otherwise the derived floor reads it off the roster, so a
	// producer that forgets to pass one still gets the guard. See scoring/resolution.ts.
	//
	// Returns EMPTY categoryScores and findings, matching the reference implementation this
	// generalizes (bv-mcp `buildNonResolvingResult`): the per-check numbers on a dead domain
	// are fabricated passes, and laundering them through the score object invites a consumer
	// to publish "dnssec: 100" for a name that does not exist. The caller still holds the raw
	// results if it wants to display them as diagnostics.
	const resolutionState = resolveScanResolutionState(results, options?.resolution);
	if (!isMeasurableDomain(resolutionState)) {
		const evidenceNote = buildUnresolvableNote(resolutionState as 'nxdomain' | 'unresolvable');
		return {
			overall: null,
			grade: null,
			categoryScores: {} as Record<CheckCategory, number>,
			findings: [],
			summary: evidenceNote,
			evidence: computeScanEvidence(results),
			evidenceInsufficient: true,
			evidenceNote,
		};
	}

	// Populate category scores from actual results. Transient (checkStatus 'timeout'/'error',
	// or any other non-measured status) checks are INCONCLUSIVE — omitted from the
	// category-score output (shown as n/a, never a misleading 0) and from the finding counts;
	// buildGenericContext also excludes them from the weighted overall score via
	// transientFailures. Uses the shared `isCheckMeasured` allowlist predicate so an
	// out-of-union `checkStatus` doesn't slip through here and land a garbage/stale `score`
	// (or worse, `generic.ts`'s `?? 100` default for a missing one) as full category credit.
	for (const result of results) {
		if (!isCheckMeasured(result.checkStatus)) {
			continue;
		}
		categoryScores[result.category] = result.score;
		allFindings.push(...result.findings);
	}

	// Build the generic context and delegate to the generic engine. `categoryScores` is a partial
	// map (never-run + transient categories are absent); the generic engine treats absent scored
	// keys via `transientFailures` exclusion, so the widening cast is runtime-safe.
	const genericContext = buildGenericContext(results, categoryScores as Record<CheckCategory, number>, allFindings, context, cfg);
	const genericResult = computeGenericScore(genericContext, config);

	// --- Build summary using original logic ---
	// The original summary uses ALL critical findings (not just verified ones used for penalty).
	const criticalCount = allFindings.filter((f) => f.severity === 'critical').length;
	const highCount = allFindings.filter((f) => f.severity === 'high').length;
	const totalIssues = allFindings.filter((f) => f.severity !== 'info').length;

	let summary: string;
	if (totalIssues === 0) {
		summary = `Excellent! No security issues found. Grade: ${genericResult.grade}`;
	} else if (criticalCount > 0) {
		summary = `${criticalCount} critical issue(s) found requiring immediate attention. Grade: ${genericResult.grade}`;
	} else if (highCount > 0) {
		summary = `${highCount} high-severity issue(s) found. Grade: ${genericResult.grade}`;
	} else {
		summary = `${totalIssues} issue(s) found. Grade: ${genericResult.grade}`;
	}

	// --- Evidence-sufficiency gate ---
	// When most checks could not RUN, any letter grade would describe the scan's own
	// failure rather than the domain's posture. Withhold it. findings and categoryScores
	// are still returned: everything that WAS measured stays available to the caller.
	const evidence = computeScanEvidence(results);
	if (!isEvidenceSufficient(evidence, evidenceThreshold)) {
		const evidenceNote = buildEvidenceNote(evidence, evidenceThreshold);
		return {
			overall: null,
			grade: null,
			categoryScores: categoryScores as Record<CheckCategory, number>,
			findings: allFindings,
			summary: evidenceNote,
			tierBreakdown: genericResult.tierBreakdown,
			evidence,
			evidenceInsufficient: true,
			evidenceNote,
		};
	}

	return {
		overall: genericResult.overall,
		grade: genericResult.grade,
		categoryScores: categoryScores as Record<CheckCategory, number>,
		findings: allFindings,
		summary,
		tierBreakdown: genericResult.tierBreakdown,
		evidence,
	};
}

export interface ProfileAwareScanScore {
	score: ScanScore;
	context: DomainContext;
	profile: DomainContext['profile'];
	detectedProfile: DomainContext['profile'];
	scoringPolicyVersion: string;
}

export function computeProfileAwareScanScore(
	results: CheckResult[],
	options: { profile?: DomainContext['profile'] | 'auto'; config?: ScoringConfig; resolution?: DomainResolutionSignal } = {},
): ProfileAwareScanScore {
	const detectedContext = detectDomainContext(results);
	const explicitProfile = options.profile && options.profile !== 'auto' ? options.profile : null;
	const context: DomainContext = explicitProfile
		? {
				...detectedContext,
				profile: explicitProfile,
				signals: [...detectedContext.signals, `explicit profile override: ${explicitProfile}`],
				weights: getProfileWeights(explicitProfile, options.config),
			}
		: {
				...detectedContext,
				weights: getProfileWeights(detectedContext.profile, options.config),
			};

	return {
		score: computeScanScore(results, context, options.config, { resolution: options.resolution }),
		context,
		profile: context.profile,
		detectedProfile: detectedContext.profile,
		scoringPolicyVersion: 'dns-checks-scoring-v1',
	};
}
