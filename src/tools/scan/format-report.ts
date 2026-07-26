// SPDX-License-Identifier: BUSL-1.1

import type { ScanDomainResult } from '../scan-domain';
import type { CheckResult, Finding } from '../../lib/scoring';
import { isGraded, nistScoreToGrade } from '../../lib/scoring';
import type { OutputFormat } from '../../handlers/tool-args';
import { sanitizeOutputText } from '../../lib/output-sanitize';
import { resolveImpactNarrative } from '../explain-finding';
import { SCORING_MODEL_VERSION, computeScoringConfigHash } from '../../lib/scoring-version';
import { formatScoreGrade, isMeasured, UNGRADED_DISPLAY } from '../../lib/ungraded-display';

// All three live in a tiny leaf module so every formatter in src/tools/ can share
// them without importing the scan orchestrator. Re-exported here because this is
// where consumers have always found UNGRADED_DISPLAY — new importers should take it
// from the leaf module directly.
export { UNGRADED_DISPLAY };

/**
 * The SINGLE customer-facing display grade for the scan-output tools
 * (`scan_domain` / `batch_scan` / `compare_domains`): the NIST-aligned 6-band
 * letter, recomputed from the unchanged 0-100 score. The engine's `score.grade`
 * stays on the canonical 9-band scale for every OTHER consumer (compare_baseline
 * ordering, the badge, drift/compliance/fix-plan); only these display surfaces
 * switch.
 *
 * Returns `null` when the scan was never graded — callers must render
 * {@link UNGRADED_DISPLAY} rather than substitute a letter. An unscored scan
 * yields `null`, rendered as {@link UNGRADED_DISPLAY}; mapping it onto
 * `nistScoreToGrade(0)` here would fabricate an 'F' for a domain that does not
 * resolve — the exact defect this slice exists to remove.
 */
function displayGradeFor(score: { overall: number | null; grade: string | null }): string | null {
	if (score.overall === null || score.grade === null) return null;
	return nistScoreToGrade(score.overall);
}

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
	scoringProfile: string;
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
	/** DNSSEC configuration source. 'domain_configured' = domain has own DNSKEY/DS; 'tld_inherited' = inherited from TLD registry. null = not yet available. */
	dnssecSource: 'domain_configured' | 'tld_inherited' | null;
	/** CDN provider detected from HTTP response headers. null when no CDN detected or check did not run. */
	cdnProvider: string | null;
	/**
	 * Categories the scan MEASURED and found genuinely inapplicable to this domain
	 * (no MX → mail-only categories under `web_only`/`non_mail`). Always reported as
	 * `null` in `categoryScores` to avoid a misleading 100 or 0.
	 *
	 * **Semantic change (dns-checks 1.7.0): this array is now DISJOINT from
	 * `inconclusiveCategories`.** It previously conflated two reasons — a deliberate
	 * skip and a measurement failure — and `inconclusiveCategories` was documented as a
	 * subset of it. A consumer that read this array as the union of "not scored" must
	 * now read `notApplicableCategories.concat(inconclusiveCategories)`.
	 */
	notApplicableCategories: string[];
	/**
	 * Categories whose `null` score is due to a measurement FAILURE — the check timed
	 * out or errored (`checkStatuses[cat]` is `'timeout'`/`'error'`) — rather than the
	 * control genuinely not applying. Treat these as "could not measure / retry later".
	 *
	 * **DISJOINT from `notApplicableCategories`** as of dns-checks 1.7.0 (previously a
	 * subset of it). The two states are deliberately separate: *inconclusive* means we
	 * could not measure it; *not applicable* means we measured and it does not apply.
	 * Both are `null` in `categoryScores`. Empty when every check ran.
	 */
	inconclusiveCategories: string[];
	timestamp: string;
	cached: boolean;
	/**
	 * Scoring-policy semver (distinct from package/server version) that produced
	 * this result — bumped whenever weights/severities/thresholds change. Pins the
	 * scoring model for report reproducibility. See `lib/scoring-version.ts`.
	 */
	scoringModelVersion: string;
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
 */
const MAIL_ONLY_CATEGORIES_FOR_NON_MAIL_PROFILE = new Set<string>(['dkim', 'mta_sts', 'bimi', 'mx']);
/** Email categories that current behaviour already downgrades to info under non-mail profiles. */
const EMAIL_CATEGORIES_HEURISTIC_NA = new Set<string>(['spf', 'dmarc', 'dkim', 'mta_sts']);

/**
 * Decide whether a single check should be reported as N/A given the active scoring profile.
 * The rules combined are the single source of truth that `categoryScores` and
 * `notApplicableCategories` both derive from (defect G — single-source CategoryEvaluation).
 *
 * This function answers ONLY "we measured, and it genuinely does not apply". It is never
 * asked about a check that failed to run: the caller short-circuits those into
 * `inconclusiveCategories` before reaching here. (A former "Rule 1" returned `true` for a
 * timed-out/errored check, which filed a MEASUREMENT FAILURE as a deliberate N/A — the
 * conflation this removal fixes.)
 */
function isCategoryNonApplicable(check: CheckResult | undefined, category: string, profile: string, score: number | undefined): boolean {
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

/** Optional enrichment data for structured scan results. */
export interface ScanResultEnrichment {
	percentileRank?: number | null;
	spoofabilityScore?: number | null;
	/**
	 * Precomputed fingerprint of the effective scoring config, threaded from the
	 * call site that holds the parsed config (`runtimeOptions.scoringConfig`). When
	 * omitted, `buildStructuredScanResult` falls back to the `'default'` marker.
	 */
	scoringConfigHash?: string;
}

/** Build a machine-readable structured result from a scan. */
export function buildStructuredScanResult(result: ScanDomainResult, enrichment?: ScanResultEnrichment): StructuredScanResult {
	// checkStatuses
	const checkStatuses: Record<string, 'completed' | 'timeout' | 'error'> = {};
	for (const check of result.checks) {
		checkStatuses[check.category] = check.checkStatus ?? 'completed';
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
		if (dnssecSource === null && dnssecCheck.passed && !dnssecDeficient && (checkStatuses['dnssec'] ?? 'completed') === 'completed') {
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
		const status = check?.checkStatus;

		// INCONCLUSIVE — the check timed out or threw, so we could not measure it. This is
		// checked FIRST and returns early, because it must win over any profile-based
		// applicability rule: a check that never ran cannot be declared inapplicable on the
		// strength of the profile it would have been judged under. Disjoint from
		// `notApplicableCategories`; the score is null in both cases.
		if (status === 'timeout' || status === 'error') {
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
		maturityStage: isGraded(result.score) ? (result.maturity?.stage ?? null) : null,
		maturityLabel: result.maturity?.label ?? null,
		categoryScores,
		findingCounts: {
			critical: result.score.findings.filter((f: Finding) => f.severity === 'critical').length,
			high: result.score.findings.filter((f: Finding) => f.severity === 'high').length,
			medium: result.score.findings.filter((f: Finding) => f.severity === 'medium').length,
			low: result.score.findings.filter((f: Finding) => f.severity === 'low').length,
		},
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
		timestamp: result.timestamp,
		cached: result.cached,
		scoringModelVersion: SCORING_MODEL_VERSION,
		scoringConfigHash: enrichment?.scoringConfigHash ?? computeScoringConfigHash(),
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
		const stageText = isGraded(result.score) ? `Stage ${result.maturity.stage}` : UNGRADED_DISPLAY;
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

	const isNonMailProfile = ['non_mail', 'web_only'].includes(result.context?.profile ?? '');
	const naEmailCategories = new Set(['spf', 'dmarc', 'dkim', 'mta_sts']);

	lines.push('Category Scores:');
	lines.push('-'.repeat(30));
	for (const [category, score] of Object.entries(result.score.categoryScores) as [string, number][]) {
		if (isNonMailProfile && naEmailCategories.has(category)) {
			const check = result.checks?.find((c) => c.category === category);
			const allInfo = check && check.findings.length > 0 && check.findings.every((f: Finding) => f.severity === 'info');
			const noFindings = !check || (check.findings.length === 0 && score === 100);
			if (allInfo || noFindings) {
				lines.push(`  ∅ ${category.toUpperCase().padEnd(10)} N/A (web-only, no MX records)`);
				continue;
			}
		}
		const status = score >= 80 ? '✓' : score >= 50 ? '⚠' : '✗';
		lines.push(`  ${status} ${category.toUpperCase().padEnd(10)} ${score}/100`);
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
		lines.push(`Scoring model: v${SCORING_MODEL_VERSION}`);
	}
	return lines.join('\n');
}
