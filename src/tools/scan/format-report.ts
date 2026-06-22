// SPDX-License-Identifier: BUSL-1.1

import type { ScanDomainResult } from '../scan-domain';
import type { CheckResult, Finding } from '../../lib/scoring';
import type { OutputFormat } from '../../handlers/tool-args';
import { sanitizeOutputText } from '../../lib/output-sanitize';
import { resolveImpactNarrative } from '../explain-finding';
import { SCORING_MODEL_VERSION, computeScoringConfigHash } from '../../lib/scoring-version';

/** Structured scan result for machine-readable consumption (e.g., CI/CD actions). */
export interface StructuredScanResult {
	domain: string;
	score: number;
	grade: string;
	passed: boolean;
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
	 * Categories that don't apply to this domain (no MX → mail-only categories under
	 * `web_only`/`non_mail`; check timed-out/errored → inconclusive). These categories
	 * are always reported as `null` in `categoryScores` to avoid the misleading 100 or 0.
	 * NOTE: this array deliberately conflates two reasons — a deliberate skip and a
	 * measurement failure. Use `inconclusiveCategories` (a subset) to tell them apart.
	 */
	notApplicableCategories: string[];
	/**
	 * Subset of `notApplicableCategories` whose `null` score is due to a transient
	 * measurement FAILURE (the check timed-out or errored, `checkStatuses[cat]` is
	 * `'timeout'`/`'error'`) rather than the control genuinely not applying to this
	 * domain. A consumer should treat these as "could not measure / retry later", not
	 * as a deliberate N/A. Always a subset: every entry here is also in
	 * `notApplicableCategories` and `null` in `categoryScores`. Empty when every check ran.
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
 * The two rules combined are the single source of truth that `categoryScores` and
 * `notApplicableCategories` both derive from (defect G — single-source CategoryEvaluation).
 */
function isCategoryNonApplicable(check: CheckResult | undefined, category: string, profile: string, score: number | undefined): boolean {
	// Rule 1: transient/inconclusive checks are always N/A (could not measure).
	if (check && (check.checkStatus === 'timeout' || check.checkStatus === 'error')) return true;

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
		if (dnssecSource === null && dnssecCheck.passed && (checkStatuses['dnssec'] ?? 'completed') === 'completed') {
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
		if (isCategoryNonApplicable(check, category, profile, rawScore)) {
			notApplicableCategories.push(category);
			// A category is "inconclusive" (could-not-measure) — rather than a deliberate
			// N/A — exactly when Rule 1 fired: its check timed-out or errored. Deriving it
			// here, inside the same branch that nulls the score, keeps `inconclusiveCategories`
			// a guaranteed subset of `notApplicableCategories` with a null `categoryScores`.
			if (check && (check.checkStatus === 'timeout' || check.checkStatus === 'error')) {
				inconclusiveCategories.push(category);
			}
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
		grade: result.score.grade,
		passed: result.score.overall >= 50,
		maturityStage: result.maturity?.stage ?? null,
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

	lines.push(`DNS Security Scan: ${result.domain}`);
	lines.push(`${'='.repeat(40)}`);
	lines.push(`Overall Score: ${result.score.overall}/100 (${result.score.grade})`);
	lines.push(`${result.score.summary}`);
	lines.push('');

	if (result.maturity) {
		if (format === 'compact') {
			lines.push(`Maturity: Stage ${result.maturity.stage} — ${result.maturity.label}`);
		} else {
			lines.push(`Email Security Maturity: Stage ${result.maturity.stage} — ${result.maturity.label}`);
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
