// SPDX-License-Identifier: BUSL-1.1

/**
 * Compare domains tool.
 * Scans 2–5 domains and produces a side-by-side comparison of their security posture.
 */

import { sanitizeDomain, validateDomain } from '../lib/sanitize';
import { scanDomain, buildStructuredScanResult } from './scan-domain';
import { computeScoringConfigHash } from '../lib/scoring-version';
import type { ScanRuntimeOptions } from './scan/post-processing';
import type { StructuredScanResult } from './scan/format-report';
import type { OutputFormat } from '../handlers/tool-args';
import { formatScoreGrade, UNGRADED_DISPLAY } from '../lib/ungraded-display';

/**
 * Wall-clock budget for the synchronous `compare_domains` tool path, threaded
 * into `compareDomains` as both `deadlineMs` and (where supported) a derived
 * `AbortSignal.timeout(...)`. Kept inside the handler's 28s
 * `TOOL_CALL_TIMEOUT_MS` race so the sequential scan loop bails out and
 * preserves any completed scans *before* the outer race rejects the whole
 * call. Mirrors the brand_audit_single / discover_brand_domains sync-handoff
 * margins.
 */
export const COMPARE_DOMAINS_SYNC_BUDGET_MS = 24_000;

export interface DomainComparisonResult {
	domains: string[];
	/** Domain with the highest overall score. Null on tie or if fewer than 2 valid results. */
	winner: string | null;
	/** Overall score per domain. `null` when the domain was not measured. */
	scores: Record<string, number | null>;
	/** Grade per domain. `null` when the domain was not measured. */
	grades: Record<string, string | null>;
	/**
	 * Per-category scores: [{ category, scores: { 'example.com': 100, 'test.com': 85 } }].
	 *
	 * Keyed ONLY by the domains that were actually measured — an unmeasured domain
	 * (NXDOMAIN, budget exceeded, scan threw) contributes no per-category claim at
	 * all rather than a key. A `null` value means the category was measured-as-
	 * not-applicable for that domain (e.g. MTA-STS on a non-mail domain); it is not
	 * a score of 0 and is skipped by every gap predicate and column below.
	 */
	categoryComparison: Array<{ category: string; scores: Record<string, number | null> }>;
	/** Categories where ALL measured domains score below 50. */
	commonGaps: string[];
	/** Categories where only one measured domain scores below 50 (unique weakness). */
	uniqueGaps: Array<{ domain: string; categories: string[] }>;
	/** Errors keyed by domain, for domains that failed validation or scanning. */
	errors: Record<string, string>;
	/**
	 * True when the deadline budget fired before all domains were scanned. The
	 * remaining (un-scanned) domains appear in `errors` with `budget_exceeded`.
	 */
	partial?: boolean;
}

/** Signature compatible with `scanDomain`. Exposed as an option for testing. */
type ScanFn = typeof scanDomain;

export interface CompareDomainsOptions {
	kv?: KVNamespace;
	runtimeOptions?: ScanRuntimeOptions;
	/**
	 * Optional abort signal forwarded to `scanDomain` if/when it gains
	 * cancellation support. Today scan-domain does not accept a signal, so this
	 * is reserved for future plumbing; the per-iteration deadline guard below
	 * is what actually bounds wall-clock for now.
	 */
	signal?: AbortSignal;
	/**
	 * Absolute wall-clock cut-off in ms (e.g. `Date.now() + 24_000`). When set,
	 * the scan loop checks the deadline before each `scanDomain` call and
	 * marks the result `partial: true` rather than running past the handler's
	 * 28s `TOOL_CALL_TIMEOUT_MS` race (which discards every completed scan).
	 */
	deadlineMs?: number;
	/** Override scanDomain for testing. Matches the `batch-scan` injection seam. */
	scanFn?: ScanFn;
}

/**
 * Scan 2–5 domains and compare their security posture.
 */
export async function compareDomains(rawDomains: string[], options: CompareDomainsOptions = {}): Promise<DomainComparisonResult> {
	if (rawDomains.length < 2) {
		throw new Error('compare_domains requires at least 2 domains');
	}
	if (rawDomains.length > 5) {
		throw new Error(`compare_domains accepts a max of 5 domains (received ${rawDomains.length})`);
	}

	const sanitized: string[] = [];
	const errors: Record<string, string> = {};

	for (const raw of rawDomains) {
		const validation = validateDomain(raw);
		if (!validation.valid) {
			errors[raw] = validation.error ?? 'Invalid domain';
			sanitized.push(raw);
		} else {
			sanitized.push(sanitizeDomain(raw));
		}
	}

	const structuredResults: Record<string, StructuredScanResult | null> = {};
	const scan = options.scanFn ?? scanDomain;
	let partial = false;

	for (const domain of sanitized) {
		if (errors[domain]) {
			structuredResults[domain] = null;
			continue;
		}
		// Deadline guard: stop *before* the next scanDomain await so we don't
		// blow past the handler's 28s TOOL_CALL_TIMEOUT_MS race and discard
		// already-completed scans. Remaining domains surface in `errors` with
		// `budget_exceeded`, mirroring batch_scan's neighbouring shape.
		if (options.deadlineMs !== undefined && Date.now() >= options.deadlineMs) {
			errors[domain] = 'budget_exceeded';
			structuredResults[domain] = null;
			partial = true;
			continue;
		}
		try {
			// scanDomain doesn't currently accept an AbortSignal; the deadline
			// guard above is the active bound. `options.signal` is held for the
			// day scan-domain plumbs cancellation through.
			const scanResult = await scan(domain, options.kv, options.runtimeOptions);
			structuredResults[domain] = buildStructuredScanResult(scanResult, {
				scoringConfigHash: computeScoringConfigHash(options.runtimeOptions?.scoringConfig),
			});
		} catch (err) {
			errors[domain] = err instanceof Error ? err.message : 'Scan failed';
			structuredResults[domain] = null;
		}
	}

	const validResults = Object.entries(structuredResults).filter((entry): entry is [string, StructuredScanResult] => entry[1] !== null);

	const scores: Record<string, number | null> = {};
	const grades: Record<string, string | null> = {};
	for (const [domain, r] of validResults) {
		// `measured === false` means this domain contributed no checks. The scan
		// producers now null its `score`/`grade` at the source, so this is a
		// belt-and-braces restatement of the invariant "unmeasured implies null" at
		// the DomainComparisonResult boundary: any future ScanScore source that
		// reintroduces a placeholder pair is still nulled here.
		scores[domain] = r.measured ? r.score : null;
		grades[domain] = r.measured ? r.grade : null;
	}

	// Winner: highest score among GRADED domains only. An unmeasured domain has no
	// score to compare, so it is excluded rather than sorted as 0. Null on tie or
	// fewer than 2 graded results.
	const rankable = validResults.filter(
		(e): e is [string, StructuredScanResult & { score: number }] => e[1].measured && e[1].score !== null,
	);
	let winner: string | null = null;
	if (rankable.length >= 2) {
		const sorted = [...rankable].sort((a, b) => b[1].score - a[1].score);
		if (sorted[0][1].score > sorted[1][1].score) {
			winner = sorted[0][0];
		}
	}

	// Category comparison — over the MEASURED domains only.
	//
	// The domain set is `measured`, not `rankable`: a scan whose checks all ran but
	// whose scoring bundle failed (`buildUnscoredResult`) has no overall score yet has
	// genuine per-category numbers, and dropping it would suppress a real measurement.
	// An unmeasured domain is the opposite case — `categoryScores` is `{}` — and the
	// old `?? 0` turned that absence into a full set of failing zeros: ~18 named
	// "unique weaknesses" for a domain nobody looked at, printed directly beneath its
	// own "not measured" line, AND (because a fabricated 0 sits in every OTHER
	// domain's `others` list) the deletion of the measured domain's real deficiencies
	// from `uniqueGaps`. Excluding it emits no per-category claim for it in any
	// channel: gaps, table, or `structuredContent.categoryComparison`.
	const measuredResults = validResults.filter(([, r]) => r.measured);

	const allCategories = new Set<string>();
	for (const [, r] of measuredResults) {
		Object.keys(r.categoryScores).forEach((c) => allCategories.add(c));
	}
	// `null`, never `0`, for a category this domain does not carry: absent from its
	// map (the category was not evaluated for this domain) or explicitly null (measured
	// as NOT APPLICABLE — MTA-STS on a non-mail domain). Both are "no score here", and
	// a `✗ 0` column is a failing verdict neither of them supports.
	const categoryComparison: DomainComparisonResult['categoryComparison'] = [...allCategories].map((category) => ({
		category,
		scores: Object.fromEntries(measuredResults.map(([d, r]) => [d, r.categoryScores[category] ?? null])),
	}));

	/** The scores a gap predicate may reason about: real numbers only. */
	const realScores = (scores: Record<string, number | null>, exclude?: string): number[] =>
		Object.entries(scores)
			.filter(([d]) => d !== exclude)
			.map(([, s]) => s)
			.filter((s): s is number => s !== null);

	// Common gaps: categories where EVERY domain that has a real score there fails.
	// `length > 0` is the non-vacuity guard — a category nobody scored is not a gap
	// shared by all.
	const commonGaps: string[] = categoryComparison
		.filter((cc) => {
			const scored = realScores(cc.scores);
			return scored.length > 0 && scored.every((s) => s < 50);
		})
		.map((cc) => cc.category);

	// Unique gaps: categories where exactly one measured domain scores below 50.
	const uniqueGaps: Array<{ domain: string; categories: string[] }> = [];
	for (const [domain] of measuredResults) {
		const unique = categoryComparison
			.filter((cc) => {
				const domScore = cc.scores[domain];
				// No score of its own → nothing to call a weakness (the old `?? 100`
				// silently asserted a passing score for an unevaluated category).
				if (domScore === null || domScore === undefined) return false;
				const others = realScores(cc.scores, domain);
				return domScore < 50 && others.length > 0 && others.every((s) => s >= 50);
			})
			.map((cc) => cc.category);
		if (unique.length > 0) {
			uniqueGaps.push({ domain, categories: unique });
		}
	}

	return {
		domains: sanitized,
		winner,
		scores,
		grades,
		categoryComparison,
		commonGaps,
		uniqueGaps,
		errors,
		...(partial ? { partial: true } : {}),
	};
}

/** Format comparison as a human-readable report. */
export function formatDomainComparison(result: DomainComparisonResult, format: OutputFormat = 'compact'): string {
	const lines: string[] = [];
	lines.push('Domain Security Comparison');
	lines.push('='.repeat(40));
	lines.push('');

	for (const domain of result.domains) {
		if (result.errors[domain]) {
			lines.push(`  ✗ ${domain.padEnd(40)} Error: ${result.errors[domain]}`);
			continue;
		}
		const score = result.scores[domain];
		const grade = result.grades[domain];
		if (score === null || score === undefined || grade === null || grade === undefined) {
			lines.push(`  · ${domain.padEnd(40)} not measured`);
			continue;
		}
		const icon = score >= 80 ? '✓' : score >= 50 ? '⚠' : '✗';
		const winMark = result.winner === domain ? ' ← best' : '';
		lines.push(`  ${icon} ${domain.padEnd(40)} ${formatScoreGrade(score, grade)}${winMark}`);
	}
	lines.push('');

	if (result.commonGaps.length > 0) {
		// "all domains" was true of the old predicate only because an unmeasured domain
		// was coerced to 0 and therefore always "failed". The predicate is now "every
		// domain that has a score in this category", so the sentence says that.
		lines.push(`Common gaps (all measured domains fail): ${result.commonGaps.join(', ')}`);
		lines.push('');
	}

	if (result.uniqueGaps.length > 0) {
		lines.push('Unique weaknesses:');
		for (const ug of result.uniqueGaps) {
			lines.push(`  ${ug.domain}: ${ug.categories.join(', ')}`);
		}
		lines.push('');
	}

	if (format === 'full' && result.categoryComparison.length > 0) {
		// Columns come from the comparison itself, in input order — NOT from
		// `domains.filter(d => !errors[d])`, which kept a column for a domain that
		// validated but was never measured and rendered `✗ 0` down every category for
		// it. `categoryComparison` is already keyed by the measured domains only, so a
		// domain with no key gets no column.
		const comparedDomains = result.domains.filter((d) => result.categoryComparison.some((cc) => d in cc.scores));
		if (comparedDomains.length > 0) {
			lines.push('Category Scores:');
			lines.push('-'.repeat(30));
			const header = '  Category'.padEnd(16) + comparedDomains.map((d) => d.substring(0, 18).padEnd(20)).join('');
			lines.push(header);
			for (const cc of result.categoryComparison) {
				const row =
					`  ${cc.category.toUpperCase().padEnd(14)}` +
					comparedDomains
						.map((d) => {
							const s = cc.scores[d];
							// A category with no score for this domain (not applicable, or not
							// evaluated) renders as the ungraded token — never as a failing 0.
							if (s === null || s === undefined) return `  ${UNGRADED_DISPLAY.padEnd(18)}`;
							const mark = s >= 80 ? '✓' : s >= 50 ? '⚠' : '✗';
							return `${mark} ${String(s).padEnd(18)}`;
						})
						.join('');
				lines.push(row);
			}
		}
	}

	return lines.join('\n');
}
