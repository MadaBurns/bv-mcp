// SPDX-License-Identifier: BUSL-1.1

/**
 * Batch scan tool.
 * Runs scan_domain on up to 10 domains with bounded concurrency and a global
 * wall-clock budget so a single slow domain can't consume the entire Worker
 * request budget.
 */

import { sanitizeDomain, validateDomain } from '../lib/sanitize';
import { scanDomain, buildStructuredScanResult } from './scan-domain';
import { SCORING_MODEL_VERSION, computeScoringConfigHash } from '../lib/scoring-version';
import { DNS_CHECKS_PACKAGE_VERSION } from '../lib/dns-checks-version';
import type { ScanRuntimeOptions } from './scan/post-processing';
import type { StructuredScanResult } from './scan/format-report';
import type { OutputFormat } from '../handlers/tool-args';
import { formatScoreGrade } from '../lib/ungraded-display';
import { Semaphore } from '../lib/semaphore';

export interface BatchScanResultItem extends StructuredScanResult {
	error?: string;
}

/** Signature compatible with `scanDomain`. Exposed as an option for testing. */
type ScanFn = typeof scanDomain;

export interface CompactBatchScanResultItem {
	domain: string;
	score: number | null;
	grade: string | null;
	measured: boolean;
	findingCounts: StructuredScanResult['findingCounts'];
	categoryScores: StructuredScanResult['categoryScores'];
	scoringProfile: string | null;
	evidence: StructuredScanResult['evidence'];
	error?: string;
}

/** Compact wire payload for bulk triage; use `format: "full"` for complete findings. */
export interface CompactBatchScanResult {
	results: CompactBatchScanResultItem[];
	/**
	 * TRUE when one or more domains hit the batch wall-clock budget and were never
	 * scanned — their rows carry `measured: false, error: 'batch_budget_exceeded'`.
	 * An unmissable BATCH-LEVEL flag so a caller that does not inspect every row's
	 * `measured` flag cannot silently treat the budget-dropped tail as unscored/zero.
	 */
	incomplete: boolean;
	/**
	 * Domains that hit the batch budget and were NOT scanned, in input order. These
	 * are recoverable: re-run them in a smaller follow-up batch. Empty (`[]`) when the
	 * whole batch completed. Distinct from invalid-input errors, which are not listed here.
	 */
	unscanned: string[];
	/** Scoring-POLICY semver. ⚠️ Not the npm package version — see `dnsChecksPackageVersion` (#707). */
	scoringModelVersion: string;
	/** `@blackveil/dns-checks` engine-package version bundled by this build (#707). */
	dnsChecksPackageVersion: string;
	/** Recommended reproducibility anchor to record alongside a published score. */
	scoringConfigHash: string;
}

export interface BatchScanOptions {
	force_refresh?: boolean;
	kv?: KVNamespace;
	runtimeOptions?: ScanRuntimeOptions;
	/** Wall-clock budget for the entire batch, ms. Default 25_000 (leaves 5s Worker headroom). */
	budgetMs?: number;
	/** Max parallel scans. Default 3 (scan_domain is already 16× parallel internally). */
	concurrency?: number;
	/** Override scanDomain for testing. */
	scanFn?: ScanFn;
}

const DEFAULT_BUDGET_MS = 25_000;
const DEFAULT_CONCURRENCY = 3;
const BATCH_DNS_CONCURRENCY = 5;
const MAX_DOMAINS = 10;

/**
 * Placeholder for a domain that was NEVER MEASURED — invalid input, batch budget
 * exceeded before the scan started, or the scan threw. It carries no score, no
 * grade and no verdict, because none were observed. Emitting `score: 0, grade: 'F'`
 * here (the pre-3.35.0 behaviour) published a fabricated failing measurement about
 * a real named organisation into customer reports.
 */
function emptyResult(domain: string, error: string, scoringConfigHash: string): BatchScanResultItem {
	return {
		domain,
		score: null,
		grade: null,
		passed: null,
		measured: false,
		maturityStage: null,
		maturityLabel: null,
		categoryScores: {},
		findingCounts: { critical: 0, high: 0, medium: 0, low: 0 },
		findings: [],
		scoringProfile: null,
		scoringSignals: [],
		scoringNote: null,
		adaptiveWeightDeltas: null,
		percentileRank: null,
		spoofabilityScore: null,
		interactionEffects: [],
		checkStatuses: {},
		dnssecSource: null,
		cdnProvider: null,
		notApplicableCategories: [],
		inconclusiveCategories: [],
		// Nothing ran, so there is no evidence to report. `evidenceInsufficient` stays
		// FALSE deliberately: that flag means "checks ran but too few completed". The
		// "nothing ran at all" state is carried by `measured: false`, and the two are
		// mutually exclusive by contract.
		evidence: { attempted: 0, completed: 0, ratio: 0 },
		evidenceInsufficient: false,
		evidenceNote: null,
		timestamp: new Date().toISOString(),
		cached: false,
		// No scan ran for an error placeholder (invalid domain / budget exceeded), but the
		// batch itself DID run under a scoring config — stamp that config's fingerprint,
		// not the `'default'` marker. Stamping `'default'` while a live `SCORING_CONFIG`
		// override was in force made the placeholder claim a reproducibility it could not
		// back, and made an error item disagree with its own siblings in the same batch.
		scoringModelVersion: SCORING_MODEL_VERSION,
		dnsChecksPackageVersion: DNS_CHECKS_PACKAGE_VERSION,
		scoringConfigHash,
		error,
	};
}

/**
 * A scan that returned without recording a check is not equivalent to an apex
 * NXDOMAIN/broken-DNS short circuit. The latter explicitly sets `resolves`; the
 * former is an execution failure worth retrying, even when no exception escaped.
 */
function markUnexpectedNoEvidence(result: BatchScanResultItem): BatchScanResultItem {
	if (
		result.evidence.attempted > 0 ||
		result.score !== null ||
		result.grade !== null ||
		result.resolves === false ||
		result.resolves === 'broken'
	) {
		return result;
	}

	return {
		...result,
		scoringProfile: null,
		evidenceInsufficient: true,
		evidenceNote: 'No checks ran for a domain whose DNS resolution was not reported as absent or broken; retry the scan.',
		error: 'scan_produced_no_evidence',
	};
}

/**
 * Scan multiple domains with bounded concurrency and a global time budget.
 * Returns one structured result per input domain, in input order.
 * Invalid domains and budget-exceeded scans produce an error result instead of throwing.
 */
export async function batchScan(domains: string[], options: BatchScanOptions = {}): Promise<BatchScanResultItem[]> {
	if (domains.length > MAX_DOMAINS) {
		throw new Error(`Batch scan accepts a max of ${MAX_DOMAINS} domains per request (received ${domains.length})`);
	}

	const budgetMs = options.budgetMs ?? DEFAULT_BUDGET_MS;
	const concurrency = Math.max(1, Math.min(options.concurrency ?? DEFAULT_CONCURRENCY, domains.length || 1));
	const scan = options.scanFn ?? scanDomain;
	const deadline = Date.now() + budgetMs;
	const dnsSemaphore = options.runtimeOptions?.dnsSemaphore ?? new Semaphore(BATCH_DNS_CONCURRENCY);
	// One fingerprint for the whole batch — every item (scanned or placeholder) is
	// produced under the same effective scoring config.
	const scoringConfigHash = computeScoringConfigHash(options.runtimeOptions?.scoringConfig);

	const results: BatchScanResultItem[] = new Array(domains.length);
	const pending: Array<{ idx: number; domain: string }> = [];

	// Fast path: validate all inputs up front; invalid domains never occupy a worker slot.
	for (let i = 0; i < domains.length; i++) {
		const raw = domains[i];
		const validation = validateDomain(raw);
		if (!validation.valid) {
			results[i] = emptyResult(raw, validation.error ?? 'Invalid domain', scoringConfigHash);
			continue;
		}
		pending.push({ idx: i, domain: sanitizeDomain(raw) });
	}

	let cursor = 0;

	async function worker() {
		while (cursor < pending.length) {
			const task = pending[cursor++];
			if (!task) return;

			const remaining = deadline - Date.now();
			if (remaining <= 0) {
				results[task.idx] = emptyResult(task.domain, 'batch_budget_exceeded', scoringConfigHash);
				continue;
			}

			const scanAbort = new AbortController();
			const parentSignal = options.runtimeOptions?.signal;
			const signal = parentSignal ? AbortSignal.any([scanAbort.signal, parentSignal]) : scanAbort.signal;
			const runtimeOpts: ScanRuntimeOptions = {
				...options.runtimeOptions,
				forceRefresh: options.force_refresh,
				dnsSemaphore,
				signal,
			};

			let timeoutId: ReturnType<typeof setTimeout> | undefined;
			try {
				const scanPromise = scan(task.domain, options.kv, runtimeOpts);
				const timeoutPromise = new Promise<never>((_, reject) => {
					timeoutId = setTimeout(() => {
						const error = new Error('batch_budget_exceeded');
						scanAbort.abort(error);
						reject(error);
					}, remaining);
				});
				let scanResult;
				try {
					scanResult = await Promise.race([scanPromise, timeoutPromise]);
				} catch (error) {
					if (scanAbort.signal.aborted) await scanPromise.catch(() => undefined);
					throw error;
				}
				results[task.idx] = markUnexpectedNoEvidence(buildStructuredScanResult(scanResult, { scoringConfigHash }));
			} catch (err) {
				const msg = err instanceof Error ? err.message : 'Scan failed';
				results[task.idx] = emptyResult(task.domain, msg, scoringConfigHash);
			} finally {
				if (timeoutId !== undefined) clearTimeout(timeoutId);
			}
		}
	}

	await Promise.all(Array.from({ length: concurrency }, () => worker()));
	return results;
}

/**
 * Domains that hit the batch wall-clock budget and were never scanned. Both the
 * pre-scan deadline check and the per-scan timeout stamp `error: 'batch_budget_exceeded'`,
 * so this single predicate captures the whole budget-dropped tail — and ONLY that tail,
 * not invalid-input or scan-threw placeholders, which are a different failure class.
 */
export function budgetExceededDomains(results: BatchScanResultItem[]): string[] {
	return results.filter((r) => r.error === 'batch_budget_exceeded').map((r) => r.domain);
}

/**
 * Reduce a batch to the fields needed to rank an estate and select domains for
 * a full scan. Findings and per-check diagnostics are intentionally excluded:
 * their repeated explanatory prose makes multi-domain MCP responses unusable.
 */
export function compactBatchScanResults(results: BatchScanResultItem[]): CompactBatchScanResult {
	// Batch-level incompleteness signal: surfaces the budget-dropped tail at the top
	// of the payload so a caller cannot silently treat those domains as unscored/zero
	// by skipping the per-row `measured` flag.
	const unscanned = budgetExceededDomains(results);
	return {
		results: results.map(({ domain, score, grade, measured, findingCounts, categoryScores, scoringProfile, evidence, error }) => ({
			domain,
			score,
			grade,
			measured,
			findingCounts,
			categoryScores,
			scoringProfile,
			evidence,
			...(error === undefined ? {} : { error }),
		})),
		incomplete: unscanned.length > 0,
		unscanned,
		// These are computed once for the batch, so hoist them rather than repeating
		// identical values in every domain result.
		scoringModelVersion: results[0]?.scoringModelVersion ?? SCORING_MODEL_VERSION,
		dnsChecksPackageVersion: results[0]?.dnsChecksPackageVersion ?? DNS_CHECKS_PACKAGE_VERSION,
		scoringConfigHash: results[0]?.scoringConfigHash ?? computeScoringConfigHash(),
	};
}

/** Format batch scan results as a text summary. */
export function formatBatchScan(results: BatchScanResultItem[], format: OutputFormat = 'compact'): string {
	const lines: string[] = [];
	lines.push('Batch DNS Security Scan');
	lines.push('='.repeat(40));
	lines.push('');

	for (const r of results) {
		// `!r.measured` is defence-in-depth alongside the nullness checks. The producers
		// now emit `null` for an unmeasured domain, but before 3.35.0 an NXDOMAIN/SERVFAIL
		// scan_domain result ran zero checks and still carried a raw score/grade pair —
		// neither of them null — so gating on nullness alone rendered a confident
		// `0/100 (F)` for a domain that was never measured. Any future ScanScore source
		// that reintroduces a placeholder pair is still caught here. Mirrors the same
		// conjunction compare-domains.ts uses for its `rankable` filter.
		if (!r.measured || r.score === null || r.grade === null) {
			// A gate-fired domain (checks ran, evidence was too thin to grade) is NOT the
			// same state as a domain that was never scanned at all (invalid input / budget
			// exceeded / threw) — rendering both as bare "not measured" made a real partial
			// scan with real findings byte-identical to a domain that never resolved.
			if (r.evidenceInsufficient) {
				lines.push(`· ${r.domain.padEnd(40)} evidence insufficient (${r.evidence.completed}/${r.evidence.attempted} checks completed)`);
			} else {
				const why = r.error ? `: ${r.error}` : '';
				lines.push(`· ${r.domain.padEnd(40)} not measured${why}`);
			}
			continue;
		}
		const icon = r.score >= 80 ? '✓' : r.score >= 50 ? '⚠' : '✗';
		lines.push(`${icon} ${r.domain.padEnd(40)} ${formatScoreGrade(r.score, r.grade)}`);
		if (format === 'full') {
			lines.push(`   Profile: ${r.scoringProfile} | Maturity: Stage ${r.maturityStage ?? '?'}`);
			if (r.evidence.attempted > 0 && r.evidence.completed < r.evidence.attempted) {
				lines.push(`   Checks completed: ${r.evidence.completed}/${r.evidence.attempted}`);
			}
			const critHigh = r.findingCounts.critical + r.findingCounts.high;
			if (critHigh > 0) {
				lines.push(`   Critical/High findings: ${critHigh}`);
			}
		}
	}

	lines.push('');
	lines.push(`Scanned ${results.filter((r) => r.measured && r.score !== null).length}/${results.length} domain(s) successfully`);

	// Batch-level incompleteness banner: the per-row `not measured: batch_budget_exceeded`
	// lines above are easy to miss in a 10-row list, so name the dropped tail explicitly.
	const unscanned = budgetExceededDomains(results);
	if (unscanned.length > 0) {
		lines.push('');
		lines.push(`⚠ INCOMPLETE: ${unscanned.length} domain(s) hit the batch time budget and were NOT scanned:`);
		lines.push(`   ${unscanned.join(', ')}`);
		lines.push('   These are recoverable — re-run them in a smaller follow-up batch.');
	}
	return lines.join('\n');
}
