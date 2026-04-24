// SPDX-License-Identifier: BUSL-1.1

/**
 * Batch scan tool.
 * Runs scan_domain on up to 10 domains with bounded concurrency and a global
 * wall-clock budget so a single slow domain can't consume the entire Worker
 * request budget.
 */

import { sanitizeDomain, validateDomain } from '../lib/sanitize';
import { scanDomain, buildStructuredScanResult } from './scan-domain';
import type { ScanRuntimeOptions } from './scan/post-processing';
import type { StructuredScanResult } from './scan/format-report';
import type { OutputFormat } from '../handlers/tool-args';

export interface BatchScanResultItem extends StructuredScanResult {
	error?: string;
}

/** Signature compatible with `scanDomain`. Exposed as an option for testing. */
type ScanFn = typeof scanDomain;

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
const MAX_DOMAINS = 10;

function emptyResult(domain: string, error: string): BatchScanResultItem {
	return {
		domain,
		score: 0,
		grade: 'F',
		passed: false,
		maturityStage: null,
		maturityLabel: null,
		categoryScores: {},
		findingCounts: { critical: 0, high: 0, medium: 0, low: 0 },
		scoringProfile: 'mail_enabled',
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
		timestamp: new Date().toISOString(),
		cached: false,
		error,
	};
}

/**
 * Scan multiple domains with bounded concurrency and a global time budget.
 * Returns one structured result per input domain, in input order.
 * Invalid domains and budget-exceeded scans produce an error result instead of throwing.
 */
export async function batchScan(
	domains: string[],
	options: BatchScanOptions = {},
): Promise<BatchScanResultItem[]> {
	if (domains.length > MAX_DOMAINS) {
		throw new Error(`Batch scan accepts a max of ${MAX_DOMAINS} domains per request (received ${domains.length})`);
	}

	const budgetMs = options.budgetMs ?? DEFAULT_BUDGET_MS;
	const concurrency = Math.max(1, Math.min(options.concurrency ?? DEFAULT_CONCURRENCY, domains.length || 1));
	const scan = options.scanFn ?? scanDomain;
	const deadline = Date.now() + budgetMs;

	const results: BatchScanResultItem[] = new Array(domains.length);
	const pending: Array<{ idx: number; domain: string }> = [];

	// Fast path: validate all inputs up front; invalid domains never occupy a worker slot.
	for (let i = 0; i < domains.length; i++) {
		const raw = domains[i];
		const validation = validateDomain(raw);
		if (!validation.valid) {
			results[i] = emptyResult(raw, validation.error ?? 'Invalid domain');
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
				results[task.idx] = emptyResult(task.domain, 'batch_budget_exceeded');
				continue;
			}

			const runtimeOpts: ScanRuntimeOptions = {
				...options.runtimeOptions,
				forceRefresh: options.force_refresh,
			};

			let timeoutId: ReturnType<typeof setTimeout> | undefined;
			try {
				const scanPromise = scan(task.domain, options.kv, runtimeOpts);
				const timeoutPromise = new Promise<never>((_, reject) => {
					timeoutId = setTimeout(() => reject(new Error('batch_budget_exceeded')), remaining);
				});
				const scanResult = await Promise.race([scanPromise, timeoutPromise]);
				results[task.idx] = buildStructuredScanResult(scanResult);
			} catch (err) {
				const msg = err instanceof Error ? err.message : 'Scan failed';
				results[task.idx] = emptyResult(task.domain, msg);
			} finally {
				if (timeoutId !== undefined) clearTimeout(timeoutId);
			}
		}
	}

	await Promise.all(Array.from({ length: concurrency }, () => worker()));
	return results;
}

/** Format batch scan results as a text summary. */
export function formatBatchScan(results: BatchScanResultItem[], format: OutputFormat = 'compact'): string {
	const lines: string[] = [];
	lines.push('Batch DNS Security Scan');
	lines.push('='.repeat(40));
	lines.push('');

	for (const r of results) {
		if (r.error) {
			lines.push(`✗ ${r.domain.padEnd(40)} Error: ${r.error}`);
			continue;
		}
		const icon = r.score >= 80 ? '✓' : r.score >= 50 ? '⚠' : '✗';
		lines.push(`${icon} ${r.domain.padEnd(40)} ${r.score}/100 (${r.grade})`);
		if (format === 'full') {
			lines.push(`   Profile: ${r.scoringProfile} | Maturity: Stage ${r.maturityStage ?? '?'}`);
			const critHigh = r.findingCounts.critical + r.findingCounts.high;
			if (critHigh > 0) {
				lines.push(`   Critical/High findings: ${critHigh}`);
			}
		}
	}

	lines.push('');
	lines.push(`Scanned ${results.filter((r) => !r.error).length}/${results.length} domain(s) successfully`);
	return lines.join('\n');
}
