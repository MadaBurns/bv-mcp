// SPDX-License-Identifier: BUSL-1.1

/**
 * Batch scan tool.
 * Runs scan_domain sequentially on up to 10 domains and aggregates results.
 */

import { sanitizeDomain, validateDomain } from '../lib/sanitize';
import { scanDomain, buildStructuredScanResult } from './scan-domain';
import type { ScanRuntimeOptions } from './scan/post-processing';
import type { StructuredScanResult } from './scan/format-report';
import type { OutputFormat } from '../handlers/tool-args';

export interface BatchScanResultItem extends StructuredScanResult {
	error?: string;
}

export interface BatchScanOptions {
	force_refresh?: boolean;
	kv?: KVNamespace;
	runtimeOptions?: ScanRuntimeOptions;
}

/**
 * Scan multiple domains sequentially. Returns one structured result per domain.
 * Invalid domains produce an error result instead of throwing.
 * @param domains - Array of domains to scan (max 10)
 */
export async function batchScan(
	domains: string[],
	options: BatchScanOptions = {},
): Promise<BatchScanResultItem[]> {
	if (domains.length > 10) {
		throw new Error(`Batch scan accepts a max of 10 domains per request (received ${domains.length})`);
	}

	const results: BatchScanResultItem[] = [];

	for (const rawDomain of domains) {
		let domain: string;
		const validation = validateDomain(rawDomain);
		if (!validation.valid) {
			results.push({
				domain: rawDomain,
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
				error: validation.error ?? 'Invalid domain',
			});
			continue;
		}
		domain = sanitizeDomain(rawDomain);

		try {
			const runtimeOpts: ScanRuntimeOptions = {
				...options.runtimeOptions,
				forceRefresh: options.force_refresh,
			};
			const scanResult = await scanDomain(domain, options.kv, runtimeOpts);
			results.push(buildStructuredScanResult(scanResult));
		} catch (err) {
			results.push({
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
				error: err instanceof Error ? err.message : 'Scan failed',
			});
		}
	}

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
