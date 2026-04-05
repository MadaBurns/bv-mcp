// SPDX-License-Identifier: BUSL-1.1

/**
 * Compare domains tool.
 * Scans 2–5 domains and produces a side-by-side comparison of their security posture.
 */

import { sanitizeDomain, validateDomain } from '../lib/sanitize';
import { scanDomain, buildStructuredScanResult } from './scan-domain';
import type { ScanRuntimeOptions } from './scan/post-processing';
import type { StructuredScanResult } from './scan/format-report';
import type { OutputFormat } from '../handlers/tool-args';

export interface DomainComparisonResult {
	domains: string[];
	/** Domain with the highest overall score. Null on tie or if fewer than 2 valid results. */
	winner: string | null;
	scores: Record<string, number>;
	grades: Record<string, string>;
	/** Per-category scores: [{ category, scores: { 'example.com': 100, 'test.com': 85 } }] */
	categoryComparison: Array<{ category: string; scores: Record<string, number> }>;
	/** Categories where ALL scanned domains score below 50. */
	commonGaps: string[];
	/** Categories where only one domain scores below 50 (unique weakness). */
	uniqueGaps: Array<{ domain: string; findings: string[] }>;
	/** Errors keyed by domain, for domains that failed validation or scanning. */
	errors: Record<string, string>;
}

export interface CompareDomainsOptions {
	kv?: KVNamespace;
	runtimeOptions?: ScanRuntimeOptions;
}

/**
 * Scan 2–5 domains and compare their security posture.
 */
export async function compareDomains(
	rawDomains: string[],
	options: CompareDomainsOptions = {},
): Promise<DomainComparisonResult> {
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

	for (const domain of sanitized) {
		if (errors[domain]) {
			structuredResults[domain] = null;
			continue;
		}
		try {
			const scanResult = await scanDomain(domain, options.kv, options.runtimeOptions);
			structuredResults[domain] = buildStructuredScanResult(scanResult);
		} catch (err) {
			errors[domain] = err instanceof Error ? err.message : 'Scan failed';
			structuredResults[domain] = null;
		}
	}

	const validResults = Object.entries(structuredResults)
		.filter((entry): entry is [string, StructuredScanResult] => entry[1] !== null);

	const scores: Record<string, number> = {};
	const grades: Record<string, string> = {};
	for (const [domain, r] of validResults) {
		scores[domain] = r.score;
		grades[domain] = r.grade;
	}

	// Winner: highest score, null on tie
	let winner: string | null = null;
	if (validResults.length >= 2) {
		const sorted = [...validResults].sort((a, b) => b[1].score - a[1].score);
		if (sorted[0][1].score > sorted[1][1].score) {
			winner = sorted[0][0];
		}
	} else if (validResults.length === 1) {
		winner = validResults[0][0];
	}

	// Category comparison
	const allCategories = new Set<string>();
	for (const [, r] of validResults) {
		Object.keys(r.categoryScores).forEach((c) => allCategories.add(c));
	}
	const categoryComparison = [...allCategories].map((category) => ({
		category,
		scores: Object.fromEntries(validResults.map(([d, r]) => [d, r.categoryScores[category] ?? 0])),
	}));

	// Common gaps: categories where ALL valid domains score below 50
	const commonGaps: string[] = categoryComparison
		.filter((cc) => validResults.length > 0 && Object.values(cc.scores).every((s) => s < 50))
		.map((cc) => cc.category);

	// Unique gaps: categories where exactly one domain scores below 50
	const uniqueGaps: Array<{ domain: string; findings: string[] }> = [];
	for (const [domain] of validResults) {
		const unique = categoryComparison
			.filter((cc) => {
				const domScore = cc.scores[domain] ?? 100;
				const others = Object.entries(cc.scores).filter(([d]) => d !== domain).map(([, s]) => s);
				return domScore < 50 && others.length > 0 && others.every((s) => s >= 50);
			})
			.map((cc) => cc.category);
		if (unique.length > 0) {
			uniqueGaps.push({ domain, findings: unique });
		}
	}

	return { domains: sanitized, winner, scores, grades, categoryComparison, commonGaps, uniqueGaps, errors };
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
		const score = result.scores[domain] ?? 0;
		const grade = result.grades[domain] ?? 'F';
		const icon = score >= 80 ? '✓' : score >= 50 ? '⚠' : '✗';
		const winMark = result.winner === domain ? ' ← best' : '';
		lines.push(`  ${icon} ${domain.padEnd(40)} ${score}/100 (${grade})${winMark}`);
	}
	lines.push('');

	if (result.commonGaps.length > 0) {
		lines.push(`Common gaps (all domains fail): ${result.commonGaps.join(', ')}`);
		lines.push('');
	}

	if (result.uniqueGaps.length > 0) {
		lines.push('Unique weaknesses:');
		for (const ug of result.uniqueGaps) {
			lines.push(`  ${ug.domain}: ${ug.findings.join(', ')}`);
		}
		lines.push('');
	}

	if (format === 'full' && result.categoryComparison.length > 0) {
		const validDomains = result.domains.filter((d) => !result.errors[d]);
		lines.push('Category Scores:');
		lines.push('-'.repeat(30));
		const header = '  Category'.padEnd(16) + validDomains.map((d) => d.substring(0, 18).padEnd(20)).join('');
		lines.push(header);
		for (const cc of result.categoryComparison) {
			const row =
				`  ${cc.category.toUpperCase().padEnd(14)}` +
				validDomains.map((d) => {
					const s = cc.scores[d] ?? 0;
					const mark = s >= 80 ? '✓' : s >= 50 ? '⚠' : '✗';
					return `${mark} ${String(s).padEnd(18)}`;
				}).join('');
			lines.push(row);
		}
	}

	return lines.join('\n');
}
