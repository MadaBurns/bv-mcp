// SPDX-License-Identifier: BUSL-1.1

import type { ScanDomainResult } from '../scan-domain';
import type { OutputFormat } from '../../handlers/tool-args';
import { sanitizeOutputText } from '../../lib/output-sanitize';
import { resolveImpactNarrative } from '../explain-finding';

/** Structured scan result for machine-readable consumption (e.g., CI/CD actions). */
export interface StructuredScanResult {
	domain: string;
	score: number;
	grade: string;
	passed: boolean;
	maturityStage: number | null;
	maturityLabel: string | null;
	categoryScores: Record<string, number>;
	findingCounts: { critical: number; high: number; medium: number; low: number };
	scoringProfile: string;
	scoringSignals: string[];
	scoringNote: string | null;
	adaptiveWeightDeltas: Record<string, number> | null;
	/** Percentile rank within the scoring profile population (0–100). Null when insufficient benchmark data. */
	percentileRank: number | null;
	/** Composite email spoofability score (0–100, higher = more spoofable). Null when not computed. */
	spoofabilityScore: number | null;
	timestamp: string;
	cached: boolean;
}

/** Optional enrichment data for structured scan results. */
export interface ScanResultEnrichment {
	percentileRank?: number | null;
	spoofabilityScore?: number | null;
}

/** Build a machine-readable structured result from a scan. */
export function buildStructuredScanResult(result: ScanDomainResult, enrichment?: ScanResultEnrichment): StructuredScanResult {
	return {
		domain: result.domain,
		score: result.score.overall,
		grade: result.score.grade,
		passed: result.score.overall >= 50,
		maturityStage: result.maturity?.stage ?? null,
		maturityLabel: result.maturity?.label ?? null,
		categoryScores: result.score.categoryScores,
		findingCounts: {
			critical: result.score.findings.filter((f) => f.severity === 'critical').length,
			high: result.score.findings.filter((f) => f.severity === 'high').length,
			medium: result.score.findings.filter((f) => f.severity === 'medium').length,
			low: result.score.findings.filter((f) => f.severity === 'low').length,
		},
		scoringProfile: result.context?.profile ?? 'mail_enabled',
		scoringSignals: (result.context?.signals ?? []).map((s) => s.replace(/[<>&"']/g, '')),
		scoringNote: result.scoringNote ?? null,
		adaptiveWeightDeltas: result.adaptiveWeightDeltas ?? null,
		percentileRank: enrichment?.percentileRank ?? null,
		spoofabilityScore: enrichment?.spoofabilityScore ?? null,
		timestamp: result.timestamp,
		cached: result.cached,
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

	lines.push('Category Scores:');
	lines.push('-'.repeat(30));
	for (const [category, score] of Object.entries(result.score.categoryScores)) {
		const status = score >= 80 ? '✓' : score >= 50 ? '⚠' : '✗';
		lines.push(`  ${status} ${category.toUpperCase().padEnd(10)} ${score}/100`);
	}
	lines.push('');

	const nonInfoFindings = result.score.findings.filter((finding) => finding.severity !== 'info');
	if (nonInfoFindings.length > 0) {
		lines.push('Findings:');
		lines.push('-'.repeat(30));
		for (const finding of nonInfoFindings) {
			if (format === 'compact') {
				lines.push(`  [${finding.severity.toUpperCase()}] ${sanitizeOutputText(finding.title, 120)} — ${sanitizeOutputText(finding.detail, 200)}`);
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

	if (result.cached) {
		lines.push('');
		lines.push('(Results served from cache)');
	}

	lines.push('');
	lines.push(`Scan completed: ${result.timestamp}`);
	return lines.join('\n');
}