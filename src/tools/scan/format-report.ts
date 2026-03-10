// SPDX-License-Identifier: MIT

import type { ScanDomainResult } from '../scan-domain';
import { sanitizeOutputText } from '../../lib/output-sanitize';
import { resolveImpactNarrative } from '../explain-finding';

export function formatScanReport(result: ScanDomainResult): string {
	const lines: string[] = [];

	lines.push(`DNS Security Scan: ${result.domain}`);
	lines.push(`${'='.repeat(40)}`);
	lines.push(`Overall Score: ${result.score.overall}/100 (${result.score.grade})`);
	lines.push(`${result.score.summary}`);
	lines.push('');

	if (result.maturity) {
		lines.push(`Email Security Maturity: Stage ${result.maturity.stage} — ${result.maturity.label}`);
		lines.push(result.maturity.description);
		if (result.maturity.nextStep) {
			lines.push(`Next step: ${result.maturity.nextStep}`);
		}
		lines.push('');
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