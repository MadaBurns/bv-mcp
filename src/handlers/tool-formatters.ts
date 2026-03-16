// SPDX-License-Identifier: BUSL-1.1

import type { CheckResult } from '../lib/scoring';
import { sanitizeOutputText } from '../lib/output-sanitize';
import { resolveImpactNarrative } from '../tools/explain-finding';

export interface McpContent {
	type: 'text';
	text: string;
}

export function mcpError(message: string): McpContent {
	return { type: 'text', text: `Error: ${message}` };
}

export function mcpText(text: string): McpContent {
	return { type: 'text', text };
}

export function formatCheckResult(result: CheckResult): string {
	const lines: string[] = [];
	lines.push(`## ${result.category.toUpperCase()} Check`);
	lines.push(`**Status:** ${result.passed ? '✅ Passed' : '❌ Failed'}`);
	lines.push(`**Score:** ${result.score}/100`);
	lines.push('');

	if (result.findings.length > 0) {
		lines.push('### Findings');
		for (const finding of result.findings) {
			const icon =
				finding.severity === 'info'
					? 'ℹ️'
					: finding.severity === 'low'
						? '⚠️'
						: finding.severity === 'medium'
							? '🔶'
							: finding.severity === 'high'
								? '🔴'
								: '🚨';
					lines.push(`- ${icon} **[${finding.severity.toUpperCase()}]** ${sanitizeOutputText(finding.title, 120)}`);
					lines.push(`  ${sanitizeOutputText(finding.detail)}`);

			const verificationStatus =
				finding.category === 'subdomain_takeover' && finding.metadata?.verificationStatus
					? String(finding.metadata.verificationStatus)
					: undefined;
			if (verificationStatus) {
				lines.push(`  Takeover Verification: ${sanitizeOutputText(verificationStatus, 80)}`);
			}

			const confidence = finding.metadata?.confidence ? String(finding.metadata.confidence) : undefined;
			if (confidence) {
				lines.push(`  Confidence: ${sanitizeOutputText(confidence, 80)}`);
			}

			if (finding.severity !== 'info') {
				const narrative = resolveImpactNarrative({
					category: finding.category,
					severity: finding.severity,
					title: finding.title,
					detail: finding.detail,
				});
				if (narrative.impact) {
					lines.push(`  Potential Impact: ${narrative.impact}`);
				}
				if (narrative.adverseConsequences) {
					lines.push(`  Adverse Consequences: ${narrative.adverseConsequences}`);
				}
			}
		}
	}

	return lines.join('\n');
}