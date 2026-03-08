import type { CheckResult } from '../lib/scoring';
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
			lines.push(`- ${icon} **[${finding.severity.toUpperCase()}]** ${finding.title}`);
			lines.push(`  ${finding.detail}`);

			const verificationStatus =
				finding.category === 'subdomain_takeover' && finding.metadata?.verificationStatus
					? String(finding.metadata.verificationStatus)
					: undefined;
			if (verificationStatus) {
				lines.push(`  Takeover Verification: ${verificationStatus}`);
			}

			const confidence = finding.metadata?.confidence ? String(finding.metadata.confidence) : undefined;
			if (confidence) {
				lines.push(`  Confidence: ${confidence}`);
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