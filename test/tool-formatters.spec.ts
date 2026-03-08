import { describe, expect, it } from 'vitest';
import { formatCheckResult, mcpError, mcpText } from '../src/handlers/tool-formatters';
import type { CheckResult } from '../src/lib/scoring';

describe('tool-formatters', () => {
	it('mcpError and mcpText return MCP text content', () => {
		expect(mcpError('Bad input')).toEqual({ type: 'text', text: 'Error: Bad input' });
		expect(mcpText('All good')).toEqual({ type: 'text', text: 'All good' });
	});

	it('formatCheckResult renders findings, confidence, and impact sections', () => {
		const result: CheckResult = {
			category: 'spf',
			passed: false,
			score: 60,
			findings: [
				{
					category: 'spf',
					title: 'Unsafe SPF policy',
					severity: 'high',
					detail: 'SPF record contains +all and permits spoofing.',
					metadata: { confidence: 'deterministic' },
				},
			],
		};

		const text = formatCheckResult(result);
		expect(text).toContain('## SPF Check');
		expect(text).toContain('❌ Failed');
		expect(text).toContain('Confidence: deterministic');
		expect(text).toContain('Potential Impact:');
		expect(text).toContain('Adverse Consequences:');
	});
});