// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import type { CheckResult } from '../src/lib/scoring';
import { formatBrandAuditMarkdown } from '../src/lib/brand-audit-markdown';

describe('formatBrandAuditMarkdown', () => {
	it('surfaces discovery depth warnings from the summary metadata', () => {
		const result: CheckResult = {
			category: 'brand_discovery',
			score: 100,
			findings: [
				{
					category: 'brand_discovery',
					title: 'summary',
					severity: 'info',
					detail: '',
					metadata: {
						summary: true,
						target: 'example.com',
						consolidated: 0,
						shadowIt: 0,
						indeterminate: 0,
						impersonation: 0,
						depth: {
							warnings: [
								'Candidate universe was truncated by cap (154 candidate(s) dropped); discovery coverage is incomplete.',
							],
						},
					},
				},
			],
		};

		const markdown = formatBrandAuditMarkdown(result);

		expect(markdown).toContain('**Discovery depth warnings:**');
		expect(markdown).toContain('Candidate universe was truncated by cap');
	});
});
