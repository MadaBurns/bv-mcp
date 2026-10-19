// SPDX-License-Identifier: BUSL-1.1

/**
 * Tiered-mode "Owned Portfolio" section of `formatBrandAuditMarkdown`.
 * Pins how consolidated rows are partitioned by tier: tiers 0/1/2 get their own
 * subsections, while an undefined tier or tier 3 both fall into the inferred
 * "Consolidated" subsection (the `tier === undefined || tier === 3` predicate).
 */

import { describe, expect, it } from 'vitest';
import type { CheckResult, Finding } from '../src/lib/scoring';
import { formatBrandAuditMarkdown } from '../src/lib/brand-audit-markdown';

function candidate(domain: string, metadata: Record<string, unknown>): Finding {
	return {
		category: 'brand_discovery',
		title: domain,
		severity: 'info',
		detail: '',
		metadata: { candidate: domain, registrar: 'Example Registrar', registrarSource: 'rdap', combinedConfidence: 0.9, signals: [], ...metadata },
	};
}

function tieredResult(findings: Finding[]): CheckResult {
	return {
		category: 'brand_discovery',
		score: 100,
		passed: true,
		findings: [
			{
				category: 'brand_discovery',
				title: 'summary',
				severity: 'info',
				detail: '',
				metadata: { summary: true, target: 'bank.example', discoveryMode: 'tiered', consolidated: findings.length },
			},
			...findings,
		],
	};
}

describe('formatBrandAuditMarkdown tiered Owned Portfolio', () => {
	it('routes consolidated rows by tier; undefined tier and tier 3 both land in the inferred Consolidated subsection', () => {
		const md = formatBrandAuditMarkdown(
			tieredResult([
				candidate('zero.example', { bucket: 'consolidated', tier: 0 }),
				candidate('one.example', { bucket: 'consolidated', tier: 1 }),
				candidate('two.example', { bucket: 'consolidated', tier: 2 }),
				candidate('three.example', { bucket: 'consolidated', tier: 3 }),
				candidate('untiered.example', { bucket: 'consolidated' }),
			]),
		);

		expect(md).toContain('## Owned Portfolio (5)');
		expect(md).toContain('### Tenant-declared (tier 0) (1)');
		expect(md).toContain('### Graph-surfaced (tier 1) (1)');
		expect(md).toContain('### Declared evidence (tier 2) (1)');
		expect(md).toContain('### Inferred (tier 3) — 2');
		expect(md).toContain('#### Consolidated (2)');

		const portfolio = md.slice(md.indexOf('## Owned Portfolio'));
		const inferred = portfolio.slice(portfolio.indexOf('### Inferred (tier 3)'));
		const consolidatedSection = inferred.slice(inferred.indexOf('#### Consolidated'), inferred.indexOf('#### Shadow IT'));
		expect(consolidatedSection).toContain('**three.example**');
		expect(consolidatedSection).toContain('**untiered.example**');
		// Tiers 0-2 stay out of the inferred subsection.
		for (const d of ['zero.example', 'one.example', 'two.example']) {
			expect(consolidatedSection).not.toContain(d);
		}
		// An empty inferred sibling renders the empty-tier marker.
		expect(inferred.slice(inferred.indexOf('#### Shadow IT'))).toContain('_No candidates in this tier._');
	});
});
