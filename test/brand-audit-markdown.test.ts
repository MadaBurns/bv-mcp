// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import type { CheckResult } from '../src/lib/scoring';
import { formatBrandAuditMarkdown } from '../src/lib/brand-audit-markdown';

describe('formatBrandAuditMarkdown', () => {
	it('renders authorized vendor dependencies outside the Shadow IT section', () => {
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
						target: 'bank.example',
						consolidated: 0,
						shadowIt: 1,
						indeterminate: 1,
						impersonation: 0,
					},
				},
				{
					category: 'brand_discovery',
					title: 'Brand candidate: pphosted.example',
					severity: 'low',
					detail: '',
					metadata: {
						candidate: 'pphosted.example',
						bucket: 'indeterminate',
						relationshipType: 'authorized_vendor_dependency',
						registrar: 'Example Registrar',
						registrarSource: 'rdap',
						reasons: ['authorized vendor dependency via seed SPF delegation'],
						signals: ['spf_include_seed'],
						combinedConfidence: 0.85,
					},
				},
				{
					category: 'brand_discovery',
					title: 'Brand candidate: bank.example.ca',
					severity: 'medium',
					detail: '',
					metadata: {
						candidate: 'bank.example.ca',
						bucket: 'shadowIt',
						relationshipType: 'owned_off_primary_registrar',
						registrar: 'Other Registrar',
						registrarSource: 'rdap',
						reasons: ['brand-owned domain on off-primary registrar'],
						signals: ['ns', 'spf_include'],
						combinedConfidence: 1,
					},
				},
			],
		};

		const markdown = formatBrandAuditMarkdown(result);

		expect(markdown).toContain('## Registrar Sprawl / Real Shadow IT');
		expect(markdown).toContain('bank.example.ca');
		expect(markdown).toContain('## Authorized Vendor Dependencies');
		expect(markdown).toContain('pphosted.example');
		expect(markdown.indexOf('pphosted.example')).toBeGreaterThan(markdown.indexOf('## Authorized Vendor Dependencies'));
	});

	it('annotates defensive registrations with a "(defensive registration)" suffix', () => {
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
						target: 'brandepsilon.com',
						consolidated: 1,
						shadowIt: 0,
						indeterminate: 0,
						impersonation: 0,
					},
				},
				{
					category: 'brand_discovery',
					title: 'Brand candidate: brandepsiln.com',
					severity: 'info',
					detail: '',
					metadata: {
						candidate: 'brandepsiln.com',
						bucket: 'consolidated',
						relationshipType: 'owned_primary',
						registrar: 'CSC Corporate Domains',
						registrarSource: 'rdap',
						reasons: ['shared registrar family (CSC) + 2 corroborating signals'],
						signals: ['ns', 'san'],
						combinedConfidence: 0.9,
						defensive: true,
						defensiveReason: 'parked-ns',
					},
				},
			],
		};

		const markdown = formatBrandAuditMarkdown(result);

		// Candidate still belongs in the Consolidated section — we label, not re-bucket.
		expect(markdown).toContain('## Consolidated (owned/operated by the brand)');
		expect(markdown).toContain('brandepsiln.com');
		// And carries the defensive-registration tag inline. The label is wrapped
		// in markdown italics and includes the reason discriminant; assert the
		// canonical prefix rather than the exact closing-paren form so the test
		// is robust to reason-token additions.
		expect(markdown).toContain('defensive registration');
		expect(markdown).toContain('parked-ns');
	});

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
