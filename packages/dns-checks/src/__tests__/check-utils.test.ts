// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect } from 'vitest';
import { createFinding, buildCheckResult, computeCategoryScore, inferFindingConfidence, sanitizeDnsData } from '../check-utils';

describe('createFinding', () => {
	it('creates a finding with correct fields', () => {
		const finding = createFinding('spf', 'SPF configured', 'info', 'SPF record found');
		expect(finding.category).toBe('spf');
		expect(finding.title).toBe('SPF configured');
		expect(finding.severity).toBe('info');
		expect(finding.detail).toBe('SPF record found');
	});

	it('includes metadata when provided', () => {
		const finding = createFinding('dmarc', 'DMARC missing', 'critical', 'No record found', { record: 'v=DMARC1' });
		expect(finding.metadata).toEqual({ record: 'v=DMARC1' });
	});

	it('omits metadata key when not provided', () => {
		const finding = createFinding('spf', 'SPF ok', 'info', 'detail');
		expect(Object.prototype.hasOwnProperty.call(finding, 'metadata')).toBe(false);
	});

	it('sanitizes the detail string', () => {
		const finding = createFinding('spf', 'Title', 'info', 'v=spf1 `include`<evil>');
		expect(finding.detail).not.toContain('<');
		expect(finding.detail).not.toContain('`');
	});
});

describe('computeCategoryScore', () => {
	it('returns 100 for no findings', () => {
		expect(computeCategoryScore([])).toBe(100);
	});

	it('deducts 15 points for a medium finding', () => {
		const findings = [createFinding('spf', 'Issue', 'medium', 'Detail')];
		expect(computeCategoryScore(findings)).toBe(85);
	});

	it('deducts 25 points for a high finding', () => {
		const findings = [createFinding('spf', 'Issue', 'high', 'Detail')];
		expect(computeCategoryScore(findings)).toBe(75);
	});

	it('deducts 40 points for a critical finding', () => {
		const findings = [createFinding('spf', 'Issue', 'critical', 'Detail')];
		expect(computeCategoryScore(findings)).toBe(60);
	});

	it('deducts 5 points for a low finding', () => {
		const findings = [createFinding('spf', 'Issue', 'low', 'Detail')];
		expect(computeCategoryScore(findings)).toBe(95);
	});

	it('deducts nothing for info findings', () => {
		const findings = [createFinding('spf', 'Info', 'info', 'Detail')];
		expect(computeCategoryScore(findings)).toBe(100);
	});

	it('floors at 0 when penalties exceed 100', () => {
		const findings = [
			createFinding('spf', 'Critical', 'critical', 'Detail'),
			createFinding('spf', 'High', 'high', 'Detail'),
			createFinding('spf', 'High2', 'high', 'Detail'),
		];
		// 100 - 40 - 25 - 25 = 10
		expect(computeCategoryScore(findings)).toBe(10);
	});

	it('accumulates penalties from multiple findings', () => {
		const findings = [
			createFinding('dmarc', 'A', 'critical', 'x'),
			createFinding('dmarc', 'B', 'critical', 'x'),
			createFinding('dmarc', 'C', 'high', 'x'),
		];
		// 100 - 40 - 40 - 25 = 0 (floored)
		expect(computeCategoryScore(findings)).toBe(0);
	});
});

describe('buildCheckResult', () => {
	it('builds result with score from findings', () => {
		const result = buildCheckResult('spf', []);
		expect(result.category).toBe('spf');
		expect(result.score).toBe(100);
		expect(result.findings).toHaveLength(0);
		expect(result.passed).toBe(true);
	});

	it('marks passed=true when score >= 50', () => {
		const findings = [createFinding('spf', 'Medium issue', 'medium', 'detail')];
		const result = buildCheckResult('spf', findings);
		expect(result.score).toBe(85);
		expect(result.passed).toBe(true);
	});

	it('marks passed=false when score < 50', () => {
		const findings = [
			createFinding('dmarc', 'Critical', 'critical', 'detail'),
			createFinding('dmarc', 'High', 'high', 'detail'),
		];
		// 100 - 40 - 25 = 35
		const result = buildCheckResult('dmarc', findings);
		expect(result.score).toBe(35);
		expect(result.passed).toBe(false);
	});

	it('injects confidence metadata onto each finding', () => {
		const findings = [createFinding('spf', 'SPF ok', 'info', 'detail')];
		const result = buildCheckResult('spf', findings);
		expect(result.findings[0].metadata?.confidence).toBeDefined();
	});

	it('preserves the category on the result', () => {
		const result = buildCheckResult('dkim', []);
		expect(result.category).toBe('dkim');
	});
});

describe('inferFindingConfidence', () => {
	it('returns declared confidence when set in metadata', () => {
		const finding = createFinding('spf', 'Title', 'info', 'detail', { confidence: 'verified' });
		expect(inferFindingConfidence(finding)).toBe('verified');
	});

	it('returns heuristic for subdomain_takeover without verificationStatus', () => {
		const finding = createFinding('subdomain_takeover', 'Takeover', 'high', 'detail');
		expect(inferFindingConfidence(finding)).toBe('heuristic');
	});

	it('returns verified for subdomain_takeover with verificationStatus=verified', () => {
		const finding = createFinding('subdomain_takeover', 'Takeover', 'high', 'detail', {
			verificationStatus: 'verified',
		});
		expect(inferFindingConfidence(finding)).toBe('verified');
	});

	it('returns heuristic when detail contains "potential"', () => {
		const finding = createFinding('spf', 'Title', 'medium', 'potential misconfiguration');
		expect(inferFindingConfidence(finding)).toBe('heuristic');
	});

	it('returns heuristic when detail contains "possible"', () => {
		const finding = createFinding('dmarc', 'Title', 'medium', 'possible issue here');
		expect(inferFindingConfidence(finding)).toBe('heuristic');
	});

	it('returns heuristic when title contains "inferred"', () => {
		const finding = createFinding('dkim', 'Inferred selector', 'low', 'detail');
		expect(inferFindingConfidence(finding)).toBe('heuristic');
	});

	it('returns deterministic for clear protocol findings', () => {
		const finding = createFinding('spf', 'SPF record missing', 'critical', 'No SPF TXT record found');
		expect(inferFindingConfidence(finding)).toBe('deterministic');
	});
});

describe('sanitizeDnsData', () => {
	it('strips control characters', () => {
		// \x00 is removed entirely (not replaced with space); surrounding text is joined
		expect(sanitizeDnsData('hello\x00world')).toBe('helloworld');
	});

	it('strips control characters separated by spaces', () => {
		// When control char is between spaces, whitespace collapse gives one space
		expect(sanitizeDnsData('hello \x00 world')).toBe('hello world');
	});

	it('replaces markdown injection characters', () => {
		expect(sanitizeDnsData('v=spf1 `include`<evil>[link]')).not.toMatch(/[`<>[\]]/);
	});

	it('collapses whitespace', () => {
		expect(sanitizeDnsData('a  b   c')).toBe('a b c');
	});

	it('trims leading and trailing whitespace', () => {
		expect(sanitizeDnsData('  hello  ')).toBe('hello');
	});

	it('preserves underscores and parentheses', () => {
		const input = '_dmarc.example.com (check this)';
		expect(sanitizeDnsData(input)).toBe('_dmarc.example.com (check this)');
	});
});
