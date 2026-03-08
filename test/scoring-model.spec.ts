import { describe, expect, it } from 'vitest';
import { buildCheckResult, computeCategoryScore, createFinding, inferFindingConfidence } from '../src/lib/scoring-model';

describe('scoring-model', () => {
	it('normalizes confidence metadata when building check results', () => {
		const result = buildCheckResult('spf', [createFinding('spf', 'SPF record configured', 'info', 'Healthy SPF')]);
		expect(result.findings[0].metadata?.confidence).toBe('deterministic');
		expect(result.passed).toBe(true);
	});

	it('detects heuristic confidence from partial-evidence language', () => {
		const finding = createFinding('dkim', 'No DKIM records found among tested selectors', 'high', 'Possible missing DKIM coverage.');
		expect(inferFindingConfidence(finding)).toBe('heuristic');
	});

	it('applies severity penalties for category scoring', () => {
		const findings = [
			createFinding('dmarc', 'Missing DMARC', 'critical', 'No record found'),
			createFinding('dmarc', 'No aggregate reporting', 'medium', 'rua tag missing'),
		];
		expect(computeCategoryScore(findings)).toBe(45);
	});
});