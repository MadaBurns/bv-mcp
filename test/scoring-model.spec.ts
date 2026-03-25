import { describe, expect, it } from 'vitest';
import { buildCheckResult, CATEGORY_TIERS, computeCategoryScore, createFinding, inferFindingConfidence } from '../src/lib/scoring-model';

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

describe('CATEGORY_TIERS', () => {
	it('classifies all 22 categories into tiers', () => {
		expect(Object.keys(CATEGORY_TIERS)).toHaveLength(22);
	});

	it('has 5 core categories', () => {
		const core = Object.entries(CATEGORY_TIERS).filter(([, t]) => t === 'core');
		expect(core.map(([k]) => k).sort()).toEqual(['dkim', 'dmarc', 'dnssec', 'spf', 'ssl']);
	});

	it('has 10 protective categories', () => {
		const protective = Object.entries(CATEGORY_TIERS).filter(([, t]) => t === 'protective');
		expect(protective).toHaveLength(10);
	});

	it('has 7 hardening categories', () => {
		const hardening = Object.entries(CATEGORY_TIERS).filter(([, t]) => t === 'hardening');
		expect(hardening).toHaveLength(7);
	});
});