// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import { buildCheckResult, CATEGORY_TIERS, computeCategoryScore, createFinding, inferFindingConfidence } from '../../scoring';

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

describe('CATEGORY_PENALTY_CAPS — subdomain_takeover', () => {
	const mediums = (n: number) =>
		Array.from({ length: n }, (_, i) => createFinding('subdomain_takeover', `Dangling CNAME #${i + 1}`, 'medium', 'operational drift'));

	it('1 MEDIUM → unsaturated (no cap hit): 85/100', () => {
		expect(computeCategoryScore(mediums(1), 'subdomain_takeover')).toBe(85);
	});

	it('5 MEDIUM = 75 penalty → cap exactly at floor: 25/100', () => {
		expect(computeCategoryScore(mediums(5), 'subdomain_takeover')).toBe(25);
	});

	it('9 MEDIUM (x.ai cluster pattern) = 135 raw → capped at 75 → 25/100 (no longer 0)', () => {
		expect(computeCategoryScore(mediums(9), 'subdomain_takeover')).toBe(25);
	});

	it('1 CRITICAL = 40 penalty → unsaturated: 60/100 (no cap hit)', () => {
		const findings = [createFinding('subdomain_takeover', 'Verified takeover', 'critical', 'fingerprint match')];
		expect(computeCategoryScore(findings, 'subdomain_takeover')).toBe(60);
	});

	it('1 CRITICAL + 5 MEDIUM = 115 raw → capped at 75 → 25/100', () => {
		const findings = [createFinding('subdomain_takeover', 'Verified takeover', 'critical', 'fingerprint match'), ...mediums(5)];
		expect(computeCategoryScore(findings, 'subdomain_takeover')).toBe(25);
	});

	it('2 CRITICAL = 80 raw → capped at 75 → 25/100', () => {
		const findings = [
			createFinding('subdomain_takeover', 'Verified takeover #1', 'critical', 'fingerprint match'),
			createFinding('subdomain_takeover', 'Verified takeover #2', 'critical', 'fingerprint match'),
		];
		expect(computeCategoryScore(findings, 'subdomain_takeover')).toBe(25);
	});

	it('preserves discriminative power: 9 MEDIUM (25) > 0 (the saturated floor)', () => {
		const nineMedium = computeCategoryScore(mediums(9), 'subdomain_takeover');
		expect(nineMedium).toBe(25);
		expect(nineMedium).toBeGreaterThan(0);
	});

	it('omitting category retains the original uncapped-then-clamped behavior', () => {
		expect(computeCategoryScore(mediums(9))).toBe(0);
	});

	it('non-takeover categories unaffected by the cap (e.g., 9 MEDIUM DMARC saturates to 0)', () => {
		const findings = Array.from({ length: 9 }, (_, i) => createFinding('dmarc', `Issue ${i + 1}`, 'medium', 'detail'));
		expect(computeCategoryScore(findings, 'dmarc')).toBe(0);
	});
});

describe('CATEGORY_TIERS', () => {
	it('classifies all categories into tiers', () => {
		expect(Object.keys(CATEGORY_TIERS)).toHaveLength(26);
	});

	it('has 6 core categories', () => {
		const core = Object.entries(CATEGORY_TIERS).filter(([, t]) => t === 'core');
		expect(core.map(([k]) => k).sort()).toEqual(['authoritative_dns_infra', 'dkim', 'dmarc', 'dnssec', 'spf', 'ssl']);
	});

	it('has 11 protective categories', () => {
		const protective = Object.entries(CATEGORY_TIERS).filter(([, t]) => t === 'protective');
		expect(protective).toHaveLength(11);
	});

	it('has 9 hardening categories', () => {
		const hardening = Object.entries(CATEGORY_TIERS).filter(([, t]) => t === 'hardening');
		expect(hardening).toHaveLength(9);
	});
});
