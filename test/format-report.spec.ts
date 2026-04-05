// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect } from 'vitest';
import type { ScanDomainResult, MaturityStage } from '../src/tools/scan-domain';
import type { CheckCategory, CheckResult, ScanScore, DomainContext } from '../src/lib/scoring';
import { buildStructuredScanResult, formatScanReport } from '../src/tools/scan/format-report';

function makeMockScanResult(overrides: Partial<ScanDomainResult> = {}): ScanDomainResult {
	return {
		domain: 'example.com',
		score: { overall: 80, grade: 'B', categoryScores: {} as Record<CheckCategory, number>, findings: [], summary: 'ok' } as ScanScore,
		checks: [],
		maturity: null as unknown as MaturityStage,
		context: { profile: 'mail_enabled', signals: [], weights: {}, detectedProvider: null } as DomainContext,
		cached: false,
		timestamp: '2026-04-05T00:00:00Z',
		scoringNote: null,
		adaptiveWeightDeltas: null,
		interactionEffects: [],
		...overrides,
	};
}

describe('buildStructuredScanResult', () => {
	it('populates checkStatuses from check results', () => {
		const result = makeMockScanResult({
			checks: [
				{ category: 'spf', passed: true, score: 100, findings: [], checkStatus: 'completed' },
				{ category: 'dmarc', passed: false, score: 0, findings: [], checkStatus: 'timeout' },
				{ category: 'ssl', passed: false, score: 0, findings: [], checkStatus: 'error' },
			] as CheckResult[],
		});
		const s = buildStructuredScanResult(result);
		expect(s.checkStatuses).toEqual({ spf: 'completed', dmarc: 'timeout', ssl: 'error' });
	});

	it('defaults missing checkStatus to completed', () => {
		const result = makeMockScanResult({
			checks: [{ category: 'spf', passed: true, score: 100, findings: [] }] as CheckResult[],
		});
		const s = buildStructuredScanResult(result);
		expect(s.checkStatuses.spf).toBe('completed');
	});

	it('derives dnssecSource from finding metadata', () => {
		const result = makeMockScanResult({
			checks: [{
				category: 'dnssec', passed: true, score: 100,
				findings: [{ category: 'dnssec', title: 'DNSSEC inherited from TLD', severity: 'info', detail: 'x', metadata: { dnssecSource: 'tld_inherited' } }],
				checkStatus: 'completed',
			}] as CheckResult[],
		});
		const s = buildStructuredScanResult(result);
		expect(s.dnssecSource).toBe('tld_inherited');
	});

	it('defaults dnssecSource to domain_configured when dnssec passed with no source finding', () => {
		const result = makeMockScanResult({
			checks: [{ category: 'dnssec', passed: true, score: 100, findings: [], checkStatus: 'completed' }] as CheckResult[],
		});
		const s = buildStructuredScanResult(result);
		expect(s.dnssecSource).toBe('domain_configured');
	});

	it('sets dnssecSource to null when dnssec check failed', () => {
		const result = makeMockScanResult({
			checks: [{ category: 'dnssec', passed: false, score: 0, findings: [], checkStatus: 'completed' }] as CheckResult[],
		});
		const s = buildStructuredScanResult(result);
		expect(s.dnssecSource).toBeNull();
	});

	it('sets dnssecSource to null when dnssec check not present', () => {
		const result = makeMockScanResult({ checks: [] });
		const s = buildStructuredScanResult(result);
		expect(s.dnssecSource).toBeNull();
	});

	it('sets dnssecSource to null when dnssec check timed out (even if passed=true)', () => {
		const result = makeMockScanResult({
			checks: [{ category: 'dnssec', passed: true, score: 100, findings: [], checkStatus: 'timeout' }] as CheckResult[],
		});
		const s = buildStructuredScanResult(result);
		expect(s.dnssecSource).toBeNull();
	});

	it('derives cdnProvider from http_security finding metadata', () => {
		const result = makeMockScanResult({
			checks: [{
				category: 'http_security', passed: true, score: 100,
				findings: [{ category: 'http_security', title: 'CDN', severity: 'info', detail: 'x', metadata: { cdnProvider: 'Cloudflare' } }],
			}] as CheckResult[],
		});
		const s = buildStructuredScanResult(result);
		expect(s.cdnProvider).toBe('Cloudflare');
	});

	it('sets cdnProvider to null when no http_security check', () => {
		const result = makeMockScanResult({ checks: [] });
		const s = buildStructuredScanResult(result);
		expect(s.cdnProvider).toBeNull();
	});

	it('sets cdnProvider to null when no cdnProvider metadata in findings', () => {
		const result = makeMockScanResult({
			checks: [{
				category: 'http_security', passed: true, score: 100,
				findings: [{ category: 'http_security', title: 'HSTS', severity: 'info', detail: 'x', metadata: {} }],
			}] as CheckResult[],
		});
		const s = buildStructuredScanResult(result);
		expect(s.cdnProvider).toBeNull();
	});

	it('sets notApplicableCategories for web_only profile with all-info email findings', () => {
		const result = makeMockScanResult({
			context: { profile: 'web_only', signals: [], weights: {}, detectedProvider: null } as DomainContext,
			checks: [
				{ category: 'spf', passed: true, score: 100, findings: [{ category: 'spf', title: 'No SPF record found', severity: 'info', detail: 'expected' }] },
				{ category: 'dmarc', passed: true, score: 100, findings: [] },
			] as CheckResult[],
		});
		const s = buildStructuredScanResult(result);
		expect(s.notApplicableCategories).toContain('spf');
		expect(s.notApplicableCategories).toContain('dmarc');
	});

	it('sets notApplicableCategories for non_mail profile', () => {
		const result = makeMockScanResult({
			context: { profile: 'non_mail', signals: [], weights: {}, detectedProvider: null } as DomainContext,
			checks: [
				{ category: 'dkim', passed: true, score: 100, findings: [] },
				{ category: 'mta_sts', passed: true, score: 100, findings: [{ category: 'mta_sts', title: 'No MTA-STS', severity: 'info', detail: 'N/A' }] },
			] as CheckResult[],
		});
		const s = buildStructuredScanResult(result);
		expect(s.notApplicableCategories).toContain('dkim');
		expect(s.notApplicableCategories).toContain('mta_sts');
	});

	it('does not set notApplicableCategories for mail_enabled profile', () => {
		const result = makeMockScanResult({
			context: { profile: 'mail_enabled', signals: [], weights: {}, detectedProvider: null } as DomainContext,
			checks: [
				{ category: 'spf', passed: true, score: 100, findings: [] },
			] as CheckResult[],
		});
		const s = buildStructuredScanResult(result);
		expect(s.notApplicableCategories).toEqual([]);
	});

	it('does not mark email category as N/A when it has non-info findings', () => {
		const result = makeMockScanResult({
			context: { profile: 'web_only', signals: [], weights: {}, detectedProvider: null } as DomainContext,
			checks: [
				{ category: 'spf', passed: false, score: 50, findings: [{ category: 'spf', title: 'Weak SPF', severity: 'medium', detail: 'some issue' }] },
			] as CheckResult[],
		});
		const s = buildStructuredScanResult(result);
		expect(s.notApplicableCategories).not.toContain('spf');
	});

	it('returns empty checkStatuses when checks array is empty', () => {
		const result = makeMockScanResult({ checks: [] });
		const s = buildStructuredScanResult(result);
		expect(s.checkStatuses).toEqual({});
	});

	it('includes enrichment fields when provided', () => {
		const result = makeMockScanResult();
		const s = buildStructuredScanResult(result, { percentileRank: 75, spoofabilityScore: 30 });
		expect(s.percentileRank).toBe(75);
		expect(s.spoofabilityScore).toBe(30);
	});
});

describe('formatScanReport web-only email categories', () => {
	it('shows N/A for email categories when web_only and findings are all info', () => {
		const result = makeMockScanResult({
			score: {
				overall: 85,
				grade: 'A',
				categoryScores: { spf: 100, dmarc: 100, ssl: 90 } as Record<CheckCategory, number>,
				findings: [],
				summary: 'ok',
			} as ScanScore,
			context: { profile: 'web_only', signals: [], weights: {}, detectedProvider: null } as DomainContext,
			checks: [
				{
					category: 'spf', passed: true, score: 100,
					findings: [{ category: 'spf', title: 'No SPF record found', severity: 'info', detail: 'expected' }],
				},
				{ category: 'dmarc', passed: true, score: 100, findings: [] },
				{ category: 'ssl', passed: true, score: 90, findings: [] },
			] as CheckResult[],
		});
		const output = formatScanReport(result, 'compact');
		expect(output).toContain('∅ SPF        N/A');
		expect(output).toContain('∅ DMARC      N/A');
		expect(output).not.toContain('SPF        100/100');
		// SSL is not an email category — should still show score
		expect(output).toContain('SSL');
		expect(output).toContain('90/100');
	});

	it('does NOT show N/A for mail_enabled profile even if findings are info', () => {
		const result = makeMockScanResult({
			score: {
				overall: 90,
				grade: 'A',
				categoryScores: { spf: 100 } as Record<CheckCategory, number>,
				findings: [],
				summary: 'ok',
			} as ScanScore,
			context: { profile: 'mail_enabled', signals: [], weights: {}, detectedProvider: null } as DomainContext,
			checks: [
				{ category: 'spf', passed: true, score: 100, findings: [{ category: 'spf', title: 'Info', severity: 'info', detail: 'x' }] },
			] as CheckResult[],
		});
		const output = formatScanReport(result, 'compact');
		expect(output).not.toContain('N/A');
		expect(output).toContain('100/100');
	});
});

describe('formatScanReport compact truncation', () => {
	it('does not truncate critical finding detail in compact mode', () => {
		const longDetail = 'A'.repeat(280) + ' END';
		const result = makeMockScanResult({
			score: {
				overall: 50,
				grade: 'D',
				categoryScores: {} as Record<CheckCategory, number>,
				findings: [{
					category: 'spf' as CheckCategory,
					title: 'Critical SPF issue',
					severity: 'critical' as const,
					detail: longDetail,
				}],
				summary: 'ok',
			} as ScanScore,
			checks: [],
		});
		const output = formatScanReport(result, 'compact');
		expect(output).toContain('END');
	});

	it('truncates medium finding detail at 300 chars in compact mode', () => {
		const longDetail = 'B'.repeat(350);
		const result = makeMockScanResult({
			score: {
				overall: 70,
				grade: 'C',
				categoryScores: {} as Record<CheckCategory, number>,
				findings: [{
					category: 'spf' as CheckCategory,
					title: 'Medium SPF issue',
					severity: 'medium' as const,
					detail: longDetail,
				}],
				summary: 'ok',
			} as ScanScore,
			checks: [],
		});
		const output = formatScanReport(result, 'compact');
		// Should truncate — the 350-char detail should be cut to 300 + '...'
		expect(output).toContain('...');
		// But should NOT contain the END of the string (chars 301-350)
		// Since it's all B's, just check the total finding line doesn't include all 350 B's
		const bCount = (output.match(/B/g) || []).length;
		expect(bCount).toBeLessThanOrEqual(300);
	});
});
