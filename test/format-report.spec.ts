// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect } from 'vitest';
import type { ScanDomainResult } from '../src/tools/scan-domain';
import { buildStructuredScanResult } from '../src/tools/scan/format-report';

function makeMockScanResult(overrides: Partial<ScanDomainResult> = {}): ScanDomainResult {
	return {
		domain: 'example.com',
		score: { overall: 80, grade: 'B', categoryScores: {} as any, findings: [], summary: 'ok' },
		checks: [],
		maturity: null as any,
		context: { profile: 'mail_enabled' as any, signals: [], weights: {} as any, detectedProvider: null },
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
			] as any,
		});
		const s = buildStructuredScanResult(result);
		expect(s.checkStatuses).toEqual({ spf: 'completed', dmarc: 'timeout', ssl: 'error' });
	});

	it('defaults missing checkStatus to completed', () => {
		const result = makeMockScanResult({
			checks: [{ category: 'spf', passed: true, score: 100, findings: [] }] as any,
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
			}] as any,
		});
		const s = buildStructuredScanResult(result);
		expect(s.dnssecSource).toBe('tld_inherited');
	});

	it('defaults dnssecSource to domain_configured when dnssec passed with no source finding', () => {
		const result = makeMockScanResult({
			checks: [{ category: 'dnssec', passed: true, score: 100, findings: [], checkStatus: 'completed' }] as any,
		});
		const s = buildStructuredScanResult(result);
		expect(s.dnssecSource).toBe('domain_configured');
	});

	it('sets dnssecSource to null when dnssec check failed', () => {
		const result = makeMockScanResult({
			checks: [{ category: 'dnssec', passed: false, score: 0, findings: [], checkStatus: 'completed' }] as any,
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
			checks: [{ category: 'dnssec', passed: true, score: 100, findings: [], checkStatus: 'timeout' }] as any,
		});
		const s = buildStructuredScanResult(result);
		expect(s.dnssecSource).toBeNull();
	});

	it('derives cdnProvider from http_security finding metadata', () => {
		const result = makeMockScanResult({
			checks: [{
				category: 'http_security', passed: true, score: 100,
				findings: [{ category: 'http_security', title: 'CDN', severity: 'info', detail: 'x', metadata: { cdnProvider: 'Cloudflare' } }],
			}] as any,
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
			}] as any,
		});
		const s = buildStructuredScanResult(result);
		expect(s.cdnProvider).toBeNull();
	});

	it('sets notApplicableCategories for web_only profile with all-info email findings', () => {
		const result = makeMockScanResult({
			context: { profile: 'web_only' as any, signals: [], weights: {} as any, detectedProvider: null },
			checks: [
				{ category: 'spf', passed: true, score: 100, findings: [{ category: 'spf', title: 'No SPF record found', severity: 'info', detail: 'expected' }] },
				{ category: 'dmarc', passed: true, score: 100, findings: [] },
			] as any,
		});
		const s = buildStructuredScanResult(result);
		expect(s.notApplicableCategories).toContain('spf');
		expect(s.notApplicableCategories).toContain('dmarc');
	});

	it('sets notApplicableCategories for non_mail profile', () => {
		const result = makeMockScanResult({
			context: { profile: 'non_mail' as any, signals: [], weights: {} as any, detectedProvider: null },
			checks: [
				{ category: 'dkim', passed: true, score: 100, findings: [] },
				{ category: 'mta_sts', passed: true, score: 100, findings: [{ category: 'mta_sts', title: 'No MTA-STS', severity: 'info', detail: 'N/A' }] },
			] as any,
		});
		const s = buildStructuredScanResult(result);
		expect(s.notApplicableCategories).toContain('dkim');
		expect(s.notApplicableCategories).toContain('mta_sts');
	});

	it('does not set notApplicableCategories for mail_enabled profile', () => {
		const result = makeMockScanResult({
			context: { profile: 'mail_enabled' as any, signals: [], weights: {} as any, detectedProvider: null },
			checks: [
				{ category: 'spf', passed: true, score: 100, findings: [] },
			] as any,
		});
		const s = buildStructuredScanResult(result);
		expect(s.notApplicableCategories).toEqual([]);
	});

	it('does not mark email category as N/A when it has non-info findings', () => {
		const result = makeMockScanResult({
			context: { profile: 'web_only' as any, signals: [], weights: {} as any, detectedProvider: null },
			checks: [
				{ category: 'spf', passed: false, score: 50, findings: [{ category: 'spf', title: 'Weak SPF', severity: 'medium', detail: 'some issue' }] },
			] as any,
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
