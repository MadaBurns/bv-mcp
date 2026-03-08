import { describe, expect, it } from 'vitest';
import { formatScanReport } from '../src/tools/scan/format-report';
import type { ScanDomainResult } from '../src/tools/scan-domain';

describe('format-scan-report', () => {
	it('renders scan summaries without changing report structure', () => {
		const result: ScanDomainResult = {
			domain: 'example.com',
			score: {
				overall: 72,
				grade: 'C+',
				categoryScores: {
					spf: 70,
					dmarc: 80,
					dkim: 65,
					dnssec: 100,
					ssl: 90,
					mta_sts: 50,
					ns: 100,
					caa: 100,
					subdomain_takeover: 100,
					mx: 100,
				},
				findings: [
					{
						category: 'subdomain_takeover',
						title: 'Dangling CNAME',
						severity: 'critical',
						detail: 'Potential takeover vector.',
						metadata: { verificationStatus: 'potential', confidence: 'heuristic' },
					},
				],
				summary: '1 issue(s) found. Grade: C+',
			},
			checks: [],
			cached: true,
			timestamp: '2026-03-07T00:00:00.000Z',
		};

		const report = formatScanReport(result);
		expect(report).toContain('DNS Security Scan: example.com');
		expect(report).toContain('Overall Score: 72/100 (C+)');
		expect(report).toContain('Takeover Verification: potential');
		expect(report).toContain('Confidence: heuristic');
		expect(report).toContain('Results served from cache');
	});
});