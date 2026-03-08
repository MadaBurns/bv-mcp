import { describe, expect, it, vi } from 'vitest';
import type { CheckResult } from '../src/lib/scoring';

describe('scan-post-processing helpers', () => {
	it('downgrades missing email findings for non-mail domains when no MX records exist', async () => {
		vi.doMock('../src/lib/dns', () => ({
			queryTxtRecords: vi.fn().mockResolvedValue(['v=DMARC1; p=reject']),
		}));
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const results: CheckResult[] = [
			{
				category: 'spf',
				passed: false,
				score: 0,
				findings: [{ category: 'spf', title: 'No SPF record found', severity: 'critical', detail: 'No SPF record found for example.com.' }],
			},
			{
				category: 'mx',
				passed: true,
				score: 100,
				findings: [{ category: 'mx', title: 'No MX records found', severity: 'info', detail: 'No inbound mail is configured.' }],
			},
		];

		const updated = await applyScanPostProcessing('app.example.com', results);
		expect(updated[0].findings[0].severity).toBe('info');
		expect(updated[0].findings[0].detail).toContain('expected');
		vi.doUnmock('../src/lib/dns');
	});

	it('adds outbound provider inference when SPF include domains match provider signatures', async () => {
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const results: CheckResult[] = [
			{
				category: 'spf',
				passed: true,
				score: 100,
				findings: [
					{
						category: 'spf',
						title: 'SPF record configured',
						severity: 'info',
						detail: 'Healthy SPF',
						metadata: { includeDomains: ['google.com'] },
					},
				],
			},
			{
				category: 'dkim',
				passed: true,
				score: 100,
				findings: [],
			},
			{
				category: 'mx',
				passed: true,
				score: 100,
				findings: [],
			},
		];

		const updated = await applyScanPostProcessing('example.com', results);
		const spf = updated.find((result) => result.category === 'spf');
		expect(spf?.findings.some((finding) => finding.title === 'Outbound email provider inferred')).toBe(true);
	});
});