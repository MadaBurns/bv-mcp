import { describe, expect, it, vi } from 'vitest';
import { type CheckResult, buildCheckResult, createFinding } from '../src/lib/scoring';

describe('scan-post-processing helpers', () => {
	it('downgrades missing email findings for non-mail domains when no MX records exist', async () => {
		vi.doMock('../src/lib/dns', () => ({
			queryTxtRecords: vi.fn().mockResolvedValue(['v=DMARC1; p=reject']),
		}));
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const results: CheckResult[] = [
			buildCheckResult('spf', [createFinding('spf', 'No SPF record found', 'critical', 'No SPF record found for example.com.')]),
			buildCheckResult('mx', [createFinding('mx', 'No MX records found', 'info', 'No inbound mail is configured.')]),
		];

		const updated = await applyScanPostProcessing('app.example.com', results);
		expect(updated[0].findings[0].severity).toBe('info');
		expect(updated[0].findings[0].detail).toContain('expected');
		vi.doUnmock('../src/lib/dns');
	});

	it('clarifies MTA-STS text for mail domains with MX records', async () => {
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const results: CheckResult[] = [
			buildCheckResult('mx', [createFinding('mx', 'MX records found', 'info', '2 MX records configured.')]),
			buildCheckResult('mta_sts', [
				createFinding('mta_sts', 'No MTA-STS or TLS-RPT records found', 'medium', 'Neither MTA-STS nor TLS-RPT DNS records were found.'),
			]),
		];

		const updated = await applyScanPostProcessing('example.com', results);
		const mtaSts = updated.find((r) => r.category === 'mta_sts');
		expect(mtaSts?.findings[0].detail).toContain('has MX records and accepts email');
		expect(mtaSts?.findings[0].detail).toContain('recommended');
	});

	it('does not clarify MTA-STS text when no MX records exist', async () => {
		vi.doMock('../src/lib/dns', () => ({
			queryTxtRecords: vi.fn().mockResolvedValue([]),
		}));
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const results: CheckResult[] = [
			buildCheckResult('mx', [createFinding('mx', 'No MX records found', 'info', 'No inbound mail.')]),
			buildCheckResult('mta_sts', [
				createFinding('mta_sts', 'No MTA-STS or TLS-RPT records found', 'medium', 'Neither MTA-STS nor TLS-RPT DNS records were found.'),
			]),
		];

		const updated = await applyScanPostProcessing('no-mail.example.com', results);
		const mtaSts = updated.find((r) => r.category === 'mta_sts');
		// For non-mail domains, severity gets downgraded to info (not clarified)
		expect(mtaSts?.findings[0].detail).not.toContain('has MX records and accepts email');
		vi.doUnmock('../src/lib/dns');
	});

	it('adds outbound provider inference when SPF include domains match provider signatures', async () => {
		const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');

		const results: CheckResult[] = [
			buildCheckResult('spf', [createFinding('spf', 'SPF record configured', 'info', 'Healthy SPF', { includeDomains: ['google.com'] })]),
			buildCheckResult('dkim', []),
			buildCheckResult('mx', []),
		];

		const updated = await applyScanPostProcessing('example.com', results);
		const spf = updated.find((result) => result.category === 'spf');
		expect(spf?.findings.some((finding) => finding.title === 'Outbound email provider inferred')).toBe(true);
	});
});