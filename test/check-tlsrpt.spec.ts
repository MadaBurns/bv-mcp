import { describe, it, expect, afterEach } from 'vitest';
import { setupFetchMock, mockTxtRecords } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

describe('checkTlsrpt', () => {
	async function run(domain = 'example.com') {
		const { checkTlsrpt } = await import('../src/tools/check-tlsrpt');
		return checkTlsrpt(domain);
	}

	it('should return low finding when no TLS-RPT record exists', async () => {
		mockTxtRecords([]);
		const result = await run();
		expect(result.category).toBe('tlsrpt');
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('low');
		expect(result.findings[0].title).toMatch(/No TLS-RPT record/i);
	});

	it('should return info finding for valid record with mailto: URI', async () => {
		mockTxtRecords(['v=TLSRPTv1; rua=mailto:tlsrpt@example.com']);
		const result = await run();
		const finding = result.findings.find((f) => /TLS-RPT record configured/i.test(f.title));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('info');
	});

	it('should return info finding for valid record with https:// URI', async () => {
		mockTxtRecords(['v=TLSRPTv1; rua=https://report.example.com/tlsrpt']);
		const result = await run();
		const finding = result.findings.find((f) => /TLS-RPT record configured/i.test(f.title));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('info');
	});

	it('should return medium finding when rua= is missing', async () => {
		mockTxtRecords(['v=TLSRPTv1;']);
		const result = await run();
		const finding = result.findings.find((f) => /TLS-RPT record missing reporting URI/i.test(f.title));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('medium');
	});

	it('should return medium finding for invalid URI scheme', async () => {
		mockTxtRecords(['v=TLSRPTv1; rua=ftp://example.com/report']);
		const result = await run();
		const finding = result.findings.find((f) => /TLS-RPT invalid reporting URI scheme/i.test(f.title));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('medium');
	});

	it('should return medium finding for multiple TLS-RPT records', async () => {
		mockTxtRecords(['v=TLSRPTv1; rua=mailto:a@example.com', 'v=TLSRPTv1; rua=mailto:b@example.com']);
		const result = await run();
		const finding = result.findings.find((f) => /Multiple TLS-RPT records/i.test(f.title));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('medium');
	});

	it('should return info finding for record with multiple comma-separated valid URIs', async () => {
		mockTxtRecords(['v=TLSRPTv1; rua=mailto:a@example.com,https://report.example.com']);
		const result = await run();
		const finding = result.findings.find((f) => /TLS-RPT record configured/i.test(f.title));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('info');
	});
});
