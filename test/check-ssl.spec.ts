import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, mockFetchError } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

describe('checkSsl', () => {
	async function run(domain = 'example.com') {
		const { checkSsl } = await import('../src/tools/check-ssl');
		return checkSsl(domain);
	}

	it('should return info finding when HTTPS connection succeeds', async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({ url: 'https://example.com/', ok: true, status: 200 });
		const result = await run();
		expect(result.category).toBe('ssl');
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('info');
		expect(result.findings[0].title).toMatch(/properly configured/i);
		expect(result.passed).toBe(true);
	});

	it('should return critical finding when HTTPS redirects to HTTP', async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({ url: 'http://example.com/', ok: true, status: 200 });
		const result = await run();
		const finding = result.findings.find(f => /redirects to HTTP/i.test(f.title));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('critical');
	});

	it('should return high finding on connection timeout', async () => {
		globalThis.fetch = vi.fn().mockRejectedValue(new Error('The operation was aborted due to timeout'));
		const result = await run();
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('high');
		expect(result.findings[0].title).toMatch(/timeout/i);
	});

	it('should return critical finding on connection failure', async () => {
		mockFetchError(new Error('ECONNREFUSED'));
		const result = await run();
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('critical');
		expect(result.findings[0].title).toMatch(/failed/i);
	});
});
