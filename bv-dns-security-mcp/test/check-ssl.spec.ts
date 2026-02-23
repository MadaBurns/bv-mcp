import { describe, it, expect, afterEach } from 'vitest';
import { setupFetchMock, mockFetchError } from './helpers/dns-mock';
import { vi } from 'vitest';

const { restore } = setupFetchMock();

afterEach(() => {
	restore();
});

describe('checkSsl', () => {
	async function run(domain = 'example.com') {
		const { checkSsl } = await import('../src/tools/check-ssl');
		return checkSsl(domain);
	}

	it('returns info finding when HTTPS connection succeeds', async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({
			url: 'https://example.com/',
			ok: true,
			status: 200,
		});
		const r = await run();
		expect(r.category).toBe('ssl');
		expect(r.findings).toHaveLength(1);
		expect(r.findings[0].severity).toBe('info');
		expect(r.findings[0].title).toContain('properly configured');
		expect(r.passed).toBe(true);
	});

	it('returns critical finding when HTTPS redirects to HTTP', async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({
			url: 'http://example.com/',
			ok: true,
			status: 200,
		});
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('redirects to HTTP'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('critical');
	});

	it('returns high finding on connection timeout', async () => {
		globalThis.fetch = vi.fn().mockRejectedValue(new Error('The operation was aborted due to timeout'));
		const r = await run();
		expect(r.findings).toHaveLength(1);
		expect(r.findings[0].severity).toBe('high');
		expect(r.findings[0].title).toContain('timeout');
	});

	it('returns critical finding on connection failure', async () => {
		mockFetchError(new Error('ECONNREFUSED'));
		const r = await run();
		expect(r.findings).toHaveLength(1);
		expect(r.findings[0].severity).toBe('critical');
		expect(r.findings[0].title).toContain('failed');
	});

	it('returns high finding on AbortError', async () => {
		const abortError = new Error('The operation was aborted');
		abortError.name = 'AbortError';
		globalThis.fetch = vi.fn().mockRejectedValue(abortError);
		const r = await run();
		expect(r.findings).toHaveLength(1);
		expect(r.findings[0].severity).toBe('high');
		expect(r.findings[0].title).toContain('timeout');
	});
});
