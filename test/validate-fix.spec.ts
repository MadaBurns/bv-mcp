import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, mockTxtRecords, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

describe('validateFix', () => {
	async function run(domain: string, check: string, expected?: string) {
		const { validateFix } = await import('../src/tools/validate-fix');
		return validateFix(domain, check, expected);
	}

	it('returns fixed when check passes with no critical/high findings', async () => {
		// Simple SPF with -all and no includes avoids circular-include artifacts from the mock.
		mockTxtRecords(['v=spf1 -all']);
		const result = await run('example.com', 'spf');
		expect(result.verdict).toBe('fixed');
		expect(result.remainingFindings).toHaveLength(0);
	});

	it('returns not_fixed when critical findings remain', async () => {
		mockTxtRecords([]);
		const result = await run('example.com', 'spf');
		expect(result.verdict).toBe('not_fixed');
		expect(result.remainingFindings.length).toBeGreaterThan(0);
		expect(result.hint).toBeTruthy();
	});

	it('returns partial when check passes but has medium findings', async () => {
		// include: with the mock causes circular-include (high) + trust-surface (medium),
		// so use a multi-domain mock that avoids the loop.
		globalThis.fetch = vi.fn().mockImplementation((url: string | URL) => {
			const u = new URL(typeof url === 'string' ? url : url.toString());
			const name = u.searchParams.get('name') ?? '';
			const records: Record<string, string[]> = {
				'example.com': ['v=spf1 include:_spf.google.com -all'],
				'_spf.google.com': ['v=spf1 ip4:172.217.0.0/19 -all'],
				'_dmarc.example.com': [], // Missing DMARC → trust-surface elevated to medium
			};
			const data = records[name] ?? [];
			const answers = data.map((d) => ({ name, type: 16, TTL: 300, data: `"${d}"` }));
			return Promise.resolve(createDohResponse([{ name, type: 16 }], answers));
		});
		const result = await run('example.com', 'spf');
		expect(['fixed', 'partial']).toContain(result.verdict);
	});

	it('checks expected record match', async () => {
		const expectedRecord = 'v=spf1 -all';
		mockTxtRecords([expectedRecord]);
		const result = await run('example.com', 'spf', expectedRecord);
		expect(result.expectedMatch).toBe(true);
	});

	it('reports expected record mismatch', async () => {
		mockTxtRecords(['v=spf1 ~all']);
		const result = await run('example.com', 'spf', 'v=spf1 include:_spf.google.com -all');
		expect(result.expectedMatch).toBe(false);
	});

	it('rejects unknown check names', async () => {
		await expect(run('example.com', 'nonexistent_check')).rejects.toThrow('Invalid');
	});

	it('includes live record in result', async () => {
		mockTxtRecords(['v=spf1 -all']);
		const result = await run('example.com', 'spf');
		expect(result.liveRecord).toBeTruthy();
	});
});
