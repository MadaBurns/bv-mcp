import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

function mockMxRecords(domain: string, records: string[]) {
	const answers = records.map((data) => ({
		name: domain,
		type: 15,
		TTL: 300,
		data,
	}));
	globalThis.fetch = vi.fn().mockResolvedValue(createDohResponse([{ name: domain, type: 15 }], answers));
}

describe('checkMx', () => {
	async function run(domain = 'example.com') {
		const { checkMx } = await import('../src/tools/check-mx');
		return checkMx(domain);
	}

	it('should return high finding if domain is invalid', async () => {
		const result = await run('');
		expect(result.findings[0].severity).toBe('high');
		expect(result.findings[0].title).toMatch(/Domain validation failed/i);
	});

	it('should return high finding if no MX records found', async () => {
		mockMxRecords('nomx.com', []);
		const result = await run('nomx.com');
		expect(result.findings[0].severity).toBe('high');
		expect(result.findings[0].title).toMatch(/No MX records found/i);
	});

	it('should return pass if MX records found', async () => {
		mockMxRecords('hasmx.com', ['10 mx1.hasmx.com.', '20 mx2.hasmx.com.']);
		const result = await run('hasmx.com');
		expect(result.passed).toBe(true);
		expect(result.findings[0].title).toMatch(/MX records found/i);
	});

	it('should flag outbound provider if MX matches', async () => {
		mockMxRecords('outbound.com', ['10 aspmx.l.google.com.']);
		const result = await run('outbound.com');
		expect(result.passed).toBe(true);
		const infoFinding = result.findings.find((f) => f.severity === 'info' && f.title.includes('outbound'));
		expect(infoFinding).toBeTruthy();
		expect(infoFinding!.title).toMatch(/Likely outbound email usage/i);
	});

	it('returns correct category', async () => {
		mockMxRecords('example.com', ['10 mx.example.com.']);
		const result = await run('example.com');
		expect(result.category).toBe('mx');
	});
});
