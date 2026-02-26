import { describe, it, expect, afterEach } from 'vitest';
import { setupFetchMock, mockMxRecords } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

describe('checkMx', () => {
	async function run(domain = 'example.com') {
		const { checkMx } = await import('../src/tools/check-mx');
		return checkMx(domain);
	}

	it('should return fail if domain is invalid', async () => {
		const result = await run('');
		expect(result.passed).toBe(false);
		expect(result.findings[0].title).toMatch(/Domain validation failed/i);
	});

	it('should return fail if no MX records found', async () => {
		mockMxRecords('nomx.com', []);
		const result = await run('nomx.com');
		expect(result.passed).toBe(false);
		expect(result.findings[0].title).toMatch(/No MX records found/i);
	});

	it('should return pass if MX records found', async () => {
		mockMxRecords('hasmx.com', [
			{ data: '10 mx1.hasmx.com.' },
			{ data: '20 mx2.hasmx.com.' },
		]);
		const result = await run('hasmx.com');
		expect(result.passed).toBe(true);
		expect(result.findings[0].title).toMatch(/MX records found/i);
	});

	it('should flag outbound provider if MX matches', async () => {
		mockMxRecords('outbound.com', [
			{ data: '10 aspmx.l.google.com.' },
		]);
		const result = await run('outbound.com');
		expect(result.passed).toBe(true);
		const infoFinding = result.findings.find(f => f.severity === 'info');
		expect(infoFinding).toBeTruthy();
		expect(infoFinding!.title).toMatch(/Likely outbound email usage/i);
	});
});
