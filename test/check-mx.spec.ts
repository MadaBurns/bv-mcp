/**
 * MX record check tests for MCP server.
 */
import { describe, it, expect } from 'vitest';
import { checkMx } from '../../src/tools/check-mx';
import { setupFetchMock, mockMxRecords, restore } from '../helpers/dns-mock';

describe('checkMx', () => {
	beforeEach(() => setupFetchMock());
	afterEach(() => restore());

	it('returns fail if domain is invalid', async () => {
		const result = await checkMx('');
		expect(result.passed).toBe(false);
		expect(result.findings[0].title).toMatch(/Domain validation failed/);
	});

	it('returns fail if no MX records found', async () => {
		mockMxRecords('nomx.com', []);
		const result = await checkMx('nomx.com');
		expect(result.passed).toBe(false);
		expect(result.findings[0].title).toMatch(/No MX records found/);
	});

	it('returns pass if MX records found', async () => {
		mockMxRecords('hasmx.com', [
			{ data: '10 mx1.hasmx.com.' },
			{ data: '20 mx2.hasmx.com.' },
		]);
		const result = await checkMx('hasmx.com');
		expect(result.passed).toBe(true);
		expect(result.findings[0].title).toMatch(/MX records found/);
	});

	it('flags outbound provider if MX matches', async () => {
		mockMxRecords('outbound.com', [
			{ data: '10 aspmx.l.google.com.' },
		]);
		const result = await checkMx('outbound.com');
		expect(result.passed).toBe(true);
		const infoFinding = result.findings.find(f => f.severity === 'info');
		expect(infoFinding).toBeTruthy();
		expect(infoFinding?.title).toMatch(/Likely outbound email usage/);
	});
});
