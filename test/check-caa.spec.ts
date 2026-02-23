import { describe, it, expect, vi, afterEach } from 'vitest';
import { RecordType, parseCaaRecord } from '../src/lib/dns';
import { setupFetchMock, createDohResponse, mockFetchResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

function mockCaaRecords(records: string[]) {
	const answers = records.map((data) => ({
		name: 'example.com',
		type: RecordType.CAA,
		TTL: 300,
		data,
	}));
	globalThis.fetch = vi.fn().mockResolvedValue(createDohResponse([{ name: 'example.com', type: 257 }], answers));
}

function mockCaaFailure() {
	mockFetchResponse({}, false, 500);
}

afterEach(() => {
	restore();
});

describe('checkCaa', () => {
	async function runCheckCaa(domain: string) {
		const { checkCaa } = await import('../src/tools/check-caa');
		return checkCaa(domain);
	}

	it('reports medium finding when no CAA records exist', async () => {
		mockCaaRecords([]);
		const result = await runCheckCaa('example.com');
		expect(result.category).toBe('caa');
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('medium');
		expect(result.findings[0].title).toContain('No CAA');
	});

	it('reports medium finding when CAA query fails', async () => {
		mockCaaFailure();
		const result = await runCheckCaa('example.com');
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('medium');
		expect(result.findings[0].title).toContain('failed');
	});

	it('reports medium finding when no issue tag present', async () => {
		mockCaaRecords(['0 iodef "mailto:admin@example.com"']);
		const result = await runCheckCaa('example.com');
		const issueFinding = result.findings.find((f) => f.title.includes('issue tag'));
		expect(issueFinding).toBeDefined();
		expect(issueFinding!.severity).toBe('medium');
	});

	it('reports low finding when no issuewild tag present', async () => {
		mockCaaRecords(['0 issue "letsencrypt.org"']);
		const result = await runCheckCaa('example.com');
		const issuewildFinding = result.findings.find((f) => f.title.includes('issuewild'));
		expect(issuewildFinding).toBeDefined();
		expect(issuewildFinding!.severity).toBe('low');
	});

	it('reports low finding when no iodef tag present', async () => {
		mockCaaRecords(['0 issue "letsencrypt.org"']);
		const result = await runCheckCaa('example.com');
		const iodefFinding = result.findings.find((f) => f.title.includes('iodef'));
		expect(iodefFinding).toBeDefined();
		expect(iodefFinding!.severity).toBe('low');
	});

	it('reports info finding when all CAA tags are present', async () => {
		mockCaaRecords(['0 issue "letsencrypt.org"', '0 issuewild "letsencrypt.org"', '0 iodef "mailto:admin@example.com"']);
		const result = await runCheckCaa('example.com');
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('info');
		expect(result.findings[0].title).toContain('properly configured');
		expect(result.passed).toBe(true);
	});

	it('handles CAA record with tab separator', async () => {
		mockCaaRecords(['0 issue\t"letsencrypt.org"']);
		const result = await runCheckCaa('example.com');
		const issueFinding = result.findings.find((f) => f.title.includes('issue tag'));
		expect(issueFinding).toBeUndefined();
	});

	it('handles multiple CAA records with mixed tags', async () => {
		mockCaaRecords(['0 issue "digicert.com"', '0 issue "letsencrypt.org"', '0 iodef "mailto:security@example.com"']);
		const result = await runCheckCaa('example.com');
		const issuewildFinding = result.findings.find((f) => f.title.includes('issuewild'));
		expect(issuewildFinding).toBeDefined();
		expect(issuewildFinding!.severity).toBe('low');
	});

	it('handles case-insensitive CAA tag matching', async () => {
		mockCaaRecords(['0 ISSUE "letsencrypt.org"']);
		const result = await runCheckCaa('example.com');
		const issueFinding = result.findings.find((f) => f.title.includes('issue tag'));
		expect(issueFinding).toBeUndefined();
	});

	it('parses hex wire format CAA records from Cloudflare DoH', async () => {
		// issue "letsencrypt.org" in hex wire format
		// flags=0x00, tag_len=0x05, tag="issue", value="letsencrypt.org"
		mockCaaRecords([
			'\\# 16 00 05 69 73 73 75 65 6c 65 74 73 65 6e 63 72 79 70 74 2e 6f 72 67',
			'\\# 1a 00 09 69 73 73 75 65 77 69 6c 64 6c 65 74 73 65 6e 63 72 79 70 74 2e 6f 72 67',
			'\\# 1f 00 05 69 6f 64 65 66 6d 61 69 6c 74 6f 3a 61 64 6d 69 6e 40 65 78 61 6d 70 6c 65 2e 63 6f 6d',
		]);
		const result = await runCheckCaa('example.com');
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('info');
		expect(result.findings[0].title).toContain('properly configured');
	});

	it('parses hex wire format with missing issuewild tag', async () => {
		// Only issue tag in hex wire format
		mockCaaRecords(['\\# 16 00 05 69 73 73 75 65 6c 65 74 73 65 6e 63 72 79 70 74 2e 6f 72 67']);
		const result = await runCheckCaa('example.com');
		const issuewildFinding = result.findings.find((f) => f.title.includes('issuewild'));
		expect(issuewildFinding).toBeDefined();
		expect(issuewildFinding!.severity).toBe('low');
		// Confirm issue tag WAS detected
		const issueFinding = result.findings.find((f) => f.title.includes('issue tag'));
		expect(issueFinding).toBeUndefined();
	});
});

describe('parseCaaRecord', () => {
	it('parses human-readable format', () => {
		const r = parseCaaRecord('0 issue "letsencrypt.org"');
		expect(r).toEqual({ flags: 0, tag: 'issue', value: 'letsencrypt.org' });
	});

	it('parses hex wire format', () => {
		const r = parseCaaRecord('\\# 16 00 05 69 73 73 75 65 6c 65 74 73 65 6e 63 72 79 70 74 2e 6f 72 67');
		expect(r).toEqual({ flags: 0, tag: 'issue', value: 'letsencrypt.org' });
	});

	it('parses issuewild hex wire format', () => {
		const r = parseCaaRecord('\\# 1a 00 09 69 73 73 75 65 77 69 6c 64 6c 65 74 73 65 6e 63 72 79 70 74 2e 6f 72 67');
		expect(r).toEqual({ flags: 0, tag: 'issuewild', value: 'letsencrypt.org' });
	});

	it('returns null for malformed data', () => {
		expect(parseCaaRecord('\\# 01')).toBeNull();
		expect(parseCaaRecord('garbage')).toBeNull();
	});
});
