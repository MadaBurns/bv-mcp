import { describe, it, expect, vi, afterEach } from 'vitest';
import { RecordType } from '../src/lib/dns';

const originalFetch = globalThis.fetch;

function mockCaaRecords(records: string[]) {
	const answers = records.map((data) => ({
		name: 'example.com',
		type: RecordType.CAA,
		TTL: 300,
		data,
	}));
	globalThis.fetch = vi.fn().mockResolvedValue({
		ok: true,
		status: 200,
		json: () => Promise.resolve({
			Status: 0, TC: false, RD: true, RA: true, AD: false, CD: false,
			Question: [{ name: 'example.com', type: 257 }],
			Answer: answers,
		}),
	} as unknown as Response);
}

function mockCaaFailure() {
	globalThis.fetch = vi.fn().mockResolvedValue({
		ok: false,
		status: 500,
	} as unknown as Response);
}

afterEach(() => {
	globalThis.fetch = originalFetch;
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
		mockCaaRecords([
			'0 issue "letsencrypt.org"',
			'0 issuewild "letsencrypt.org"',
			'0 iodef "mailto:admin@example.com"',
		]);
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
		mockCaaRecords([
			'0 issue "digicert.com"',
			'0 issue "letsencrypt.org"',
			'0 iodef "mailto:security@example.com"',
		]);
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
});
