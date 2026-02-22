import { describe, it, expect, vi, afterEach } from 'vitest';
import { RecordType } from '../src/lib/dns';

// Mock fetch globally to control DNS responses for SPF checks
const originalFetch = globalThis.fetch;

function mockTxtRecords(records: string[]) {
	const answers = records.map((data) => ({
		name: 'example.com',
		type: RecordType.TXT,
		TTL: 300,
		data: `"${data}"`,
	}));
	globalThis.fetch = vi.fn().mockResolvedValue({
		ok: true,
		status: 200,
		json: () => Promise.resolve({
			Status: 0, TC: false, RD: true, RA: true, AD: false, CD: false,
			Question: [{ name: 'example.com', type: 16 }],
			Answer: answers,
		}),
	} as unknown as Response);
}

afterEach(() => {
	globalThis.fetch = originalFetch;
});

describe('checkSpf', () => {
	// Dynamic import to ensure mocks are in place
	async function runCheckSpf(domain: string) {
		const { checkSpf } = await import('../src/tools/check-spf');
		return checkSpf(domain);
	}

	it('reports critical finding when no SPF record exists', async () => {
		mockTxtRecords([]);
		const result = await runCheckSpf('example.com');
		expect(result.category).toBe('spf');
		expect(result.score).toBe(60); // 100 - 40 (critical penalty)
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('critical');
		expect(result.findings[0].title).toContain('No SPF');
	});

	it('reports high finding for multiple SPF records', async () => {
		mockTxtRecords(['v=spf1 -all', 'v=spf1 ~all']);
		const result = await runCheckSpf('example.com');
		const multipleRecordFinding = result.findings.find((f) => f.title.includes('Multiple SPF'));
		expect(multipleRecordFinding).toBeDefined();
		expect(multipleRecordFinding!.severity).toBe('high');
	});

	it('reports critical finding for +all', async () => {
		mockTxtRecords(['v=spf1 +all']);
		const result = await runCheckSpf('example.com');
		const permissiveFinding = result.findings.find((f) => f.title.includes('Permissive'));
		expect(permissiveFinding).toBeDefined();
		expect(permissiveFinding!.severity).toBe('critical');
	});

	it('reports critical finding for ?all', async () => {
		mockTxtRecords(['v=spf1 ?all']);
		const result = await runCheckSpf('example.com');
		const permissiveFinding = result.findings.find((f) => f.title.includes('Permissive'));
		expect(permissiveFinding).toBeDefined();
		expect(permissiveFinding!.severity).toBe('critical');
	});

	it('reports low finding for ~all (soft fail)', async () => {
		mockTxtRecords(['v=spf1 include:_spf.google.com ~all']);
		const result = await runCheckSpf('example.com');
		const softFailFinding = result.findings.find((f) => f.title.includes('soft fail'));
		expect(softFailFinding).toBeDefined();
		expect(softFailFinding!.severity).toBe('low');
	});

	it('reports no issues for -all (hard fail)', async () => {
		mockTxtRecords(['v=spf1 include:_spf.google.com -all']);
		const result = await runCheckSpf('example.com');
		// Should only have an info finding
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('info');
		expect(result.passed).toBe(true);
	});

	it('reports medium finding when no all mechanism present', async () => {
		mockTxtRecords(['v=spf1 include:_spf.google.com']);
		const result = await runCheckSpf('example.com');
		const noAllFinding = result.findings.find((f) => f.title.includes("No 'all'"));
		expect(noAllFinding).toBeDefined();
		expect(noAllFinding!.severity).toBe('medium');
	});

	it('reports high finding for too many DNS lookups', async () => {
		const mechanisms = Array.from({ length: 11 }, (_, i) => `include:spf${i}.example.com`).join(' ');
		mockTxtRecords([`v=spf1 ${mechanisms} -all`]);
		const result = await runCheckSpf('example.com');
		const lookupFinding = result.findings.find((f) => f.title.includes('Too many DNS'));
		expect(lookupFinding).toBeDefined();
		expect(lookupFinding!.severity).toBe('high');
	});

	it('reports medium finding for deprecated ptr mechanism', async () => {
		mockTxtRecords(['v=spf1 ptr -all']);
		const result = await runCheckSpf('example.com');
		const ptrFinding = result.findings.find((f) => f.title.includes('ptr'));
		expect(ptrFinding).toBeDefined();
		expect(ptrFinding!.severity).toBe('medium');
	});

	it('ignores non-SPF TXT records', async () => {
		mockTxtRecords(['google-site-verification=abc123', 'v=DMARC1; p=reject']);
		const result = await runCheckSpf('example.com');
		expect(result.findings[0].title).toContain('No SPF');
	});
});

