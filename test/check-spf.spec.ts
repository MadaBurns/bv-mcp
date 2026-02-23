import { describe, it, expect, vi, afterEach } from 'vitest';
import { RecordType } from '../src/lib/dns';

const originalFetch = globalThis.fetch;

/** Helper: mock DoH to return the given TXT record strings */
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
		json: () =>
			Promise.resolve({
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
	async function run(domain = 'example.com') {
		const { checkSpf } = await import('../src/tools/check-spf');
		return checkSpf(domain);
	}

	it('returns critical finding when no SPF record exists', async () => {
		mockTxtRecords([]);
		const r = await run();
		expect(r.category).toBe('spf');
		expect(r.findings).toHaveLength(1);
		expect(r.findings[0].severity).toBe('critical');
		expect(r.findings[0].title).toContain('No SPF');
	});

	it('returns high finding for multiple SPF records', async () => {
		mockTxtRecords(['v=spf1 -all', 'v=spf1 ~all']);
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('Multiple SPF'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('high');
	});

	it('returns critical finding for +all', async () => {
		mockTxtRecords(['v=spf1 +all']);
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('Permissive'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('critical');
	});

	it('returns critical finding for ?all', async () => {
		mockTxtRecords(['v=spf1 ?all']);
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('Permissive'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('critical');
	});

	it('returns low finding for ~all (soft fail)', async () => {
		mockTxtRecords(['v=spf1 include:_spf.google.com ~all']);
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('soft fail'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('low');
	});

	it('returns info finding for -all (hard fail, best practice)', async () => {
		mockTxtRecords(['v=spf1 include:_spf.google.com -all']);
		const r = await run();
		expect(r.findings).toHaveLength(1);
		expect(r.findings[0].severity).toBe('info');
		expect(r.passed).toBe(true);
		expect(r.score).toBe(100);
	});

	it('returns medium finding when no all mechanism present', async () => {
		mockTxtRecords(['v=spf1 include:_spf.google.com']);
		const r = await run();
		const f = r.findings.find((f) => f.title.includes("No 'all'"));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('medium');
	});

	it('returns high finding for >10 DNS lookups', async () => {
		const mechs = Array.from({ length: 11 }, (_, i) => `include:spf${i}.example.com`).join(' ');
		mockTxtRecords([`v=spf1 ${mechs} -all`]);
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('Too many DNS'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('high');
	});

	it('returns medium finding for deprecated ptr mechanism', async () => {
		mockTxtRecords(['v=spf1 ptr -all']);
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('ptr'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('medium');
	});

	it('ignores non-SPF TXT records', async () => {
		mockTxtRecords(['google-site-verification=abc123', 'v=DMARC1; p=reject']);
		const r = await run();
		expect(r.findings[0].title).toContain('No SPF');
	});

	it('handles case-insensitive SPF prefix', async () => {
		mockTxtRecords(['V=spf1 -all']);
		const r = await run();
		expect(r.findings).toHaveLength(1);
		expect(r.findings[0].severity).toBe('info');
	});

	it('detects exactly 10 DNS lookups as acceptable', async () => {
		const mechs = Array.from({ length: 10 }, (_, i) => `include:spf${i}.example.com`).join(' ');
		mockTxtRecords([`v=spf1 ${mechs} -all`]);
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('Too many DNS'));
		expect(f).toBeUndefined();
	});

	it('counts mixed lookup mechanisms (include, a, mx, redirect)', async () => {
		const mechs = 'include:a.com include:b.com include:c.com include:d.com include:e.com a:f.com mx:g.com redirect=h.com include:i.com include:j.com include:k.com';
		mockTxtRecords([`v=spf1 ${mechs} -all`]);
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('Too many DNS'));
		expect(f).toBeDefined();
	});
});

