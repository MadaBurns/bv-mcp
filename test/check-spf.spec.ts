import { describe, it, expect, afterEach } from 'vitest';
import { setupFetchMock, mockTxtRecords } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

describe('checkSpf', () => {
	async function run(domain = 'example.com') {
		const { checkSpf } = await import('../src/tools/check-spf');
		return checkSpf(domain);
	}

	it('should return critical finding when no SPF record exists', async () => {
		mockTxtRecords([]);
		const result = await run();
		expect(result.category).toBe('spf');
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('critical');
		expect(result.findings[0].title).toMatch(/No SPF/i);
	});

	it('should return high finding for multiple SPF records', async () => {
		mockTxtRecords(['v=spf1 -all', 'v=spf1 ~all']);
		const result = await run();
		const finding = result.findings.find((f) => /Multiple SPF/i.test(f.title));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('high');
	});

	it('should return critical finding for +all', async () => {
		mockTxtRecords(['v=spf1 +all']);
		const result = await run();
		const finding = result.findings.find((f) => /Permissive/i.test(f.title));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('critical');
	});

	it('should return critical finding for ?all', async () => {
		mockTxtRecords(['v=spf1 ?all']);
		const result = await run();
		const finding = result.findings.find((f) => /Permissive/i.test(f.title));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('critical');
	});

	it('should return low finding for ~all (soft fail)', async () => {
		mockTxtRecords(['v=spf1 include:_spf.google.com ~all']);
		const result = await run();
		const finding = result.findings.find((f) => /soft fail/i.test(f.title));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('low');
	});

	it('should return info finding for -all (hard fail, best practice)', async () => {
		mockTxtRecords(['v=spf1 include:_spf.google.com -all']);
		const result = await run();
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('info');
		expect(result.findings[0].title).toMatch(/SPF record configured/i);
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
		const mechs =
			'include:a.com include:b.com include:c.com include:d.com include:e.com a:f.com mx:g.com redirect=h.com include:i.com include:j.com include:k.com';
		mockTxtRecords([`v=spf1 ${mechs} -all`]);
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('Too many DNS'));
		expect(f).toBeDefined();
	});
});
