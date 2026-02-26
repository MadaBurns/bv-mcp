import { describe, it, expect, afterEach } from 'vitest';
import { setupFetchMock, mockTxtRecords } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

describe('checkDmarc', () => {
	async function run(domain = 'example.com') {
		const { checkDmarc } = await import('../src/tools/check-dmarc');
		return checkDmarc(domain);
	}

	it('should return critical finding when no DMARC record exists', async () => {
		mockTxtRecords([]);
		const result = await run();
		expect(result.category).toBe('dmarc');
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('critical');
		expect(result.findings[0].title).toMatch(/No DMARC/i);
	});

	it('should return high finding for multiple DMARC records', async () => {
		mockTxtRecords(['v=DMARC1; p=reject', 'v=DMARC1; p=none']);
		const result = await run();
		const finding = result.findings.find(f => /Multiple DMARC/i.test(f.title));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('high');
	});

	it('should return critical finding when p= tag is missing', async () => {
		mockTxtRecords(['v=DMARC1; rua=mailto:dmarc@example.com']);
		const result = await run();
		const finding = result.findings.find(f => /Missing DMARC policy/i.test(f.title));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('critical');
	});

	it('should return high finding for p=none', async () => {
		mockTxtRecords(['v=DMARC1; p=none; rua=mailto:dmarc@example.com']);
		const result = await run();
		const finding = result.findings.find(f => /policy set to none/i.test(f.title));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('high');
	});

	it('should return low finding for p=quarantine', async () => {
		mockTxtRecords(['v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com']);
		const result = await run();
		const finding = result.findings.find(f => /quarantine/i.test(f.title));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('low');
	});

	it('should return info finding for p=reject with rua and sp', async () => {
		mockTxtRecords(['v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@example.com']);
		const result = await run();
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('info');
		expect(result.findings[0].title).toMatch(/DMARC policy is reject/i);
	});

	it('returns low finding for missing sp= when p=reject', async () => {
		mockTxtRecords(['v=DMARC1; p=reject; rua=mailto:dmarc@example.com']);
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('No subdomain'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('low');
	});

	it('returns medium finding for pct < 100', async () => {
		mockTxtRecords(['v=DMARC1; p=reject; pct=50; rua=mailto:dmarc@example.com; sp=reject']);
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('not applied to all'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('medium');
	});

	it('returns medium finding when rua= is missing', async () => {
		mockTxtRecords(['v=DMARC1; p=reject; sp=reject']);
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('No aggregate'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('medium');
	});

	it('ignores non-DMARC TXT records', async () => {
		mockTxtRecords(['v=spf1 -all', 'google-site-verification=abc']);
		const r = await run();
		expect(r.findings[0].title).toContain('No DMARC');
	});

	it('handles case-insensitive DMARC prefix', async () => {
		mockTxtRecords(['V=DMARC1; p=reject; sp=reject; rua=mailto:d@example.com']);
		const r = await run();
		expect(r.findings).toHaveLength(1);
		expect(r.findings[0].severity).toBe('info');
	});

	it('does not flag sp= missing when p is not reject', async () => {
		mockTxtRecords(['v=DMARC1; p=quarantine; rua=mailto:d@example.com']);
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('No subdomain'));
		expect(f).toBeUndefined();
	});

	it('accepts pct=100 without finding', async () => {
		mockTxtRecords(['v=DMARC1; p=reject; pct=100; sp=reject; rua=mailto:d@example.com']);
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('not applied'));
		expect(f).toBeUndefined();
	});
// ...existing code...
