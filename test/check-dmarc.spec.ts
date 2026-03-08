import { describe, it, expect, afterEach } from 'vitest';
import { vi } from 'vitest';
import { setupFetchMock, mockTxtRecords, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

/**
 * Helper: set up fetch mock that returns different TXT responses per queried domain.
 * Keys are the domain queried (e.g. '_dmarc.example.com'), values are arrays of TXT strings.
 */
function mockMultipleTxtRecords(mapping: Record<string, string[]>) {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
		const parsed = new URL(url);
		const name = parsed.searchParams.get('name') ?? '';
		const records = mapping[name] ?? [];
		const answers = records.map((data) => ({
			name,
			type: 16,
			TTL: 300,
			data: `"${data}"`,
		}));
		return Promise.resolve(createDohResponse([{ name, type: 16 }], answers));
	});
}

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
		const finding = result.findings.find((f) => /Multiple DMARC/i.test(f.title));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('high');
	});

	it('should return critical finding when p= tag is missing', async () => {
		mockTxtRecords(['v=DMARC1; rua=mailto:dmarc@example.com']);
		const result = await run();
		const finding = result.findings.find((f) => /Missing DMARC policy/i.test(f.title));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('critical');
	});

	it('should return high finding for p=none', async () => {
		mockTxtRecords(['v=DMARC1; p=none; rua=mailto:dmarc@example.com']);
		const result = await run();
		const finding = result.findings.find((f) => /policy set to none/i.test(f.title));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('high');
	});

	it('should return low finding for p=quarantine', async () => {
		mockTxtRecords(['v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com']);
		const result = await run();
		const finding = result.findings.find((f) => /quarantine/i.test(f.title));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('low');
	});

	it('should return info finding for p=reject with rua and sp', async () => {
		mockTxtRecords(['v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@example.com; ruf=mailto:forensic@example.com']);
		const result = await run();
		// Now includes alignment warnings (low severity) since adkim/aspf default to relaxed
		expect(result.findings.length).toBeGreaterThanOrEqual(1);
		const infoFinding = result.findings.find((f) => f.severity === 'info');
		expect(infoFinding).toBeDefined();
		expect(infoFinding!.title).toMatch(/DMARC properly configured/i);
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
		mockTxtRecords(['V=DMARC1; p=reject; sp=reject; rua=mailto:d@example.com; ruf=mailto:f@example.com']);
		const r = await run();
		// Includes alignment warnings since adkim/aspf default to relaxed
		expect(r.findings.length).toBeGreaterThanOrEqual(1);
		const infoFinding = r.findings.find((f) => f.severity === 'info');
		expect(infoFinding).toBeDefined();
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

	it('flags invalid pct values', async () => {
		mockTxtRecords(['v=DMARC1; p=reject; pct=200; sp=reject; rua=mailto:d@example.com']);
		const r = await run();
		const f = r.findings.find((f) => /Invalid DMARC percentage/i.test(f.title));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('medium');
	});

	it('flags sp=none as weaker than parent reject policy', async () => {
		mockTxtRecords(['v=DMARC1; p=reject; sp=none; rua=mailto:d@example.com']);
		const r = await run();
		const f = r.findings.find((f) => /Subdomain policy weaker/i.test(f.title));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('high');
	});

	it('flags invalid fo values', async () => {
		mockTxtRecords(['v=DMARC1; p=reject; sp=reject; fo=x; rua=mailto:d@example.com']);
		const r = await run();
		const f = r.findings.find((f) => /Invalid DMARC failure reporting/i.test(f.title));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('medium');
	});

	it('warns when fo=0 limits forensic visibility', async () => {
		mockTxtRecords(['v=DMARC1; p=reject; sp=reject; fo=0; rua=mailto:d@example.com']);
		const r = await run();
		const f = r.findings.find((f) => /Limited DMARC failure reporting coverage/i.test(f.title));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('low');
	});

	// URI Validation Tests
	it('accepts valid mailto: URI in rua', async () => {
		mockTxtRecords(['v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@example.com']);
		const r = await run();
		const f = r.findings.find((f) => /Invalid aggregate report URI/i.test(f.title));
		expect(f).toBeUndefined();
	});

	it('flags invalid rua= URI (missing mailto:)', async () => {
		mockTxtRecords(['v=DMARC1; p=reject; sp=reject; rua=http://example.com/dmarc']);
		const r = await run();
		const f = r.findings.find((f) => /Invalid aggregate report URI/i.test(f.title));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('medium');
	});

	it('flags malformed email in rua= URI', async () => {
		mockTxtRecords(['v=DMARC1; p=reject; sp=reject; rua=mailto:invalid-email']);
		const r = await run();
		const f = r.findings.find((f) => /Invalid aggregate report URI/i.test(f.title));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('medium');
	});

	it('validates multiple comma-separated rua= URIs', async () => {
		mockTxtRecords(['v=DMARC1; p=reject; sp=reject; rua=mailto:a@example.com, mailto:b@example.com']);
		const r = await run();
		const f = r.findings.find((f) => /Invalid aggregate report URI/i.test(f.title));
		expect(f).toBeUndefined();
	});

	it('flags invalid ruf= URI format', async () => {
		mockTxtRecords(['v=DMARC1; p=reject; sp=reject; rua=mailto:d@example.com; ruf=ftp://forensic.com']);
		const r = await run();
		const f = r.findings.find((f) => /Invalid forensic report URI/i.test(f.title));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('medium');
	});

	it('accepts valid ruf= URI', async () => {
		mockTxtRecords(['v=DMARC1; p=reject; sp=reject; rua=mailto:d@example.com; ruf=mailto:forensic@example.com']);
		const r = await run();
		const f = r.findings.find((f) => /Invalid forensic report URI/i.test(f.title));
		expect(f).toBeUndefined();
	});

	// Aggregator Detection Tests
	it('detects dmarcian.com aggregator', async () => {
		mockTxtRecords(['v=DMARC1; p=reject; sp=reject; rua=mailto:reports@dmarcian.com']);
		const r = await run();
		const f = r.findings.find((f) => /Third-party DMARC aggregator/i.test(f.title));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('info');
		expect(f!.metadata?.aggregators).toContain('dmarcian.com');
	});

	it('detects multiple aggregators', async () => {
		mockTxtRecords(['v=DMARC1; p=reject; sp=reject; rua=mailto:a@dmarcian.com, mailto:b@valimail.com']);
		const r = await run();
		const f = r.findings.find((f) => /Third-party DMARC aggregator/i.test(f.title));
		expect(f).toBeDefined();
		expect(f!.metadata?.aggregators).toContain('dmarcian.com');
		expect(f!.metadata?.aggregators).toContain('valimail.com');
	});

	it('does not flag non-aggregator domains', async () => {
		mockTxtRecords(['v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@internal-company.com']);
		const r = await run();
		const f = r.findings.find((f) => /Third-party DMARC aggregator/i.test(f.title));
		expect(f).toBeUndefined();
	});

	// Alignment Mode Tests
	it('warns about relaxed DKIM alignment (adkim=r)', async () => {
		mockTxtRecords(['v=DMARC1; p=reject; sp=reject; rua=mailto:d@example.com; adkim=r']);
		const r = await run();
		const f = r.findings.find((f) => /Relaxed DKIM alignment/i.test(f.title));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('low');
	});

	it('warns about relaxed DKIM alignment (adkim unset)', async () => {
		mockTxtRecords(['v=DMARC1; p=reject; sp=reject; rua=mailto:d@example.com']);
		const r = await run();
		const f = r.findings.find((f) => /Relaxed DKIM alignment/i.test(f.title));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('low');
	});

	it('does not warn when DKIM alignment is strict (adkim=s)', async () => {
		mockTxtRecords(['v=DMARC1; p=reject; sp=reject; rua=mailto:d@example.com; adkim=s; aspf=s']);
		const r = await run();
		const f = r.findings.find((f) => /Relaxed DKIM alignment/i.test(f.title));
		expect(f).toBeUndefined();
	});

	it('flags invalid adkim value', async () => {
		mockTxtRecords(['v=DMARC1; p=reject; sp=reject; rua=mailto:d@example.com; adkim=x']);
		const r = await run();
		const f = r.findings.find((f) => /Invalid DKIM alignment mode/i.test(f.title));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('medium');
	});

	it('warns about relaxed SPF alignment (aspf=r)', async () => {
		mockTxtRecords(['v=DMARC1; p=reject; sp=reject; rua=mailto:d@example.com; aspf=r']);
		const r = await run();
		const f = r.findings.find((f) => /Relaxed SPF alignment/i.test(f.title));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('low');
	});

	it('warns about relaxed SPF alignment (aspf unset)', async () => {
		mockTxtRecords(['v=DMARC1; p=reject; sp=reject; rua=mailto:d@example.com']);
		const r = await run();
		const f = r.findings.find((f) => /Relaxed SPF alignment/i.test(f.title));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('low');
	});

	it('does not warn when SPF alignment is strict (aspf=s)', async () => {
		mockTxtRecords(['v=DMARC1; p=reject; sp=reject; rua=mailto:d@example.com; adkim=s; aspf=s']);
		const r = await run();
		const f = r.findings.find((f) => /Relaxed SPF alignment/i.test(f.title));
		expect(f).toBeUndefined();
	});

	it('flags invalid aspf value', async () => {
		mockTxtRecords(['v=DMARC1; p=reject; sp=reject; rua=mailto:d@example.com; aspf=invalid']);
		const r = await run();
		const f = r.findings.find((f) => /Invalid SPF alignment mode/i.test(f.title));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('medium');
	});

	it('handles fully configured DMARC with strict alignment', async () => {
		mockTxtRecords(['v=DMARC1; p=reject; sp=reject; rua=mailto:d@example.com; ruf=mailto:f@example.com; adkim=s; aspf=s']);
		const r = await run();
		// Should only have info finding for proper configuration
		expect(r.findings).toHaveLength(1);
		expect(r.findings[0].severity).toBe('info');
		expect(r.findings[0].title).toMatch(/DMARC properly configured/i);
	});

	// --- RUA cross-domain authorization (RFC 7489 §7.1) ---

	it('does not flag RUA when third-party has authorization record', async () => {
		mockMultipleTxtRecords({
			'_dmarc.example.com': ['v=DMARC1; p=reject; sp=reject; rua=mailto:d@thirdparty.com; ruf=mailto:f@example.com; adkim=s; aspf=s'],
			'example.com._report._dmarc.thirdparty.com': ['v=DMARC1'],
		});
		const r = await run();
		const f = r.findings.find((f) => /Third-party aggregate reporting not authorized/i.test(f.title));
		expect(f).toBeUndefined();
	});

	it('flags RUA when third-party lacks authorization record', async () => {
		mockMultipleTxtRecords({
			'_dmarc.example.com': ['v=DMARC1; p=reject; sp=reject; rua=mailto:d@thirdparty.com; ruf=mailto:f@example.com; adkim=s; aspf=s'],
			'example.com._report._dmarc.thirdparty.com': [],
		});
		const r = await run();
		const f = r.findings.find((f) => /Third-party aggregate reporting not authorized/i.test(f.title));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('medium');
		expect(f!.detail).toContain('thirdparty.com');
	});

	// --- Size limit suffix in rua= (RFC 7489 §6.2) ---

	it('accepts rua= with size limit suffix !10m', async () => {
		mockTxtRecords(['v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@example.com!10m; ruf=mailto:f@example.com; adkim=s; aspf=s']);
		const r = await run();
		const f = r.findings.find((f) => /Invalid aggregate report URI/i.test(f.title));
		expect(f).toBeUndefined();
	});

	// --- sp= inheritance for p=none ---

	it('returns info finding when sp= not set and p=none', async () => {
		mockTxtRecords(['v=DMARC1; p=none; rua=mailto:d@example.com']);
		const r = await run();
		const f = r.findings.find((f) => /Subdomains inherit p=none/i.test(f.title));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('info');
	});

	// --- sp=none weaker than p=quarantine ---

	it('flags sp=none as weaker than p=quarantine', async () => {
		mockTxtRecords(['v=DMARC1; p=quarantine; sp=none; rua=mailto:d@example.com']);
		const r = await run();
		const f = r.findings.find((f) => /Subdomain policy weaker than domain policy/i.test(f.title));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('medium');
	});

	// --- Missing ruf= when rua= is present ---

	it('flags missing ruf= when rua= is present', async () => {
		mockTxtRecords(['v=DMARC1; p=reject; sp=reject; rua=mailto:d@example.com; adkim=s; aspf=s']);
		const r = await run();
		const f = r.findings.find((f) => /No forensic reporting configured/i.test(f.title));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('low');
	});
});
