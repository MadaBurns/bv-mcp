import { describe, it, expect, afterEach } from 'vitest';
import { vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

/**
 * Helper: set up fetch mock that returns different TXT responses per queried domain.
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

describe('checkBimi', () => {
	async function run(domain = 'example.com') {
		const { checkBimi } = await import('../src/tools/check-bimi');
		return checkBimi(domain);
	}

	it('should return low finding when no BIMI record and DMARC not enforcing', async () => {
		mockMultipleTxtRecords({
			'default._bimi.example.com': [],
			'_dmarc.example.com': ['v=DMARC1; p=none'],
		});
		const result = await run();
		expect(result.category).toBe('bimi');
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('low');
		expect(result.findings[0].title).toMatch(/No BIMI record.*DMARC not enforcing/i);
	});

	it('should return low finding when no BIMI record but DMARC is enforcing (p=reject)', async () => {
		mockMultipleTxtRecords({
			'default._bimi.example.com': [],
			'_dmarc.example.com': ['v=DMARC1; p=reject; rua=mailto:dmarc@example.com'],
		});
		const result = await run();
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('low');
		expect(result.findings[0].title).toMatch(/No BIMI record found/i);
	});

	it('should return low finding when no BIMI record but DMARC is quarantine', async () => {
		mockMultipleTxtRecords({
			'default._bimi.example.com': [],
			'_dmarc.example.com': ['v=DMARC1; p=quarantine'],
		});
		const result = await run();
		expect(result.findings[0].severity).toBe('low');
	});

	it('should return info findings for valid BIMI with l= and a= tags', async () => {
		// Smart mock: returns valid SVG for logo URLs, DNS responses for DoH queries
		const validSvg = '<svg xmlns="http://www.w3.org/2000/svg" baseProfile="tiny-ps"></svg>';
		const dnsMapping: Record<string, string[]> = {
			'default._bimi.example.com': ['v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem'],
		};
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : (input as Request).url;
			if (url.endsWith('.svg')) {
				return Promise.resolve(new Response(validSvg, { status: 200, headers: { 'content-type': 'image/svg+xml' } }));
			}
			const name = new URL(url).searchParams.get('name') ?? '';
			const records = dnsMapping[name] ?? [];
			const answers = records.map((data) => ({ name, type: 16, TTL: 300, data: `"${data}"` }));
			return Promise.resolve(createDohResponse([{ name, type: 16 }], answers));
		});
		const result = await run();
		const svgFinding = result.findings.find((f) => /BIMI logo SVG validated/i.test(f.title));
		const authFinding = result.findings.find((f) => /authority evidence present/i.test(f.title));
		expect(svgFinding).toBeDefined();
		expect(svgFinding!.severity).toBe('info');
		expect(authFinding).toBeDefined();
		expect(authFinding!.severity).toBe('info');
	});

	it('should return low finding about missing VMC when l= present but no a= tag', async () => {
		// Smart mock: returns valid SVG for logo URLs, DNS responses for DoH queries
		const validSvg = '<svg xmlns="http://www.w3.org/2000/svg" baseProfile="tiny-ps"></svg>';
		const dnsMapping: Record<string, string[]> = {
			'default._bimi.example.com': ['v=BIMI1; l=https://example.com/logo.svg'],
		};
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : (input as Request).url;
			if (url.endsWith('.svg')) {
				return Promise.resolve(new Response(validSvg, { status: 200, headers: { 'content-type': 'image/svg+xml' } }));
			}
			const name = new URL(url).searchParams.get('name') ?? '';
			const records = dnsMapping[name] ?? [];
			const answers = records.map((data) => ({ name, type: 16, TTL: 300, data: `"${data}"` }));
			return Promise.resolve(createDohResponse([{ name, type: 16 }], answers));
		});
		const result = await run();
		const vmcFinding = result.findings.find((f) => /No BIMI authority evidence/i.test(f.title));
		expect(vmcFinding).toBeDefined();
		expect(vmcFinding!.severity).toBe('low');
		// SVG validation should succeed
		const svgFinding = result.findings.find((f) => /BIMI logo SVG validated/i.test(f.title));
		expect(svgFinding).toBeDefined();
	});

	it('should return medium finding when BIMI record has no l= tag', async () => {
		mockMultipleTxtRecords({
			'default._bimi.example.com': ['v=BIMI1; a=https://example.com/vmc.pem'],
		});
		const result = await run();
		const finding = result.findings.find((f) => /BIMI record missing logo URL/i.test(f.title));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('medium');
	});

	it('should return medium finding for non-HTTPS logo URL', async () => {
		mockMultipleTxtRecords({
			'default._bimi.example.com': ['v=BIMI1; l=http://example.com/logo.svg'],
		});
		const result = await run();
		const finding = result.findings.find((f) => /BIMI logo URL invalid format/i.test(f.title));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('medium');
		expect(finding!.detail).toContain('HTTPS');
	});

	it('should return medium finding for non-SVG logo URL', async () => {
		mockMultipleTxtRecords({
			'default._bimi.example.com': ['v=BIMI1; l=https://example.com/logo.png'],
		});
		const result = await run();
		const finding = result.findings.find((f) => /BIMI logo URL invalid format/i.test(f.title));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('medium');
		expect(finding!.detail).toContain('SVG');
	});

	it('should return medium finding for multiple BIMI records', async () => {
		mockMultipleTxtRecords({
			'default._bimi.example.com': [
				'v=BIMI1; l=https://example.com/logo1.svg',
				'v=BIMI1; l=https://example.com/logo2.svg',
			],
		});
		const result = await run();
		const finding = result.findings.find((f) => /Multiple BIMI records/i.test(f.title));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('medium');
	});
});
