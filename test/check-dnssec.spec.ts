import { describe, it, expect, afterEach, vi } from 'vitest';
import { RecordType } from '../src/lib/dns';
import { setupFetchMock, createDohResponse, mockFetchError } from './helpers/dns-mock';

const { restore } = setupFetchMock();

function mockDnssecResponses(adFlag: boolean, hasDnskey = true, hasDs = true) {
	globalThis.fetch = vi.fn().mockImplementation((url: string) => {
		const typeMatch = url.match(/type=([^&]+)/);
		const type = typeMatch ? typeMatch[1] : '';
		if (type === 'A') {
			return Promise.resolve(
				createDohResponse(
					[{ name: 'example.com', type: 1 }],
					[{ name: 'example.com', type: RecordType.A, TTL: 300, data: '93.184.216.34' }],
					{ ad: adFlag },
				),
			);
		}
		if (type === 'DNSKEY') {
			const answers = hasDnskey ? [{ name: 'example.com', type: RecordType.DNSKEY, TTL: 300, data: '257 3 13 mdsswUyr3DPW...' }] : [];
			return Promise.resolve(createDohResponse([{ name: 'example.com', type: 48 }], answers));
		}
		if (type === 'DS') {
			const answers = hasDs ? [{ name: 'example.com', type: RecordType.DS, TTL: 300, data: '12345 13 2 abc123...' }] : [];
			return Promise.resolve(createDohResponse([{ name: 'example.com', type: 43 }], answers));
		}
		return Promise.resolve(createDohResponse([], []));
	});
}

afterEach(() => restore());

describe('checkDnssec', () => {
	async function run(domain = 'example.com') {
		const { checkDnssec } = await import('../src/tools/check-dnssec');
		return checkDnssec(domain);
	}

	it('should return info finding when DNSSEC is fully valid (AD=true)', async () => {
		mockDnssecResponses(true, true, true);
		const result = await run();
		expect(result.category).toBe('dnssec');
		expect(result.findings[0].severity).toBe('info');
		// With DNSKEY records present, algorithm audit produces a modern algorithm info finding
		expect(result.findings[0].title).toMatch(/Modern DNSSEC algorithm/i);
	});

	it('returns medium finding when DNS query fails entirely', async () => {
		mockFetchError();
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('check failed'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('medium');
	});

	it('adds tld_inherited info finding when AD=true but no DNSKEY/DS on domain', async () => {
		mockDnssecResponses(true, false, false);
		const r = await run();
		// Base result has one info finding; augmentation adds the tld_inherited finding
		expect(r.findings.every((f) => f.severity === 'info')).toBe(true);
		const inherited = r.findings.find((f) => f.title === 'DNSSEC inherited from TLD');
		expect(inherited).toBeDefined();
		expect(inherited!.metadata?.dnssecSource).toBe('tld_inherited');
	});
});

describe('DNSSEC finding consolidation', () => {
	async function run(domain = 'example.com') {
		const { checkDnssec } = await import('../src/tools/check-dnssec');
		return checkDnssec(domain);
	}

	it('emits single HIGH finding when DNSSEC is fully absent', async () => {
		// AD=false, no DNSKEY, no DS
		mockDnssecResponses(false, false, false);
		const result = await run();
		const nonInfoFindings = result.findings.filter((f) => f.severity !== 'info');
		expect(nonInfoFindings).toHaveLength(1);
		expect(nonInfoFindings[0].severity).toBe('high');
		expect(nonInfoFindings[0].title).toBe('DNSSEC not enabled');
	});

	it('emits HIGH when DNSKEY present but DS missing', async () => {
		// AD=false, DNSKEY present, no DS
		mockDnssecResponses(false, true, false);
		const result = await run();
		expect(result.findings.some((f) => f.title === 'DNSSEC chain of trust incomplete' && f.severity === 'high')).toBe(true);
	});

	it('emits HIGH when DNSKEY+DS present but AD not set', async () => {
		// AD=false, DNSKEY present, DS present
		mockDnssecResponses(false, true, true);
		const result = await run();
		expect(result.findings.some((f) => f.title === 'DNSSEC validation failing' && f.severity === 'high')).toBe(true);
	});
});

describe('checkDnssec — dnssecSource detection', () => {
	it('adds tld_inherited finding when DNSSEC validates but no DNSKEY/DS on domain', async () => {
		mockDnssecResponses(true, false, false);
		const { checkDnssec } = await import('../src/tools/check-dnssec');
		const result = await checkDnssec('example.com');
		const inheritedFinding = result.findings.find((f) => f.title === 'DNSSEC inherited from TLD');
		expect(inheritedFinding).toBeDefined();
		expect(inheritedFinding!.severity).toBe('info');
		expect(inheritedFinding!.metadata?.dnssecSource).toBe('tld_inherited');
	});

	it('tags domain_configured when both DNSKEY and DS records are present', async () => {
		mockDnssecResponses(true, true, true);
		const { checkDnssec } = await import('../src/tools/check-dnssec');
		const result = await checkDnssec('example.com');
		const tldFinding = result.findings.find((f) => f.title === 'DNSSEC inherited from TLD');
		expect(tldFinding).toBeUndefined();
		// Source should be domain_configured somewhere in findings metadata
		const hasDomainConfigured = result.findings.some((f) => f.metadata?.dnssecSource === 'domain_configured');
		expect(hasDomainConfigured).toBe(true);
	});
});
