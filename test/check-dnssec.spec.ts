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

	it('does not flag missing DNSKEY/DS when AD=true', async () => {
		mockDnssecResponses(true, false, false);
		const r = await run();
		expect(r.findings).toHaveLength(1);
		expect(r.findings[0].severity).toBe('info');
	});
});

describe('DNSSEC finding consolidation', () => {
	async function run(domain = 'example.com') {
		const { checkDnssec } = await import('../src/tools/check-dnssec');
		return checkDnssec(domain);
	}

	it('emits single MEDIUM finding when DNSSEC is fully absent', async () => {
		// AD=false, no DNSKEY, no DS
		mockDnssecResponses(false, false, false);
		const result = await run();
		const nonInfoFindings = result.findings.filter((f) => f.severity !== 'info');
		expect(nonInfoFindings).toHaveLength(1);
		expect(nonInfoFindings[0].severity).toBe('medium');
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
