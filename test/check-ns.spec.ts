import { describe, it, expect, afterEach, vi } from 'vitest';
import { RecordType } from '../src/lib/dns';
import { setupFetchMock, createDohResponse, mockFetchError } from './helpers/dns-mock';

const { restore } = setupFetchMock();

function mockNsResponses(nsRecords: string[], soaData?: string, aRecords?: string[]) {
	const nsAnswers = nsRecords.map((data) => ({
		name: 'example.com',
		type: RecordType.NS,
		TTL: 86400,
		data,
	}));
	const soaAnswers = soaData ? [{ name: 'example.com', type: RecordType.SOA, TTL: 3600, data: soaData }] : [];
	const aAnswers = (aRecords ?? []).map((data) => ({
		name: 'example.com',
		type: RecordType.A,
		TTL: 300,
		data,
	}));
	globalThis.fetch = vi.fn().mockImplementation((url: string) => {
		const typeMatch = url.match(/type=([^&]+)/);
		const type = typeMatch ? typeMatch[1] : '';
		if (type === 'NS') {
			return Promise.resolve(createDohResponse([{ name: 'example.com', type: RecordType.NS }], nsAnswers));
		}
		if (type === 'A') {
			return Promise.resolve(createDohResponse([{ name: 'example.com', type: RecordType.A }], aAnswers));
		}
		if (type === 'SOA') {
			return Promise.resolve(createDohResponse([{ name: 'example.com', type: RecordType.SOA }], soaAnswers));
		}
		return Promise.resolve(createDohResponse([], []));
	});
}

afterEach(() => restore());

describe('checkNs', () => {
	async function run(domain = 'example.com') {
		const { checkNs } = await import('../src/tools/check-ns');
		return checkNs(domain);
	}

	it('should return critical finding when no NS records exist and domain does not resolve', async () => {
		mockNsResponses([]);
		const result = await run();
		expect(result.category).toBe('ns');
		expect(result.findings[0].severity).toBe('critical');
		expect(result.findings[0].title).toMatch(/No NS records/i);
	});

	it('should return info finding when valid NS records exist', async () => {
		mockNsResponses(
			['ns1.provider-a.com.', 'ns2.provider-b.net.'],
			'ns1.provider-a.com. admin.example.com. 2024010101 3600 900 604800 86400',
		);
		const result = await run();
		expect(result.findings[0].severity).toBe('info');
		expect(result.findings[0].title).toMatch(/properly configured/i);
	});

	it('returns info finding for multiple nameservers from different providers', async () => {
		mockNsResponses(
			['ns1.provider-a.com.', 'ns2.provider-b.net.'],
			'ns1.provider-a.com. admin.example.com. 2024010101 3600 900 604800 86400',
		);
		const r = await run();
		expect(r.category).toBe('ns');
		expect(r.findings).toHaveLength(1);
		expect(r.findings[0].severity).toBe('info');
		expect(r.findings[0].title).toContain('properly configured');
		expect(r.passed).toBe(true);
	});

	it('returns high severity finding for single nameserver with RFC 1035 reference', async () => {
		mockNsResponses(['ns1.example.com.'], 'ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400');
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('Single nameserver'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('high');
		expect(f!.title).toContain('RFC 1035');
		expect(f!.detail).toContain('RFC 1035 §2.2');
	});

	it('returns low severity finding when all nameservers share same TLD', async () => {
		mockNsResponses(
			['ns1.cloudflare.com.', 'ns2.cloudflare.com.', 'ns3.cloudflare.com.'],
			'ns1.cloudflare.com. admin.example.com. 2024010101 3600 900 604800 86400',
		);
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('Low nameserver diversity'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('low');
		expect(f!.detail).toContain('cloudflare.com');
	});

	it('returns critical finding when no NS records and domain does not resolve', async () => {
		mockNsResponses(
			[],
			'ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400',
			[], // no A records either
		);
		const r = await run();
		expect(r.findings).toHaveLength(1);
		expect(r.findings[0].severity).toBe('critical');
		expect(r.findings[0].title).toContain('No NS records');
	});

	it('returns low finding for delegation-only domains that still resolve', async () => {
		mockNsResponses(
			[], // no NS records
			undefined,
			['192.0.2.1'], // but domain resolves via A record
		);
		const r = await run();
		expect(r.findings).toHaveLength(1);
		expect(r.findings[0].severity).toBe('low');
		expect(r.findings[0].title).toContain('not directly visible');
		expect(r.findings[0].detail).toContain('parent zone');
	});

	it('returns critical finding when NS query fails', async () => {
		mockFetchError();
		const r = await run();
		expect(r.findings).toHaveLength(1);
		expect(r.findings[0].severity).toBe('critical');
		expect(r.findings[0].title).toContain('NS query failed');
	});

	it('returns medium finding when no SOA record exists', async () => {
		mockNsResponses(
			['ns1.provider-a.com.', 'ns2.provider-b.net.'],
			undefined, // no SOA
		);
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('No SOA'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('medium');
	});

	it('normalizes trailing dots in NS records', async () => {
		mockNsResponses(
			['ns1.provider-a.com.', 'ns2.provider-b.net.'],
			'ns1.provider-a.com. admin.example.com. 2024010101 3600 900 604800 86400',
		);
		const r = await run();
		expect(r.findings).toHaveLength(1);
		expect(r.findings[0].severity).toBe('info');
		expect(r.findings[0].detail).toContain('ns1.provider-a.com');
		expect(r.findings[0].detail).not.toContain('ns1.provider-a.com.');
	});

	it('passes with two nameservers (minimum acceptable)', async () => {
		mockNsResponses(['ns1.dns-a.org.', 'ns2.dns-b.com.'], 'ns1.dns-a.org. admin.example.com. 2024010101 3600 900 604800 86400');
		const r = await run();
		expect(r.findings).toHaveLength(1);
		expect(r.findings[0].severity).toBe('info');
		expect(r.findings[0].title).toContain('properly configured');
		expect(r.findings[0].detail).toContain('2 nameservers');
	});

	it('handles nameservers with proper delegation from diverse providers', async () => {
		mockNsResponses(
			['ns1.awsdns.com.', 'ns2.google.net.', 'ns3.cloudflare.org.'],
			'ns1.awsdns.com. admin.example.com. 2024010101 3600 900 604800 86400',
		);
		const r = await run();
		expect(r.findings).toHaveLength(1);
		expect(r.findings[0].severity).toBe('info');
		expect(r.findings[0].detail).toContain('3 nameservers');
		expect(r.passed).toBe(true);
	});

	it('flags SOA refresh interval too short (< 300s)', async () => {
		mockNsResponses(
			['ns1.provider-a.com.', 'ns2.provider-b.net.'],
			'ns1.provider-a.com. admin.example.com. 2024010101 60 30 604800 86400',
		);
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('SOA refresh interval too short'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('low');
		expect(f!.detail).toContain('60s');
	});

	it('flags SOA refresh interval too long (> 86400s)', async () => {
		mockNsResponses(
			['ns1.provider-a.com.', 'ns2.provider-b.net.'],
			'ns1.provider-a.com. admin.example.com. 2024010101 172800 900 604800 86400',
		);
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('SOA refresh interval too long'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('low');
		expect(f!.detail).toContain('172800s');
	});

	it('flags SOA retry exceeding refresh interval', async () => {
		mockNsResponses(
			['ns1.provider-a.com.', 'ns2.provider-b.net.'],
			'ns1.provider-a.com. admin.example.com. 2024010101 3600 7200 604800 86400',
		);
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('SOA retry exceeds refresh'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('low');
		expect(f!.detail).toContain('7200s');
		expect(f!.detail).toContain('3600s');
	});

	it('flags SOA expire too short (< 604800s)', async () => {
		mockNsResponses(
			['ns1.provider-a.com.', 'ns2.provider-b.net.'],
			'ns1.provider-a.com. admin.example.com. 2024010101 3600 900 86400 86400',
		);
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('SOA expire too short'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('medium');
		expect(f!.detail).toContain('86400s');
	});

	it('flags SOA negative cache TTL too long (> 86400s)', async () => {
		mockNsResponses(
			['ns1.provider-a.com.', 'ns2.provider-b.net.'],
			'ns1.provider-a.com. admin.example.com. 2024010101 3600 900 604800 172800',
		);
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('SOA negative cache TTL too long'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('low');
		expect(f!.detail).toContain('172800s');
	});

	it('skips SOA validation silently when data does not parse cleanly', async () => {
		mockNsResponses(
			['ns1.provider-a.com.', 'ns2.provider-b.net.'],
			'ns1.provider-a.com. admin.example.com.',
		);
		const r = await run();
		// Should not crash; should produce no SOA-related findings
		const soaFindings = r.findings.filter((f) => f.title.includes('SOA'));
		expect(soaFindings).toHaveLength(0);
	});

	it('does not flag SOA parameters within normal ranges', async () => {
		mockNsResponses(
			['ns1.provider-a.com.', 'ns2.provider-b.net.'],
			'ns1.provider-a.com. admin.example.com. 2024010101 3600 900 604800 86400',
		);
		const r = await run();
		const soaFindings = r.findings.filter((f) => f.title.includes('SOA'));
		expect(soaFindings).toHaveLength(0);
	});

	it('detects wildcard DNS when probe subdomain resolves', async () => {
		globalThis.fetch = vi.fn().mockImplementation((url: string) => {
			const typeMatch = url.match(/type=([^&]+)/);
			const type = typeMatch ? typeMatch[1] : '';
			const nameMatch = url.match(/name=([^&]+)/);
			const name = nameMatch ? nameMatch[1] : '';

			if (type === 'NS') {
				return Promise.resolve(
					createDohResponse(
						[{ name: 'example.com', type: 2 }],
						[
							{ name: 'example.com', type: 2, TTL: 86400, data: 'ns1.provider-a.com.' },
							{ name: 'example.com', type: 2, TTL: 86400, data: 'ns2.provider-b.net.' },
						],
					),
				);
			}
			if (type === 'SOA') {
				return Promise.resolve(
					createDohResponse(
						[{ name: 'example.com', type: 6 }],
						[{ name: 'example.com', type: 6, TTL: 3600, data: 'ns1.provider-a.com. admin.example.com. 2024010101 3600 900 604800 86400' }],
					),
				);
			}
			if (type === 'A') {
				// Wildcard: probe subdomain resolves
				if (name.startsWith('_bv-probe-')) {
					return Promise.resolve(
						createDohResponse(
							[{ name, type: 1 }],
							[{ name, type: 1, TTL: 300, data: '1.2.3.4' }],
						),
					);
				}
				return Promise.resolve(createDohResponse([], []));
			}
			return Promise.resolve(createDohResponse([], []));
		});
		const r = await run();
		const f = r.findings.find((f) => /Wildcard DNS detected/i.test(f.title));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('medium');
		expect(f!.metadata?.wildcardDetected).toBe(true);
	});

	it('does not flag wildcard when probe subdomain does not resolve', async () => {
		mockNsResponses(
			['ns1.provider-a.com.', 'ns2.provider-b.net.'],
			'ns1.provider-a.com. admin.example.com. 2024010101 3600 900 604800 86400',
		);
		const r = await run();
		const f = r.findings.find((f) => /Wildcard DNS detected/i.test(f.title));
		expect(f).toBeUndefined();
	});
});
