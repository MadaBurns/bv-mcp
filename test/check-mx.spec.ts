import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

function mockMxRecords(domain: string, records: string[]) {
	const answers = records.map((data) => ({
		name: domain,
		type: 15,
		TTL: 300,
		data,
	}));
	globalThis.fetch = vi.fn().mockResolvedValue(createDohResponse([{ name: domain, type: 15 }], answers));
}

describe('checkMx', () => {
	async function run(domain = 'example.com') {
		const { checkMx } = await import('../src/tools/check-mx');
		return checkMx(domain);
	}

	it('should return medium finding if no MX records found', async () => {
		mockMxRecords('nomx.com', []);
		const result = await run('nomx.com');
		expect(result.findings[0].severity).toBe('medium');
		expect(result.findings[0].title).toMatch(/No MX records found/i);
	});

	it('should return pass if MX records found', async () => {
		mockMxRecords('hasmx.com', ['10 mx1.hasmx.com.', '20 mx2.hasmx.com.']);
		const result = await run('hasmx.com');
		expect(result.passed).toBe(true);
		expect(result.findings[0].title).toMatch(/MX records found/i);
	});

	it('should detect managed email provider', async () => {
		mockMxRecords('outbound.com', ['10 aspmx.l.google.com.']);
		const result = await run('outbound.com');
		expect(result.passed).toBe(true);
		const infoFinding = result.findings.find((f) => f.severity === 'info' && f.title.includes('provider'));
		expect(infoFinding).toBeTruthy();
		expect(infoFinding!.title).toMatch(/Managed email provider detected/i);
		expect(infoFinding!.metadata).toBeDefined();
		expect(infoFinding!.metadata?.detectionType).toBe('inbound');
		expect(infoFinding!.metadata?.providers).toBeDefined();
	});

	it('should avoid false positive suffix matches for provider detection', async () => {
		mockMxRecords('boundary.com', ['10 mail.evilgoogle.com.']);
		const result = await run('boundary.com');
		const infoFinding = result.findings.find((f) => f.title === 'Managed email provider detected');
		expect(infoFinding).toBeUndefined();
	});

	it('should add degraded-source finding when runtime provider source fails', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('cloudflare-dns.com')) {
				const answers = [{ name: 'fallback.com', type: 15, TTL: 300, data: '10 aspmx.l.google.com.' }];
				return Promise.resolve(createDohResponse([{ name: 'fallback.com', type: 15 }], answers));
			}
			throw new Error('Provider signature source unavailable');
		});

		const { checkMx } = await import('../src/tools/check-mx');
		const result = await checkMx('fallback.com', { providerSignaturesUrl: 'https://providers.example/signatures.json' });
		const degradedFinding = result.findings.find((f) => f.title === 'Provider signature source unavailable');
		expect(degradedFinding).toBeDefined();
		expect(degradedFinding!.severity).toBe('info');
		expect(degradedFinding!.metadata?.signatureSource).toBe('built-in');
	});

	it('returns correct category', async () => {
		mockMxRecords('example.com', ['10 mx.example.com.']);
		const result = await run('example.com');
		expect(result.category).toBe('mx');
	});

	it('should detect null MX record (RFC 7505)', async () => {
		mockMxRecords('nullmx.com', ['0 .']);
		const result = await run('nullmx.com');
		const finding = result.findings.find((f) => f.title === 'Null MX record (RFC 7505)');
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('info');
	});

	it('should flag MX pointing to IP address as medium severity', async () => {
		mockMxRecords('ipmx.com', ['10 192.168.1.1']);
		const result = await run('ipmx.com');
		const finding = result.findings.find((f) => f.title === 'MX points to IP address');
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('medium');
	});

	it('should flag single MX record as low severity', async () => {
		mockMxRecords('single.com', ['10 mx.single.com.']);
		const result = await run('single.com');
		const finding = result.findings.find((f) => f.title === 'Single MX record');
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('low');
	});

	it('should not flag duplicate MX priorities as a finding', async () => {
		mockMxRecords('dupes.com', ['10 mx1.dupes.com.', '10 mx2.dupes.com.']);
		const result = await run('dupes.com');
		const finding = result.findings.find((f) => f.title === 'Duplicate MX priorities');
		expect(finding).toBeUndefined();
	});

	it('should flag dangling MX that does not resolve', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('type=MX') || url.includes('type=15')) {
				const answers = [{ name: 'dangling.com', type: 15, TTL: 300, data: '10 ghost.dangling.com.' }];
				return Promise.resolve(createDohResponse([{ name: 'dangling.com', type: 15 }], answers));
			}
			// A and AAAA queries return empty
			return Promise.resolve(createDohResponse([{ name: 'ghost.dangling.com', type: 1 }], []));
		});
		const { checkMx } = await import('../src/tools/check-mx');
		const result = await checkMx('dangling.com');
		const finding = result.findings.find((f) => f.title === 'Dangling MX record');
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('medium');
		expect(finding!.detail).toContain('ghost.dangling.com');
	});
});
