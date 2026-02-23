import { describe, it, expect, vi, afterEach } from 'vitest';
import { RecordType } from '../src/lib/dns';

const originalFetch = globalThis.fetch;

/**
 * Helper: mock DoH to return TXT records for DKIM selector queries.
 * selectorRecords maps selector names to their TXT record strings.
 * Selectors not in the map return empty answers.
 */
function mockDkimRecords(selectorRecords: Record<string, string[]>) {
	globalThis.fetch = vi.fn().mockImplementation((url: string) => {
		// Extract the queried name from the URL
		const nameMatch = url.match(/name=([^&]+)/);
		const queriedName = nameMatch ? decodeURIComponent(nameMatch[1]) : '';

		// Find matching selector
		let answers: Array<{ name: string; type: number; TTL: number; data: string }> = [];
		for (const [selector, records] of Object.entries(selectorRecords)) {
			const expectedName = `${selector}._domainkey.example.com`;
			if (queriedName === expectedName) {
				answers = records.map((data) => ({
					name: expectedName,
					type: RecordType.TXT,
					TTL: 300,
					data: `"${data}"`,
				}));
				break;
			}
		}

		return Promise.resolve({
			ok: true,
			status: 200,
			json: () =>
				Promise.resolve({
					Status: 0, TC: false, RD: true, RA: true, AD: false, CD: false,
					Question: [{ name: queriedName, type: 16 }],
					Answer: answers,
				}),
		} as unknown as Response);
	});
}

afterEach(() => {
	globalThis.fetch = originalFetch;
});

describe('checkDkim', () => {
	async function run(domain = 'example.com', selector?: string) {
		const { checkDkim } = await import('../src/tools/check-dkim');
		return checkDkim(domain, selector);
	}

	it('returns high finding when no DKIM records found across common selectors', async () => {
		mockDkimRecords({});
		const r = await run();
		expect(r.category).toBe('dkim');
		expect(r.findings).toHaveLength(1);
		expect(r.findings[0].severity).toBe('high');
		expect(r.findings[0].title).toContain('No DKIM');
	});

	it('returns info finding when valid DKIM record found', async () => {
		mockDkimRecords({ google: ['v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4G'] });
		const r = await run();
		const f = r.findings.find((f) => f.severity === 'info');
		expect(f).toBeDefined();
		expect(f!.title).toContain('DKIM configured');
	});

	it('returns medium finding for revoked key (empty p=)', async () => {
		mockDkimRecords({ google: ['v=DKIM1; k=rsa; p=;'] });
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('Revoked'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('medium');
	});

	it('returns medium finding for revoked key (p= at end)', async () => {
		mockDkimRecords({ google: ['v=DKIM1; k=rsa; p='] });
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('Revoked'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('medium');
	});

	it('returns medium finding for unknown key type', async () => {
		mockDkimRecords({ google: ['v=DKIM1; k=dsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4G'] });
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('Unknown DKIM key type'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('medium');
	});

	it('accepts rsa key type without finding', async () => {
		mockDkimRecords({ google: ['v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4G'] });
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('Unknown DKIM key type'));
		expect(f).toBeUndefined();
	});

	it('accepts ed25519 key type without finding', async () => {
		mockDkimRecords({ google: ['v=DKIM1; k=ed25519; p=MIGfMA0GCSqGSIb3DQEBAQUAA4G'] });
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('Unknown DKIM key type'));
		expect(f).toBeUndefined();
	});

	it('returns low finding for testing mode (t=y)', async () => {
		mockDkimRecords({ google: ['v=DKIM1; k=rsa; t=y; p=MIGfMA0GCSqGSIb3DQEBAQUAA4G'] });
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('testing mode'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('low');
	});

	it('checks specific selector when provided', async () => {
		mockDkimRecords({ myselector: ['v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4G'] });
		const r = await run('example.com', 'myselector');
		const f = r.findings.find((f) => f.severity === 'info');
		expect(f).toBeDefined();
		expect(f!.detail).toContain('myselector');
	});

	it('finds records across multiple selectors', async () => {
		mockDkimRecords({
			google: ['v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4G'],
			selector1: ['v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4G'],
		});
		const r = await run();
		const f = r.findings.find((f) => f.severity === 'info');
		expect(f).toBeDefined();
		expect(f!.detail).toContain('google');
		expect(f!.detail).toContain('selector1');
	});

	it('reports multiple issues across selectors', async () => {
		mockDkimRecords({
			google: ['v=DKIM1; k=rsa; t=y; p=MIGfMA0GCSqGSIb3DQEBAQUAA4G'],
			selector1: ['v=DKIM1; k=dsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4G'],
		});
		const r = await run();
		const testingFinding = r.findings.find((f) => f.title.includes('testing mode'));
		const keyTypeFinding = r.findings.find((f) => f.title.includes('Unknown DKIM key type'));
		expect(testingFinding).toBeDefined();
		expect(keyTypeFinding).toBeDefined();
	});
});

