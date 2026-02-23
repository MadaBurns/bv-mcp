import { describe, it, expect, vi, afterEach } from 'vitest';
import { RecordType } from '../src/lib/dns';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

/**
 * Helper: mock DoH to return TXT records for DKIM selector queries.
 * selectorRecords maps selector names to their TXT record strings.
 * Selectors not in the map return empty answers.
 */
function mockDkimRecords(selectorRecords: Record<string, string[]>) {
	globalThis.fetch = vi.fn().mockImplementation((url: string) => {
		const nameMatch = url.match(/name=([^&]+)/);
		const queriedName = nameMatch ? decodeURIComponent(nameMatch[1]) : '';

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

		return Promise.resolve(
			createDohResponse([{ name: queriedName, type: 16 }], answers),
		);
	});
}

afterEach(() => {
	restore();
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

	it('treats all-revoked selectors as non-sending domain posture', async () => {
		mockDkimRecords({
			google: ['v=DKIM1; k=rsa; p='],
			selector1: ['v=DKIM1; k=rsa; p=;'],
			default: ['v=DKIM1; p='],
		});
		const r = await run();
		// Should produce a single info finding instead of 3 medium findings
		expect(r.findings).toHaveLength(1);
		expect(r.findings[0].severity).toBe('info');
		expect(r.findings[0].title).toContain('non-sending');
		expect(r.findings[0].detail).toContain('3 DKIM selector(s)');
	});

	it('keeps revoked findings when mixed with valid keys', async () => {
		mockDkimRecords({
			google: ['v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4G'],
			selector1: ['v=DKIM1; k=rsa; p=;'],
		});
		const r = await run();
		const revoked = r.findings.find((f) => f.title.includes('Revoked'));
		expect(revoked).toBeDefined();
		expect(revoked!.severity).toBe('medium');
	});
});

