import { describe, it, expect, afterEach, vi } from 'vitest';
import { RecordType } from '../src/lib/dns';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

function mockDkimRecords(selectorRecords: Record<string, string[]>) {
	globalThis.fetch = vi.fn().mockImplementation((url: string) => {
		const nameMatch = url.match(/name=([^&]+)/);
		const queriedName = nameMatch ? decodeURIComponent(nameMatch[1]) : '';
		let answers: Array<{ name: string; type: number; TTL: number; data: string }> = [];
		for (const [selector, records] of Object.entries(selectorRecords)) {
			const expectedName = `${selector}._domainkey.example.com`;
			if (queriedName === expectedName) {
				answers = records.map(data => ({
					name: expectedName,
					type: RecordType.TXT,
					TTL: 300,
					data: `"${data}"`,
				}));
				break;
			}
		}
		return Promise.resolve(createDohResponse([{ name: queriedName, type: 16 }], answers));
	});
}

afterEach(() => restore());

describe('checkDkim', () => {
	async function run(domain = 'example.com', selector?: string) {
		const { checkDkim } = await import('../src/tools/check-dkim');
		return checkDkim(domain, selector);
	}

	it('should return high finding when no DKIM records found across common selectors', async () => {
		mockDkimRecords({});
		const result = await run();
		expect(result.category).toBe('dkim');
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('high');
		expect(result.findings[0].title).toMatch(/tested selectors/i);
		expect(result.findings[0].detail).toContain('selector probing');
	});

	it('detects DKIM on date-based Google selectors', async () => {
		const strongKey =
			'MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA2a2rwplBCXGHDzhtSF5cz+DfOpZB3Q9nDy0NxQyL8iB4xQoT0Q5Ka0K9KpV4LK3+KZvP5U9ZvL1yR5pZmqZLa5N4H1s7cQ7YQ0+C1jKSRQG7jP8QF1dPLqVfE1pZe7cQ8Kxc6c4PfD8QK9pC7Z1W0K8M3K7N2R4L9Y5L8B3P4N7U5Q6K0O5M5Y6W8P1R7T9A8K6S4P8b0tVm7dC1wYzV6+C2T3U4V5W6X7Y8Z9A0B1C2D3E4F5G6H7I8J9K0L1M2N3O4P5Q6R7S8T9U0V1W2X3Y4z9zzAA';
		mockDkimRecords({
			'20230601': [`v=DKIM1; k=rsa; p=${strongKey}`],
		});
		const result = await run();
		const noDkim = result.findings.find((f) => /No DKIM records found/i.test(f.title));
		const configured = result.findings.find((f) => /DKIM configured/i.test(f.title));
		expect(noDkim).toBeUndefined();
		expect(configured).toBeDefined();
		expect(configured?.metadata?.selectorsFound).toContain('20230601');
	});

	it('should return info finding when valid DKIM record found', async () => {
		// Use a genuinely strong RSA key (>330 chars = 4096-bit) to avoid key-strength findings
		const strongKey =
			'MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA2a2rwplBCXGHDzhtSF5cz+DfOpZB3Q9nDy0NxQyL8iB4xQoT0Q5Ka0K9KpV4LK3+KZvP5U9ZvL1yR5pZmqZLa5N4H1s7cQ7YQ0+C1jKSRQG7jP8QF1dPLqVfE1pZe7cQ8Kxc6c4PfD8QK9pC7Z1W0K8M3K7N2R4L9Y5L8B3P4N7U5Q6K0O5M5Y6W8P1R7T9A8K6S4P8b0tVm7dC1wYzV6+C2T3U4V5W6X7Y8Z9A0B1C2D3E4F5G6H7I8J9K0L1M2N3O4P5Q6R7S8T9U0V1W2X3Y4z9zzAA';
		mockDkimRecords({ google: [`v=DKIM1; k=rsa; p=${strongKey}`] });
		const result = await run();
		const finding = result.findings.find(f => f.severity === 'info' && /configured|found/i.test(f.title));
		expect(finding).toBeDefined();
		expect(finding!.title).toMatch(/DKIM configured/i);
		expect(finding!.metadata).toBeDefined();
		expect(finding!.metadata?.signalType).toBe('dkim');
		expect(finding!.metadata?.selectorsFound).toContain('google');
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
		// Use a genuinely strong RSA key (>330 chars) to avoid key-strength findings
		const strongKey =
			'MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA2a2rwplBCXGHDzhtSF5cz+DfOpZB3Q9nDy0NxQyL8iB4xQoT0Q5Ka0K9KpV4LK3+KZvP5U9ZvL1yR5pZmqZLa5N4H1s7cQ7YQ0+C1jKSRQG7jP8QF1dPLqVfE1pZe7cQ8Kxc6c4PfD8QK9pC7Z1W0K8M3K7N2R4L9Y5L8B3P4N7U5Q6K0O5M5Y6W8P1R7T9A8K6S4P8b0tVm7dC1wYzV6+C2T3U4V5W6X7Y8Z9A0B1C2D3E4F5G6H7I8J9K0L1M2N3O4P5Q6R7S8T9U0V1W2X3Y4z9zzAA';
		mockDkimRecords({ myselector: [`v=DKIM1; k=rsa; p=${strongKey}`] });
		const r = await run('example.com', 'myselector');
		const f = r.findings.find((f) => f.severity === 'info' && /configured|found/i.test(f.title));
		expect(f).toBeDefined();
		expect(f!.detail).toContain('myselector');
		expect(f!.metadata?.selectorsFound).toContain('myselector');
	});

	it('finds records across multiple selectors', async () => {
		// Use genuinely strong RSA keys (>330 chars) to avoid key-strength findings
		const strongKey =
			'MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA2a2rwplBCXGHDzhtSF5cz+DfOpZB3Q9nDy0NxQyL8iB4xQoT0Q5Ka0K9KpV4LK3+KZvP5U9ZvL1yR5pZmqZLa5N4H1s7cQ7YQ0+C1jKSRQG7jP8QF1dPLqVfE1pZe7cQ8Kxc6c4PfD8QK9pC7Z1W0K8M3K7N2R4L9Y5L8B3P4N7U5Q6K0O5M5Y6W8P1R7T9A8K6S4P8b0tVm7dC1wYzV6+C2T3U4V5W6X7Y8Z9A0B1C2D3E4F5G6H7I8J9K0L1M2N3O4P5Q6R7S8T9U0V1W2X3Y4z9zzAA';
		mockDkimRecords({
			google: [`v=DKIM1; k=rsa; p=${strongKey}`],
			selector1: [`v=DKIM1; k=rsa; p=${strongKey}`],
		});
		const r = await run();
		const f = r.findings.find((f) => f.severity === 'info' && /configured|found/i.test(f.title));
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

	it('detects strong RSA 4096-bit key (>330 chars) with info level', async () => {
		// Simulates a 4096-bit RSA key (>330 base64 chars)
		const strongKey =
			'MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA2a2rwplBCXGHDzhtSF5cz+DfOpZB3Q9nDy0NxQyL8iB4xQoT0Q5Ka0K9KpV4LK3+KZvP5U9ZvL1yR5pZmqZLa5N4H1s7cQ7YQ0+C1jKSRQG7jP8QF1dPLqVfE1pZe7cQ8Kxc6c4PfD8QK9pC7Z1W0K8M3K7N2R4L9Y5L8B3P4N7U5Q6K0O5M5Y6W8P1R7T9A8K6S4P8b0tVm7dC1wYzV6+C2T3U4V5W6X7Y8Z9A0B1C2D3E4F5G6H7I8J9K0L1M2N3O4P5Q6R7S8T9U0V1W2X3Y4z9zzAA';
		mockDkimRecords({ google: [`v=DKIM1; k=rsa; p=${strongKey}`] });
		const r = await run();
		const keyStrengthFinding = r.findings.find((f) => /strong|4096/i.test(f.title));
		// Strong keys should not produce a warning finding
		expect(keyStrengthFinding).toBeUndefined();
	});

	it('detects weak RSA 512-bit key (<150 chars) with critical severity', async () => {
		// Simulates a weak 512-bit RSA key (<150 base64 chars)
		const weakKey = 'MIGfMA0GCSqGSIb3DQEBAQUAA4G';
		mockDkimRecords({ google: [`v=DKIM1; k=rsa; p=${weakKey}`] });
		const r = await run();
		const finding = r.findings.find((f) => /weak|512/i.test(f.title));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('critical');
		expect(finding!.metadata?.estimatedBits).toBe(512);
	});

	it('detects legacy RSA 1024-bit key (<230 chars) with high severity', async () => {
		// Simulates a 1024-bit RSA key (150-230 base64 chars)
		const legacyKey =
			'MIGfMA0GCSqGSIb3DQEBAQUFAAOCDg8AMIIBCgKCAQEA1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012';
		mockDkimRecords({ google: [`v=DKIM1; k=rsa; p=${legacyKey}`] });
		const r = await run();
		const finding = r.findings.find((f) => /legacy|1024/i.test(f.title));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('high');
		expect(finding!.metadata?.estimatedBits).toBe(1024);
	});

	it('consolidates duplicate legacy key findings across selector probing', async () => {
		const legacyKey =
			'MIGfMA0GCSqGSIb3DQEBAQUFAAOCDg8AMIIBCgKCAQEA1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012';
		mockDkimRecords({
			google: [`v=DKIM1; k=rsa; p=${legacyKey}`],
			selector1: [`v=DKIM1; k=rsa; p=${legacyKey}`],
		});
		const r = await run();
		const legacyFindings = r.findings.filter((f) => /Legacy RSA key/i.test(f.title));
		expect(legacyFindings).toHaveLength(1);
		expect(legacyFindings[0].severity).toBe('high');

		const consolidated = r.findings.find((f) => /consolidated/i.test(f.title));
		expect(consolidated).toBeDefined();
		expect(consolidated!.severity).toBe('info');
	});

	it('detects RSA 2048-bit key (230-330 chars) with medium severity', async () => {
		// Simulates a 2048-bit RSA key (230-330 base64 chars)
		const recommendedKey =
			'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Z3VS5JJcds3s2m0V5YxFqj7xFqJ1LxlZN8W6WqLkKl1B+dKZgL5X4dQr3+4Tx3Y3Z5Z7M9N0O1P2Q3R4S5T6U7V8W9X0Y1Z2A3B4C5D6E7F8G9H0I1J2K3L4M5N6O7P8Q9R0S1T2U3V4W5X6Y7Z8A9B0C1D2E3F4G5H6I7J8K9L0M1N2O3P4Q5R6S7T8U9';
		mockDkimRecords({ google: [`v=DKIM1; k=rsa; p=${recommendedKey}`] });
		const r = await run();
		const finding = r.findings.find((f) => /recommended|2048|below/i.test(f.title));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('medium');
		expect(finding!.metadata?.estimatedBits).toBe(2048);
	});

	it('treats ED25519 keys as always strong without key-strength finding', async () => {
		// Real Ed25519 public key: 44 base64 chars, no literal "ed25519" in key material
		mockDkimRecords({ google: ['v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo='] });
		const r = await run();
		const weakFinding = r.findings.find((f) => /weak|legacy|below recommended/i.test(f.title));
		expect(weakFinding).toBeUndefined();
	});

	it('produces info finding for Ed25519 key with k=ed25519', async () => {
		mockDkimRecords({ google: ['v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo='] });
		const r = await run();
		const infoFinding = r.findings.find((f) => /ed25519/i.test(f.title) && f.severity === 'info');
		expect(infoFinding).toBeDefined();
		expect(infoFinding!.detail).toContain('Ed25519');
		expect(infoFinding!.metadata?.keyType).toBe('ed25519');
	});

	it('still flags short RSA key as critical when k=rsa is explicit', async () => {
		const weakKey = 'MIGfMA0GCSqGSIb3DQEBAQUAA4G';
		mockDkimRecords({ google: [`v=DKIM1; k=rsa; p=${weakKey}`] });
		const r = await run();
		const finding = r.findings.find((f) => /weak/i.test(f.title));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('critical');
	});

	it('works normally for RSA key with no k= tag and normal length', async () => {
		const strongKey =
			'MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA2a2rwplBCXGHDzhtSF5cz+DfOpZB3Q9nDy0NxQyL8iB4xQoT0Q5Ka0K9KpV4LK3+KZvP5U9ZvL1yR5pZmqZLa5N4H1s7cQ7YQ0+C1jKSRQG7jP8QF1dPLqVfE1pZe7cQ8Kxc6c4PfD8QK9pC7Z1W0K8M3K7N2R4L9Y5L8B3P4N7U5Q6K0O5M5Y6W8P1R7T9A8K6S4P8b0tVm7dC1wYzV6+C2T3U4V5W6X7Y8Z9A0B1C2D3E4F5G6H7I8J9K0L1M2N3O4P5Q6R7S8T9U0V1W2X3Y4z9zzAA';
		mockDkimRecords({ google: [`v=DKIM1; p=${strongKey}`] });
		const r = await run();
		const weakFinding = r.findings.find((f) => /weak|legacy|below recommended/i.test(f.title));
		expect(weakFinding).toBeUndefined();
	});

	it('flags short key without k= tag as medium severity with hint to add k= tag', async () => {
		// 44-char key with no k= tag — could be Ed25519 without proper declaration
		mockDkimRecords({ google: ['v=DKIM1; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIa'] });
		const r = await run();
		const finding = r.findings.find((f) => /short key material/i.test(f.title));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('medium');
		expect(finding!.detail).toContain('k=ed25519');
	});

	it('detects missing v= tag with medium severity', async () => {
		mockDkimRecords({ google: ['k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNAAAA'] });
		const r = await run();
		const finding = r.findings.find((f) => /version tag|missing.*v=/i.test(f.title));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('medium');
		expect(finding!.title).toContain('google');
	});

	it('aggregates findings for multiple selectors with mixed key strengths', async () => {
		const strongKey =
			'MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA2a2rwplBCXGHDzhtSF5cz+DfOpZB3Q9nDy0NxQyL8iB4xQoT0Q5Ka0K9KpV4LK3+KZvP5U9ZvL1yR5pZmqZLa5N4H1s7cQ7YQ0+C1jKSRQG7jP8QF1dPLqVfE1pZe7cQ8Kxc6c4PfD8QK9pC7Z1W0K8M3K7N2R4L9Y5L8B3P4N7U5Q6K0O5M5Y6W8P1R7T9A8K6S4P8b0tVm7dC1wYzV6+C2T3U4V5W6X7Y8Z9A0B1C2D3E4F5G6H7I8J9K0L1M2N3O4P5Q6R7S8T9U0V1W2X3Y4z9zzAA';
		const weakKey = 'MIGfMA0GCSqGSIb3DQEBAQUAA4G';
		mockDkimRecords({
			google: [`v=DKIM1; k=rsa; p=${strongKey}`],
			selector1: [`v=DKIM1; k=rsa; p=${weakKey}`],
		});
		const r = await run();
		const weakFinding = r.findings.find((f) => /weak|512|critical/i.test(f.title));
		expect(weakFinding).toBeDefined();
		expect(weakFinding!.severity).toBe('critical');
		// Google has strong key - should not produce a key-strength finding
		const strongFinding = r.findings.find((f) => f.title.includes('google') && /weak|legacy|recommended/i.test(f.title));
		expect(strongFinding).toBeUndefined();
	});

	it('handles malformed base64 in p= value gracefully without crash', async () => {
		mockDkimRecords({ google: ['v=DKIM1; k=rsa; p=!@#$%^&*()'] });
		const r = await run();
		// Should not crash; malformed keys are still processed
		expect(r.category).toBe('dkim');
		expect(r.findings.length).toBeGreaterThan(0);
	});
});
