// test/access-log-event.spec.ts
import { afterEach, describe, expect, it, vi } from 'vitest';

afterEach(() => vi.restoreAllMocks());

const base = {
	ip: '192.0.2.5', ipHash: 'i_abc', ipMasked: '192.0.2.xxx', toolName: 'check_spf', domain: 'example.com',
	source: 'public', country: 'NZ', region: 'Auckland', city: 'Auckland', latitude: '-36.85', longitude: '174.76',
	asn: 13335, asOrg: 'Cloudflare', keyHash: null, clientType: 'cursor', colo: 'AKL',
	sessionHash: 'none', userAgent: 'x', method: 'tools/call', transport: 'json',
	status: 'pass', responseMs: 12, rateLimited: false,
};

describe('buildAccessLogEvent', () => {
	it('nulls city + precise geo at coarse, keeps them at full', async () => {
		const { buildAccessLogEvent } = await import('../src/lib/access-log-event');
		const coarse = buildAccessLogEvent(base, 'coarse');
		expect(coarse.city).toBeNull();
		expect(coarse.latitude).toBeNull();
		expect(coarse.longitude).toBeNull();
		expect(coarse.region).toBe('Auckland'); // region always allowed
		expect(coarse.asn).toBe(13335); // asn always allowed
		expect(coarse.ptrHostname).toBeNull(); // consumer fills later
		expect(coarse.source).toBe('public'); // passed through unchanged
		expect(coarse.userAgent).toBeNull(); // user_agent gated at coarse

		const full = buildAccessLogEvent(base, 'full');
		expect(full.city).toBe('Auckland');
		expect(full.latitude).toBe('-36.85');
		expect(full.piiLevel).toBe('full');
		expect(full.source).toBe('public'); // passed through unchanged
		expect(full.userAgent).toBe('x'); // full preserves raw UA
	});

	it('keeps city but drops precise geo at standard', async () => {
		const { buildAccessLogEvent } = await import('../src/lib/access-log-event');
		const std = buildAccessLogEvent(base, 'standard');
		expect(std.city).toBe('Auckland');
		expect(std.latitude).toBeNull();
		expect(std.userAgent).toBe('x'); // standard preserves raw UA (same tier as city)
	});
});
