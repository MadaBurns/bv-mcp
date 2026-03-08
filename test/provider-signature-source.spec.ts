import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
	buildResult,
	fetchProviderPayload,
	isValidSignaturePayload,
	normalizeAllowedHosts,
	validateRuntimeSourceUrl,
} from '../src/lib/provider-signature-source';

async function sha256Hex(input: string): Promise<string> {
	const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
	return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

beforeEach(() => {
	vi.restoreAllMocks();
});

describe('provider-signature-source', () => {
	it('normalizes allowlisted hosts', () => {
		expect(normalizeAllowedHosts([' Example.COM ', '', 'trusted.example'])).toEqual(['example.com', 'trusted.example']);
		expect(normalizeAllowedHosts(undefined)).toEqual([]);
	});

	it('validates secure source URLs against an allowlist', () => {
		const url = validateRuntimeSourceUrl('https://example.com/signatures.json', ['example.com']);
		expect(url.hostname).toBe('example.com');
		expect(() => validateRuntimeSourceUrl('http://example.com/signatures.json', ['example.com'])).toThrow('HTTPS is required');
		expect(() => validateRuntimeSourceUrl('https://other.example/signatures.json', ['example.com'])).toThrow('host is not allowlisted');
	});

	it('normalizes provider payloads when building results', () => {
		const result = buildResult(
			{
				version: ' test-version ',
				inbound: [{ name: ' Test Provider ', domains: ['Mail.Example.com.', ''], selectorHints: [' Selector1 ', ''] }],
				outbound: [],
			},
			'runtime',
			false,
		);

		expect(result.version).toBe('test-version');
		expect(result.inbound).toEqual([{ name: 'Test Provider', domains: ['mail.example.com'], selectorHints: ['selector1'] }]);
	});

	it('validates provider payload shapes', () => {
		expect(isValidSignaturePayload({ version: 'v1', inbound: [], outbound: [] })).toBe(true);
		expect(isValidSignaturePayload({ version: 1 })).toBe(false);
		expect(isValidSignaturePayload({ inbound: {} })).toBe(false);
	});

	it('fetches and verifies a pinned runtime payload', async () => {
		const payload = JSON.stringify({ version: 'runtime-test', inbound: [], outbound: [] });
		const expectedSha256 = await sha256Hex(payload);
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			text: async () => payload,
		} as unknown as Response);

		await expect(fetchProviderPayload('https://example.com/signatures.json', 1000, 0, expectedSha256)).resolves.toEqual({
			version: 'runtime-test',
			inbound: [],
			outbound: [],
		});
	});
});