import { describe, it, expect, beforeEach, vi } from 'vitest';

import { detectProviderMatches, detectProviderMatchesBySelectors, loadProviderSignatures, resetProviderSignatureState } from '../src/lib/provider-signatures';

beforeEach(() => {
	resetProviderSignatureState();
	vi.restoreAllMocks();
});

describe('provider-signatures', () => {
	it('returns built-in signatures when no source url is provided', async () => {
		const result = await loadProviderSignatures();
		expect(result.source).toBe('built-in');
		expect(result.degraded).toBe(false);
		expect(result.inbound.length).toBeGreaterThan(0);
	});

	it('matches providers using label-boundary suffix logic', () => {
		const matches = detectProviderMatches(
			['aspmx.l.google.com', 'mx.evilgoogle.com', 'mail.protection.outlook.com'],
			[
				{ name: 'Google Workspace', domains: ['google.com'] },
				{ name: 'Microsoft 365', domains: ['protection.outlook.com'] },
			],
		);

		expect(matches).toHaveLength(2);
		expect(matches.find((m) => m.provider === 'Google Workspace')?.matches).toContain('aspmx.l.google.com');
		expect(matches.find((m) => m.provider === 'Google Workspace')?.matches).not.toContain('mx.evilgoogle.com');
		expect(matches.find((m) => m.provider === 'Microsoft 365')?.matches).toContain('mail.protection.outlook.com');
	});

	it('matches providers by DKIM selector hints', () => {
		const matches = detectProviderMatchesBySelectors(
			['google', 'selector1', 'custom'],
			[
				{ name: 'Google Workspace', domains: ['google.com'], selectorHints: ['google'] },
				{ name: 'Microsoft 365', domains: ['outlook.com'], selectorHints: ['selector1', 'selector2'] },
			],
		);

		expect(matches).toHaveLength(2);
		expect(matches.find((m) => m.provider === 'Google Workspace')?.matches).toContain('google');
		expect(matches.find((m) => m.provider === 'Microsoft 365')?.matches).toContain('selector1');
	});

	it('reuses runtime signature fetches within the cache window', async () => {
		const sourceUrl = 'https://example.com/signatures.json';
		const payload = {
			version: 'runtime-test-1',
			inbound: [{ name: 'Test Provider', domains: ['mail.test.example'] }],
			outbound: [],
		};

		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => payload,
		} as unknown as Response);

		const first = await loadProviderSignatures({ sourceUrl });
		const second = await loadProviderSignatures({ sourceUrl });

		expect(first.source).toBe('runtime');
		expect(second.source).toBe('runtime');
		expect(first.version).toBe('runtime-test-1');
		expect(second.version).toBe('runtime-test-1');
		expect(globalThis.fetch).toHaveBeenCalledTimes(1);
	});
});
