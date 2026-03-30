import { describe, it, expect } from 'vitest';
import { detectProviders, getProviderFixSteps, type DetectedProvider } from '../src/tools/provider-guides';

describe('provider-guides', () => {
	describe('detectProviders', () => {
		it('detects Google Workspace from MX records', () => {
			const result = detectProviders({
				mxHosts: ['aspmx.l.google.com', 'alt1.aspmx.l.google.com'],
				spfIncludes: [],
				nsHosts: [],
			});
			expect(result).toContainEqual(expect.objectContaining({ name: 'Google Workspace', role: 'mail' }));
		});

		it('detects Microsoft 365 from MX records', () => {
			const result = detectProviders({
				mxHosts: ['example-com.mail.protection.outlook.com'],
				spfIncludes: ['spf.protection.outlook.com'],
				nsHosts: [],
			});
			expect(result).toContainEqual(expect.objectContaining({ name: 'Microsoft 365', role: 'mail' }));
		});

		it('detects Cloudflare from NS records', () => {
			const result = detectProviders({
				mxHosts: [],
				spfIncludes: [],
				nsHosts: ['ada.ns.cloudflare.com', 'bob.ns.cloudflare.com'],
			});
			expect(result).toContainEqual(expect.objectContaining({ name: 'Cloudflare', role: 'dns' }));
		});

		it('detects multiple providers', () => {
			const result = detectProviders({
				mxHosts: ['aspmx.l.google.com'],
				spfIncludes: ['_spf.google.com', 'sendgrid.net'],
				nsHosts: ['ns1.cloudflare.com'],
			});
			expect(result.length).toBeGreaterThanOrEqual(3);
		});

		it('returns empty array for unrecognized infrastructure', () => {
			const result = detectProviders({
				mxHosts: ['mail.custom-server.example.org'],
				spfIncludes: [],
				nsHosts: ['ns1.custom-dns.example.org'],
			});
			expect(result).toHaveLength(0);
		});
	});

	describe('getProviderFixSteps', () => {
		it('returns DNS steps for Cloudflare', () => {
			const steps = getProviderFixSteps('Cloudflare', 'add_txt', {
				name: '_dmarc',
				value: 'v=DMARC1; p=reject',
			});
			expect(steps).toBeDefined();
			expect(steps!.length).toBeGreaterThan(0);
			expect(steps!.some((s) => s.toLowerCase().includes('cloudflare'))).toBe(true);
		});

		it('returns DKIM steps for Google Workspace', () => {
			const steps = getProviderFixSteps('Google Workspace', 'enable_dkim', {});
			expect(steps).toBeDefined();
			expect(steps!.some((s) => s.toLowerCase().includes('google admin'))).toBe(true);
		});

		it('returns null for unknown provider', () => {
			const steps = getProviderFixSteps('UnknownProvider', 'add_txt', {});
			expect(steps).toBeNull();
		});
	});
});
