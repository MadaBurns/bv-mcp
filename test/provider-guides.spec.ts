import { describe, it, expect } from 'vitest';
import {
	detectProviders,
	getProviderFixSteps,
	matchProviderForSpfInclude,
	matchProviderForNsHost,
	matchProviderForMxHost,
} from '../src/tools/provider-guides';

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

describe('provider catalog batch (#286)', () => {
	describe('C1 — Google MX googlemail.com', () => {
		it('maps *.googlemail.com MX to Google Workspace', () => {
			expect(matchProviderForMxHost('aspmx.l.googlemail.com')).toBe('Google Workspace');
		});
		it('still maps *.google.com MX to Google Workspace', () => {
			expect(matchProviderForMxHost('aspmx.l.google.com')).toBe('Google Workspace');
		});
	});

	describe('C2 — Google SPF _netblocks*', () => {
		it.each(['_netblocks.google.com', '_netblocks2.google.com', '_netblocks3.google.com'])(
			'maps %s to Google Workspace',
			(host) => {
				expect(matchProviderForSpfInclude(host)).toBe('Google Workspace');
			},
		);
		it('still maps _spf.google.com to Google Workspace', () => {
			expect(matchProviderForSpfInclude('_spf.google.com')).toBe('Google Workspace');
		});
	});

	describe('C3 — SPF include catalog', () => {
		it.each([
			['mail.zendesk.com', 'Zendesk'],
			['mktomail.com', 'Marketo'],
			['stspg-customer.com', 'Statuspage'],
			['cust-spf.exacttarget.com', 'Salesforce Marketing Cloud'],
			['aspmx.pardot.com', 'Salesforce Pardot'],
			['_spf.qualtrics.com', 'Qualtrics'],
			['_spf.e.sparkpost.com', 'SparkPost'],
			['spf1.alibaba.mail.aliyun.com', 'Alibaba Mail'],
			['spf.mandrillapp.com', 'Mailchimp Transactional'],
		])('maps SPF %s to %s', (host, provider) => {
			expect(matchProviderForSpfInclude(host)).toBe(provider);
		});
		it('still maps servers.mcsv.net to Mailchimp Transactional', () => {
			expect(matchProviderForSpfInclude('servers.mcsv.net')).toBe('Mailchimp Transactional');
		});
		it('does not collapse Pardot into Salesforce', () => {
			expect(matchProviderForSpfInclude('aspmx.pardot.com')).not.toBe('Salesforce');
		});
	});

	describe('C4 — NS catalog', () => {
		it.each([
			['ns1-01.azure-dns.com', 'Azure DNS'],
			['ns2-01.azure-dns.net', 'Azure DNS'],
			['ns3-01.azure-dns.org', 'Azure DNS'],
			['ns4-01.azure-dns.info', 'Azure DNS'],
			['dns1.netlifydns.com', 'Netlify DNS'],
			['ns1.vercel-dns.com', 'Vercel DNS'],
			['ns1.p201.dns.oraclecloud.net', 'Oracle Cloud DNS'],
			['ns1.salesforce-dns.com', 'Salesforce DNS'],
			['ns1.alibabadns.com', 'Alibaba DNS'],
		])('maps NS %s to %s', (host, provider) => {
			expect(matchProviderForNsHost(host)).toBe(provider);
		});
	});

	describe('C5 — MX catalog', () => {
		it('maps *.fireeyecloud.com MX to Trellix Email Security', () => {
			expect(matchProviderForMxHost('mx1.fireeyecloud.com')).toBe('Trellix Email Security');
		});
		it('maps *.cf-emailsecurity.net MX to Cloudflare Email Security', () => {
			expect(matchProviderForMxHost('isolated-eu.mx.cf-emailsecurity.net')).toBe('Cloudflare Email Security');
		});
	});

	describe('M1 — SPF macro / selector normalization', () => {
		it.each([
			['nytimes.com._nspf.vali.email', 'Valimail'],
			['%{i}._ip.%{h}._ehlo.%{d}._spf.vali.email', 'Valimail'],
			['spf-00789a01.pphosted.com', 'Proofpoint'],
			['%{ir}.%{v}.%{d}.spf.has.pphosted.com', 'Proofpoint'],
		])('maps SPF %s to %s', (host, provider) => {
			expect(matchProviderForSpfInclude(host)).toBe(provider);
		});
	});
});
