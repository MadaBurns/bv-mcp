// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, vi } from 'vitest';
import { checkDKIM } from '../../checks/check-dkim';
import type { DNSQueryFunction } from '../../types';

function createMockDNS(records: Record<string, string[]>): DNSQueryFunction {
	return vi.fn(async (domain: string, _type: string) => {
		return records[domain] ?? [];
	});
}

/**
 * Build a DNS mock supporting both TXT and CNAME queries.
 * - `txt[name]` returns TXT records for that name.
 * - `cname[name]` returns the CNAME target for that name when type === 'CNAME'.
 *   TXT queries for a CNAME-owning name will return the TXT of the resolved target.
 */
function createCnameAwareDNS(
	txt: Record<string, string[]>,
	cname: Record<string, string>,
): DNSQueryFunction {
	function resolveTxt(name: string, depth = 0): string[] {
		if (depth > 5) return [];
		if (cname[name] !== undefined) return resolveTxt(cname[name], depth + 1);
		return txt[name] ?? [];
	}
	return vi.fn(async (domain: string, type: string) => {
		if (type === 'CNAME') {
			return cname[domain] !== undefined ? [cname[domain]] : [];
		}
		return resolveTxt(domain);
	});
}

describe('checkDKIM', () => {
	it('returns high when no DKIM records found among selectors', async () => {
		const queryDNS = createMockDNS({});
		const result = await checkDKIM('example.com', queryDNS);
		expect(result.category).toBe('dkim');
		expect(result.findings.some((f) => f.title === 'No DKIM records found among tested selectors')).toBe(true);
		expect(result.findings[0].severity).toBe('high');
	});

	it('detects DKIM record with specific selector', async () => {
		const queryDNS = createMockDNS({
			'myselector._domainkey.example.com': ['v=DKIM1; k=rsa; p=' + 'A'.repeat(600)],
		});
		const result = await checkDKIM('example.com', queryDNS, { selector: 'myselector' });
		expect(result.findings.some((f) => f.title === 'DKIM configured')).toBe(true);
	});

	it('flags revoked DKIM key', async () => {
		const queryDNS = createMockDNS({
			'default._domainkey.example.com': ['v=DKIM1; p=;'],
		});
		const result = await checkDKIM('example.com', queryDNS);
		// Single revoked key = medium finding
		expect(result.findings.some((f) => f.title.includes('Revoked DKIM key'))).toBe(true);
	});

	it('detects ed25519 key type', async () => {
		const queryDNS = createMockDNS({
			'default._domainkey.example.com': ['v=DKIM1; k=ed25519; p=AAAA'],
		});
		const result = await checkDKIM('example.com', queryDNS);
		expect(result.findings.some((f) => f.title.includes('Ed25519'))).toBe(true);
	});

	it('flags testing mode', async () => {
		const queryDNS = createMockDNS({
			'default._domainkey.example.com': ['v=DKIM1; k=rsa; t=y; p=' + 'A'.repeat(400)],
		});
		const result = await checkDKIM('example.com', queryDNS);
		expect(result.findings.some((f) => f.title.includes('testing mode'))).toBe(true);
	});

	it('detects Cloudflare Email Routing DKIM selector (cf2024-1)', async () => {
		const queryDNS = createMockDNS({
			'cf2024-1._domainkey.example.com': ['v=DKIM1; k=rsa; p=' + 'A'.repeat(600)],
		});
		const result = await checkDKIM('example.com', queryDNS);
		expect(result.findings.some((f) => f.title === 'DKIM configured')).toBe(true);
	});

	// Defect D — probe list expansion (proton.me + other major providers)

	it('detects DKIM on proton.me protonmail selector', async () => {
		const queryDNS = createMockDNS({
			'protonmail._domainkey.proton.me': ['v=DKIM1; k=rsa; p=' + 'A'.repeat(600)],
		});
		const result = await checkDKIM('proton.me', queryDNS);
		expect(result.findings.some((f) => f.title === 'DKIM configured')).toBe(true);
		const configured = result.findings.find((f) => f.title === 'DKIM configured');
		expect(configured?.metadata?.selectorsFound).toContain('protonmail');
	});

	it('detects DKIM on proton.me protonmail2 selector', async () => {
		const queryDNS = createMockDNS({
			'protonmail2._domainkey.proton.me': ['v=DKIM1; k=rsa; p=' + 'A'.repeat(600)],
		});
		const result = await checkDKIM('proton.me', queryDNS);
		const configured = result.findings.find((f) => f.title === 'DKIM configured');
		expect(configured).toBeDefined();
		expect(configured?.metadata?.selectorsFound).toContain('protonmail2');
	});

	it('detects DKIM on proton.me protonmail3 selector', async () => {
		const queryDNS = createMockDNS({
			'protonmail3._domainkey.proton.me': ['v=DKIM1; k=rsa; p=' + 'A'.repeat(600)],
		});
		const result = await checkDKIM('proton.me', queryDNS);
		const configured = result.findings.find((f) => f.title === 'DKIM configured');
		expect(configured).toBeDefined();
		expect(configured?.metadata?.selectorsFound).toContain('protonmail3');
	});

	it('probe list includes Mandrill, MailerSend, SparkPost and Klaviyo selectors', async () => {
		// We can't introspect the constant directly without importing it; instead,
		// verify each selector resolves a TXT to a 'DKIM configured' finding.
		const cases: Array<{ selector: string }> = [
			{ selector: 'mandrill' },
			{ selector: 'mte1' }, // MailerSend
			{ selector: 'scph1220' }, // SparkPost
			{ selector: 'dkim2' }, // Klaviyo / generic secondary
		];
		for (const c of cases) {
			const queryDNS = createMockDNS({
				[`${c.selector}._domainkey.example.com`]: ['v=DKIM1; k=rsa; p=' + 'A'.repeat(600)],
			});
			const result = await checkDKIM('example.com', queryDNS);
			const configured = result.findings.find((f) => f.title === 'DKIM configured');
			expect(configured, `expected configured finding for selector ${c.selector}`).toBeDefined();
			expect(configured?.metadata?.selectorsFound).toContain(c.selector);
		}
	});

	// Defect E — score floor on probe miss

	it('caps score at 50 when no selectors found (HIGH finding self-consistency)', async () => {
		const queryDNS = createMockDNS({});
		const result = await checkDKIM('example.com', queryDNS);
		expect(result.findings[0].severity).toBe('high');
		expect(result.score).toBeLessThanOrEqual(50);
	});

	it('does not cap score when at least one selector resolves', async () => {
		const queryDNS = createMockDNS({
			'google._domainkey.example.com': ['v=DKIM1; k=rsa; p=' + 'A'.repeat(600)],
		});
		const result = await checkDKIM('example.com', queryDNS);
		// Strong key, no findings beyond info → score should stay at 100
		expect(result.score).toBe(100);
	});

	// Defect F — CNAME-to-SaaS attribution

	it('attributes SendGrid CNAME delegation in finding metadata', async () => {
		const queryDNS = createCnameAwareDNS(
			{
				's1.domainkey.u2680008.wl009.sendgrid.net': [
					// SendGrid's real-world record: no v=DKIM1, with t=s
					'k=rsa; t=s; p=' + 'A'.repeat(600),
				],
			},
			{
				's1._domainkey.example.com': 's1.domainkey.u2680008.wl009.sendgrid.net',
			},
		);
		const result = await checkDKIM('example.com', queryDNS);
		// Should still find the selector
		const configured = result.findings.find((f) => f.title === 'DKIM configured');
		expect(configured).toBeDefined();
		expect(configured?.metadata?.selectorsFound).toContain('s1');
		// Missing v= should be reported but attributed
		const versionFinding = result.findings.find((f) => /version tag|missing.*v=/i.test(f.title));
		expect(versionFinding).toBeDefined();
		// Downgrade severity from medium → info when CNAME-delegated
		expect(versionFinding?.severity).toBe('info');
		// Attribution metadata
		expect(versionFinding?.metadata?.delegatedTo).toBe('SendGrid');
	});

	it('downgrades 1024-bit RSA finding severity high → medium when CNAME-delegated to SaaS', async () => {
		// 1024-bit RSA key (~150-230 chars)
		const legacyKey =
			'MIGfMA0GCSqGSIb3DQEBAQUFAAOCDg8AMIIBCgKCAQEA1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012';
		const queryDNS = createCnameAwareDNS(
			{
				's2.domainkey.u2680008.wl009.sendgrid.net': [`v=DKIM1; k=rsa; p=${legacyKey}`],
			},
			{
				's2._domainkey.example.com': 's2.domainkey.u2680008.wl009.sendgrid.net',
			},
		);
		const result = await checkDKIM('example.com', queryDNS);
		const legacyFinding = result.findings.find((f) => /Legacy RSA key/i.test(f.title));
		expect(legacyFinding).toBeDefined();
		// Downgraded from high to medium because stripe (or any tenant) can't fix SendGrid's key
		expect(legacyFinding?.severity).toBe('medium');
		expect(legacyFinding?.metadata?.delegatedTo).toBe('SendGrid');
	});

	it('preserves high severity for 1024-bit RSA when NOT CNAME-delegated', async () => {
		const legacyKey =
			'MIGfMA0GCSqGSIb3DQEBAQUFAAOCDg8AMIIBCgKCAQEA1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012';
		const queryDNS = createMockDNS({
			'google._domainkey.example.com': [`v=DKIM1; k=rsa; p=${legacyKey}`],
		});
		const result = await checkDKIM('example.com', queryDNS);
		const legacyFinding = result.findings.find((f) => /Legacy RSA key/i.test(f.title));
		expect(legacyFinding).toBeDefined();
		expect(legacyFinding?.severity).toBe('high');
		expect(legacyFinding?.metadata?.delegatedTo).toBeUndefined();
	});

	it('attributes Mailgun CNAME delegation', async () => {
		const queryDNS = createCnameAwareDNS(
			{
				'mailo._mailgun.org': ['k=rsa; p=' + 'A'.repeat(600)],
			},
			{
				'mail._domainkey.example.com': 'mailo._mailgun.org',
			},
		);
		const result = await checkDKIM('example.com', queryDNS);
		const versionFinding = result.findings.find((f) => /version tag|missing.*v=/i.test(f.title));
		expect(versionFinding).toBeDefined();
		expect(versionFinding?.metadata?.delegatedTo).toBe('Mailgun');
		expect(versionFinding?.severity).toBe('info');
	});

	it('attributes Postmark CNAME delegation', async () => {
		const queryDNS = createCnameAwareDNS(
			{
				'pm._domainkey.pm.mtasv.net': ['k=rsa; p=' + 'A'.repeat(600)],
			},
			{
				'pm._domainkey.example.com': 'pm._domainkey.pm.mtasv.net',
			},
		);
		const result = await checkDKIM('example.com', queryDNS);
		const versionFinding = result.findings.find((f) => /version tag|missing.*v=/i.test(f.title));
		expect(versionFinding).toBeDefined();
		expect(versionFinding?.metadata?.delegatedTo).toBe('Postmark');
	});

	it('attributes Mailchimp CNAME delegation', async () => {
		const queryDNS = createCnameAwareDNS(
			{
				'k1.dkim.mcsv.net': ['k=rsa; p=' + 'A'.repeat(600)],
			},
			{
				'k1._domainkey.example.com': 'k1.dkim.mcsv.net',
			},
		);
		const result = await checkDKIM('example.com', queryDNS);
		const versionFinding = result.findings.find((f) => /version tag|missing.*v=/i.test(f.title));
		expect(versionFinding).toBeDefined();
		expect(versionFinding?.metadata?.delegatedTo).toBe('Mailchimp');
	});
});
