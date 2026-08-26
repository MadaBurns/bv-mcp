// SPDX-License-Identifier: BUSL-1.1

/**
 * Provider coverage guard for the DKIM selector probe list.
 *
 * Every selector asserted here was confirmed by a live Cloudflare DoH probe
 * against a real evidence domain (named per case). The list is a heuristic —
 * a miss hard-floors the dkim category at 50 — so each provider gets a
 * regression test proving the default probe path finds a key published ONLY at
 * that provider's selector.
 *
 * Control arm included: an unlisted selector must still read as "not found",
 * otherwise these tests would pass vacuously against a probe list that matched
 * everything.
 */

import { describe, expect, it, vi } from 'vitest';
import { checkDKIM } from '../../checks/check-dkim';
import { COMMON_DKIM_SELECTORS } from '../../checks/dkim-selectors';
import { attributeCnameChain } from '../../checks/dkim-saas-attribution';
import type { DNSQueryFunction } from '../../types';

const VALID_KEY = 'v=DKIM1; k=rsa; p=' + 'A'.repeat(392);
/** SendGrid-family records omit v=DKIM1 by design (RFC 6376 §3.6.1 tolerates it). */
const NO_VERSION_KEY = 'k=rsa; t=s; p=' + 'A'.repeat(392);
/** Synthetic Resend-shaped direct-TXT 1024-bit RSA key without a v= tag. */
const RESEND_LEGACY_KEY = 'p=MI' + 'GfMA0GCSqGSIb3DQEBAQUAA4GNADCB' + 'A'.repeat(184);

function dnsFor(txt: Record<string, string[]>, cname: Record<string, string> = {}): DNSQueryFunction {
	function resolveTxt(name: string, depth = 0): string[] {
		if (depth > 5) return [];
		if (cname[name] !== undefined) return resolveTxt(cname[name], depth + 1);
		return txt[name] ?? [];
	}
	return vi.fn(async (name: string, type: string) => {
		if (type === 'CNAME') return cname[name] !== undefined ? [cname[name]] : [];
		return resolveTxt(name);
	});
}

/** Original rows verified 2026-08-06; Resend reverified 2026-08-26. */
const MEASURED_COVERAGE = [
	{ provider: 'Fastmail', selector: 'fm1', record: VALID_KEY, evidence: 'fastmail.com' },
	{ provider: 'Fastmail', selector: 'fm2', record: VALID_KEY, evidence: 'fastmail.com' },
	{ provider: 'Fastmail', selector: 'fm3', record: VALID_KEY, evidence: 'fastmail.com' },
	{ provider: 'Klaviyo', selector: 'kl', record: NO_VERSION_KEY, evidence: 'glossier.com' },
	{ provider: 'Klaviyo', selector: 'kl2', record: NO_VERSION_KEY, evidence: 'glossier.com' },
	{ provider: 'Mailchimp', selector: 'k2', record: VALID_KEY, evidence: 'mailchimp.com' },
	{ provider: 'Mailchimp', selector: 'k3', record: VALID_KEY, evidence: 'mailchimp.com' },
	{ provider: 'HubSpot', selector: 'hs1', record: NO_VERSION_KEY, evidence: 'hubspot.com' },
	{ provider: 'HubSpot', selector: 'hs2', record: NO_VERSION_KEY, evidence: 'hubspot.com' },
	{ provider: 'Mailgun', selector: 'mg', record: NO_VERSION_KEY, evidence: 'mailgun.com' },
	{ provider: 'Mailgun', selector: 'pic', record: NO_VERSION_KEY, evidence: 'hubspot.com' },
	{ provider: 'SendGrid legacy', selector: 'smtpapi', record: NO_VERSION_KEY, evidence: 'klaviyo.com' },
	{ provider: 'SendGrid legacy', selector: 'm1', record: NO_VERSION_KEY, evidence: 'hubspot.com' },
	{ provider: 'Zendesk', selector: 'zendesk1', record: VALID_KEY, evidence: 'mailchimp.com' },
	{ provider: 'Zendesk', selector: 'zendesk2', record: VALID_KEY, evidence: 'mailchimp.com' },
	{ provider: 'Mailjet', selector: 'mailjet', record: NO_VERSION_KEY, evidence: 'mailgun.com' },
	{ provider: 'Resend', selector: 'resend', record: RESEND_LEGACY_KEY, evidence: 'resend.com' },
];

describe('DKIM selector coverage (default probe list)', () => {
	it.each(MEASURED_COVERAGE)(
		'$provider: probes "$selector" and finds a key published only there (observed on $evidence)',
		async ({ selector, record }) => {
			expect(COMMON_DKIM_SELECTORS).toContain(selector);
			const result = await checkDKIM(
				'example.com',
				dnsFor({ [`${selector}._domainkey.example.com`]: [record] }),
			);
			expect(result.findings.some((f) => f.title === 'No DKIM records found among tested selectors')).toBe(
				false,
			);
			expect(result.score).toBeGreaterThan(50);
		},
	);

	it('CONTROL: an unlisted selector is still reported as not found', async () => {
		const result = await checkDKIM(
			'example.com',
			dnsFor({ 'not-a-real-selector._domainkey.example.com': [VALID_KEY] }),
		);
		expect(result.findings.some((f) => f.title === 'No DKIM records found among tested selectors')).toBe(true);
		expect(result.score).toBe(50);
	});

	it('CONTROL: a total miss still hard-floors the category at 50', async () => {
		const result = await checkDKIM('example.com', dnsFor({}));
		expect(result.score).toBe(50);
	});

	it('surfaces a weak Resend key alongside a healthy listed sender', async () => {
		const result = await checkDKIM(
			'example.com',
			dnsFor({
				's1._domainkey.example.com': [VALID_KEY],
				'resend._domainkey.example.com': [RESEND_LEGACY_KEY],
			}),
		);

		expect(result.findings).toEqual(
			expect.arrayContaining([
				expect.objectContaining({
					severity: 'high',
					title: 'Legacy RSA key: resend',
				}),
			]),
		);
		expect(result.score).toBe(60);
	});
});

describe('DKIM SaaS attribution reachable from the default probe list', () => {
	it('attributes HubSpot via hs1 → hubspotemail.net', async () => {
		const result = await checkDKIM(
			'example.com',
			dnsFor(
				{ 'example-com.hs01a.dkim.hubspotemail.net': [NO_VERSION_KEY] },
				{ 'hs1._domainkey.example.com': 'example-com.hs01a.dkim.hubspotemail.net' },
			),
		);
		expect(result.findings.some((f) => f.metadata?.delegatedTo === 'HubSpot')).toBe(true);
	});

	it('attributes Mailgun via mg → dkim.mailgun.net (the .net target, not .org)', async () => {
		const result = await checkDKIM(
			'example.com',
			dnsFor(
				{ 'dkim.mailgun.net': [NO_VERSION_KEY] },
				{ 'mg._domainkey.example.com': 'dkim.mailgun.net' },
			),
		);
		expect(result.findings.some((f) => f.metadata?.delegatedTo === 'Mailgun')).toBe(true);
	});

	it('attributes Klaviyo selectors to SendGrid, which actually holds the key', async () => {
		// Measured on glossier.com: kl → kl.domainkey.u161779.wl030.sendgrid.net.
		const result = await checkDKIM(
			'example.com',
			dnsFor(
				{ 'kl.domainkey.u161779.wl030.sendgrid.net': [NO_VERSION_KEY] },
				{ 'kl._domainkey.example.com': 'kl.domainkey.u161779.wl030.sendgrid.net' },
			),
		);
		expect(result.findings.some((f) => f.metadata?.delegatedTo === 'SendGrid')).toBe(true);
	});
});

describe('SaaS attribution cannot be claimed by a lookalike domain', () => {
	it('does not attribute an attacker-registered evil-mailgun.net to Mailgun', () => {
		expect(attributeCnameChain(['dkim.mailgun.net'])).toBe('Mailgun');
		expect(attributeCnameChain(['mailgun.net'])).toBe('Mailgun');
		// Attribution downgrades severity, so a bare suffix match is exploitable.
		expect(attributeCnameChain(['evil-mailgun.net'])).toBeUndefined();
		expect(attributeCnameChain(['notmailgun.org'])).toBeUndefined();
	});
});
