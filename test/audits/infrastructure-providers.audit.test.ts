// SPDX-License-Identifier: BUSL-1.1

/**
 * Audit: INFRASTRUCTURE_PROVIDERS coverage for the brand-discovery filter.
 *
 * Pins the multi-tenant providers that must never surface as "shadow IT"
 * candidates. Each entry below is a regression net for a known false-positive
 * vector — adding a new vendor here should be cheaper than triaging an
 * incident where a customer's discovery report names their own ESP.
 *
 * Refs:
 *   - v2.14.0 Zero-False-Positive audit, leakage risk LR-3 (TLD-variant evasion)
 *   - User-named gaps: outlook.com, amazonses.com, mailgun.org
 */

import { describe, it, expect } from 'vitest';
import { isInfrastructureProvider, registeredApex } from '../../src/tools/discover-brand-domains';

/** Hosts the filter MUST classify as infrastructure. */
const MUST_MATCH: ReadonlyArray<readonly [string, string]> = [
	// User-named gaps from the v2.14.0 audit
	['outlook.com', 'cloud mail platform'],
	['amazonses.com', 'AWS SES — transactional mail egress'],
	['mailgun.org', 'Mailgun — RUA endpoint'],
	// Common transactional / bulk-mail egress
	['mailgun.com', 'Mailgun apex'],
	['mailgun.net', 'Mailgun .net variant'],
	['sendgrid.net', 'SendGrid event domain'],
	['sparkpost.com', 'SparkPost'],
	['mailchimp.com', 'Mailchimp'],
	['mcsv.net', 'Mailchimp transactional'],
	// Aggregators not yet listed
	['dmarcian.com', 'dmarcian — DMARC processor'],
	['easydmarc.com', 'easydmarc'],
	['urivault.com', 'URIVault'],
	// TLD variants (LR-3)
	['cloudflare.io', 'Cloudflare .io TLD variant'],
	['cloudflare.dev', 'Cloudflare .dev TLD variant'],
	['salesforce.io', 'Salesforce sibling TLD'],
	['hubapi.com', 'HubSpot sibling SaaS'],
	// Subdomains of listed providers (preserves original endsWith semantics)
	['mail.cloudflare.com', 'subdomain of listed provider'],
	['foo.bar.proofpoint.com', 'deep subdomain'],
];

/** Hosts the filter MUST NOT classify as infrastructure (negative control). */
const MUST_NOT_MATCH: ReadonlyArray<string> = [
	'apple.com',
	'blackveilsecurity.com',
	// Visually-similar but distinct (must not false-match via substring)
	'evil-cloudflare.com',
	'cloudflare-impersonator.io',
];

describe('INFRASTRUCTURE_PROVIDERS coverage', () => {
	for (const [host, reason] of MUST_MATCH) {
		it(`treats ${host} as infrastructure (${reason})`, () => {
			expect(isInfrastructureProvider(host)).toBe(true);
		});
	}

	for (const host of MUST_NOT_MATCH) {
		it(`does NOT match unrelated host ${host}`, () => {
			expect(isInfrastructureProvider(host)).toBe(false);
		});
	}
});

describe('registeredApex', () => {
	it('returns the 2-label apex for ordinary hostnames', () => {
		expect(registeredApex('mail.example.com')).toBe('example.com');
		expect(registeredApex('a.b.c.example.com')).toBe('example.com');
		expect(registeredApex('example.com')).toBe('example.com');
	});

	it('returns the registrable apex for multi-label public suffix hostnames', () => {
		expect(registeredApex('mail.example.co.uk')).toBe('example.co.uk');
	});

	it('treats private suffix tenants as registrable apexes', () => {
		expect(registeredApex('tenant.github.io')).toBe('tenant.github.io');
	});

	it('strips trailing dot and lowercases', () => {
		expect(registeredApex('Example.COM.')).toBe('example.com');
	});

	it('returns the input for single-label hosts (defensive)', () => {
		expect(registeredApex('localhost')).toBe('localhost');
	});
});
