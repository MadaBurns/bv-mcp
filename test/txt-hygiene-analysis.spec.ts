// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect } from 'vitest';
import { VERIFICATION_PATTERNS, SERVICE_SPF_DOMAINS, MAIL_SENDING_VERIFICATION_SERVICES } from '../src/tools/txt-hygiene-analysis';
import type { VerificationCategory, VerificationPattern } from '../src/tools/txt-hygiene-analysis';

describe('VERIFICATION_PATTERNS', () => {
	it('has the expected number of entries', () => {
		expect(VERIFICATION_PATTERNS).toHaveLength(39);
	});

	it('every entry has required fields: prefix, service, category', () => {
		for (const pattern of VERIFICATION_PATTERNS) {
			expect(typeof pattern.prefix).toBe('string');
			expect(pattern.prefix.length).toBeGreaterThan(0);
			expect(typeof pattern.service).toBe('string');
			expect(pattern.service.length).toBeGreaterThan(0);
			expect(typeof pattern.category).toBe('string');
			expect(pattern.category.length).toBeGreaterThan(0);
		}
	});

	it('all category values are valid VerificationCategory values', () => {
		const validCategories: VerificationCategory[] = [
			'search_engine',
			'identity_auth',
			'collaboration',
			'security',
			'marketing',
			'infrastructure',
			'email_auth',
		];
		for (const pattern of VERIFICATION_PATTERNS) {
			expect(validCategories).toContain(pattern.category);
		}
	});

	it('jurisdiction field is only set to RU or CN when present', () => {
		for (const pattern of VERIFICATION_PATTERNS) {
			if (pattern.jurisdiction !== undefined) {
				expect(['RU', 'CN']).toContain(pattern.jurisdiction);
			}
		}
	});

	it('contains known high-value entries', () => {
		const prefixes = VERIFICATION_PATTERNS.map((p) => p.prefix);
		expect(prefixes).toContain('google-site-verification=');
		expect(prefixes).toContain('yandex-verification:');
		expect(prefixes).toContain('baidu-site-verification=');
		expect(prefixes).toContain('MS=');
		expect(prefixes).toContain('v=DMARC1');
		expect(prefixes).toContain('TrustedForDomainSharing=');
	});

	it('Yandex has RU jurisdiction', () => {
		const yandex = VERIFICATION_PATTERNS.find((p) => p.service === 'Yandex');
		expect(yandex).toBeDefined();
		expect(yandex!.jurisdiction).toBe('RU');
	});

	it('Baidu has CN jurisdiction', () => {
		const baidu = VERIFICATION_PATTERNS.find((p) => p.service === 'Baidu');
		expect(baidu).toBeDefined();
		expect(baidu!.jurisdiction).toBe('CN');
	});

	it('has no duplicate prefixes', () => {
		const prefixes = VERIFICATION_PATTERNS.map((p) => p.prefix);
		const unique = new Set(prefixes);
		expect(unique.size).toBe(prefixes.length);
	});
});

describe('SERVICE_SPF_DOMAINS', () => {
	it('contains the expected service keys', () => {
		const keys = Object.keys(SERVICE_SPF_DOMAINS);
		expect(keys).toContain('Google Search Console');
		expect(keys).toContain('Microsoft 365');
		expect(keys).toContain('SendGrid');
		expect(keys).toContain('Mailchimp');
		expect(keys).toContain('HubSpot');
		expect(keys).toContain('Salesforce Pardot');
		expect(keys).toContain('Zoho');
		expect(keys).toContain('Freshdesk');
		expect(keys).toContain('Zendesk');
	});

	it('every value is a non-empty array of strings', () => {
		for (const [_service, domains] of Object.entries(SERVICE_SPF_DOMAINS)) {
			expect(Array.isArray(domains)).toBe(true);
			expect(domains.length).toBeGreaterThan(0);
			for (const domain of domains) {
				expect(typeof domain).toBe('string');
				expect(domain.length).toBeGreaterThan(0);
			}
		}
	});

	it('has 9 service entries', () => {
		expect(Object.keys(SERVICE_SPF_DOMAINS)).toHaveLength(9);
	});
});

// Type-level check: ensure the exported types are usable
describe('exported types', () => {
	it('VerificationPattern type is structurally correct', () => {
		const p: VerificationPattern = { prefix: 'test=', service: 'Test', category: 'security' };
		expect(p.prefix).toBe('test=');
		expect(p.category).toBe('security');
		expect(p.jurisdiction).toBeUndefined();
	});

	it('VerificationPattern type supports optional jurisdiction', () => {
		const p: VerificationPattern = { prefix: 'test=', service: 'Test', category: 'search_engine', jurisdiction: 'RU' };
		expect(p.jurisdiction).toBe('RU');
	});
});

/**
 * Stale-integration false positive (2026-09-07).
 *
 * The heuristic "verification record present but no matching SPF include => stale"
 * was gated on membership of SERVICE_SPF_DOMAINS, which also contains two OWNERSHIP
 * verifications that imply nothing about mail: Google Search Console
 * (google-site-verification=) and Microsoft 365 (MS=, an Entra/tenant ownership proof).
 *
 * Measured over 10 well-known domains before the fix: the M365 rule misfired on 7
 * (cloudflare, stripe, nytimes, shopify, atlassian, dropbox, reddit) and the Search
 * Console rule on 4 (stripe, nytimes, slack, reddit) — stacking to -10 on three.
 */
describe('MAIL_SENDING_VERIFICATION_SERVICES (FP fix 2026-09-07)', () => {
	it('EXCLUDES ownership-only verifications from the stale heuristic', () => {
		// These two are the measured false positives. Using M365 for identity while mail
		// goes elsewhere, or verifying Search Console, is ordinary — not a stale integration.
		expect(MAIL_SENDING_VERIFICATION_SERVICES.has('Microsoft 365')).toBe(false);
		expect(MAIL_SENDING_VERIFICATION_SERVICES.has('Google Search Console')).toBe(false);
	});

	it('still INCLUDES services whose verification does imply sending', () => {
		for (const svc of ['SendGrid', 'Mailchimp', 'HubSpot', 'Salesforce Pardot', 'Zoho', 'Freshdesk', 'Zendesk']) {
			expect(MAIL_SENDING_VERIFICATION_SERVICES.has(svc), `${svc} should still be stale-checkable`).toBe(true);
		}
	});

	it('is a strict subset of SERVICE_SPF_DOMAINS — the gate narrows, never widens', () => {
		// A service outside SERVICE_SPF_DOMAINS has no SPF domains to compare against,
		// so listing one here would be inert and misleading.
		for (const svc of MAIL_SENDING_VERIFICATION_SERVICES) {
			expect(SERVICE_SPF_DOMAINS[svc], `${svc} must have SPF domains defined`).toBeDefined();
		}
		expect(MAIL_SENDING_VERIFICATION_SERVICES.size).toBeLessThan(Object.keys(SERVICE_SPF_DOMAINS).length);
	});

	it('keeps both excluded services in SERVICE_SPF_DOMAINS — only the verdict is gated', () => {
		// That map still suppresses the finding when an include IS present and is read by
		// other call sites; removing the entries would be a different (wrong) fix.
		expect(SERVICE_SPF_DOMAINS['Microsoft 365']).toBeDefined();
		expect(SERVICE_SPF_DOMAINS['Google Search Console']).toBeDefined();
	});
});
