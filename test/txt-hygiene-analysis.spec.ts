// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect } from 'vitest';
import { VERIFICATION_PATTERNS, SERVICE_SPF_DOMAINS } from '../src/tools/txt-hygiene-analysis';
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
		for (const [service, domains] of Object.entries(SERVICE_SPF_DOMAINS)) {
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
