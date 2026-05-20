// Audit test: OSS fixtures must not carry real contact data, public IPs, or
// real tenant/customer domain lists. Use synthetic/reserved namespaces instead.

import { describe, expect, it } from 'vitest';

const WHOIS_FIXTURE_FILES = import.meta.glob('/packages/dns-checks/src/__tests__/fixtures/whois/**/*.{txt,ts}', {
	query: '?raw',
	eager: true,
});

const TENANT_SQL_FILES = import.meta.glob('/scripts/tenants/sql/register_*.sql', {
	query: '?raw',
	eager: true,
});

const TENANT_DATA_FILES = import.meta.glob('/test/data/*.json', {
	query: '?raw',
	eager: true,
});

const MAINTENANCE_FILES = import.meta.glob('/scripts/maintenance/*.{py,sh,js,mjs,cjs}', {
	query: '?raw',
	eager: true,
});

const PUBLIC_IPV4_PATTERN = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const EMAIL_PATTERN = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi;
const WHOIS_CONTACT_FIELD_PATTERN =
	/^\s*(?:phone|fax-no|e-mail|registrant|admin|tech|billing|registrar abuse contact)\b/im;
const OLD_REAL_FIXTURE_MARKERS = /\b(?:google|markmonitor|verisign)\b/i;
const PRIVATE_MAINTENANCE_MARKERS =
	/\b(?:tenant-pilot-\d+|bv-edge\.workers\.dev|X-Emergency-Dispatch|true-force-scan|tenant-db-tenant-)\b/i;

function rawBody(mod: unknown): string {
	const body = (mod as { default?: unknown }).default;
	return typeof body === 'string' ? body : '';
}

function rel(absKey: string): string {
	return absKey.startsWith('/') ? absKey.slice(1) : absKey;
}

function isAllowedIPv4(value: string): boolean {
	return (
		value.startsWith('127.') ||
		value.startsWith('10.') ||
		value.startsWith('192.168.') ||
		/^172\.(1[6-9]|2\d|3[01])\./.test(value) ||
		value.startsWith('192.0.2.') ||
		value.startsWith('198.51.100.') ||
		value.startsWith('203.0.113.')
	);
}

describe('OSS fixture safety', () => {
	it('WHOIS fixtures do not include contact fields, real emails, public IPv4s, or old real-provider snapshots', () => {
		const offenders: string[] = [];

		for (const [absKey, mod] of Object.entries(WHOIS_FIXTURE_FILES)) {
			const file = rel(absKey);
			const body = rawBody(mod);

			if (WHOIS_CONTACT_FIELD_PATTERN.test(body)) offenders.push(`${file}: contact field`);
			if (OLD_REAL_FIXTURE_MARKERS.test(body)) offenders.push(`${file}: old real fixture marker`);

			for (const match of body.matchAll(EMAIL_PATTERN)) {
				if (!match[0].toLowerCase().endsWith('@example.test')) {
					offenders.push(`${file}: email`);
				}
			}

			for (const match of body.matchAll(PUBLIC_IPV4_PATTERN)) {
				if (!isAllowedIPv4(match[0])) {
					offenders.push(`${file}: public IPv4`);
				}
			}
		}

		expect(offenders).toEqual([]);
	});

	it('tenant registration SQL uses only deterministic reserved domains', () => {
		const domains: string[] = [];
		const offenders: string[] = [];

		for (const [absKey, mod] of Object.entries(TENANT_SQL_FILES)) {
			const file = rel(absKey);
			const body = rawBody(mod);
			for (const match of body.matchAll(/'([^']+)'/g)) {
				const value = match[1];
				if (value === 'synthetic-batch-import') continue;
				domains.push(value);
				if (!/^tenant-seed-\d{3}\.example\.test$/.test(value)) {
					offenders.push(`${file}: non-reserved domain`);
				}
			}
		}

		expect(domains).toHaveLength(500);
		expect(new Set(domains).size).toBe(500);
		expect(offenders).toEqual([]);
	});

	it('tenant JSON payload fixtures use only reserved synthetic domains', () => {
		const offenders: string[] = [];

		function visit(value: unknown, file: string): void {
			if (Array.isArray(value)) {
				value.forEach((item) => visit(item, file));
				return;
			}
			if (value && typeof value === 'object') {
				for (const [key, nested] of Object.entries(value)) {
					if (key === 'domain' && typeof nested === 'string' && !nested.endsWith('.example.test')) {
						offenders.push(`${file}: non-reserved domain`);
					}
					if (key === 'domains' && Array.isArray(nested)) {
						for (const domain of nested) {
							if (typeof domain !== 'string' || !domain.endsWith('.example.test')) {
								offenders.push(`${file}: non-reserved domain`);
							}
						}
					}
					visit(nested, file);
				}
			}
		}

		for (const [absKey, mod] of Object.entries(TENANT_DATA_FILES)) {
			const file = rel(absKey);
			visit(JSON.parse(rawBody(mod)), file);
		}

		expect(offenders).toEqual([]);
	});

	it('maintenance scripts do not embed private tenant routing or emergency dispatch markers', () => {
		const offenders: string[] = [];

		for (const [absKey, mod] of Object.entries(MAINTENANCE_FILES)) {
			const file = rel(absKey);
			if (PRIVATE_MAINTENANCE_MARKERS.test(rawBody(mod))) {
				offenders.push(file);
			}
		}

		expect(offenders).toEqual([]);
	});
});
